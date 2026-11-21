//! Report email rendering (task EM-01).
//!
//! Pure functions, no I/O: given a stored completed scan result they produce
//! the subject, an HTML summary, a plain-text alternative and the JSON
//! attachment. Sending is a separate concern (the `Mailer` port, EM-02).
//!
//! The attachment mirrors the browser export
//! (`front/src/features/report/buildReportExport.ts`): the stored `ScanResult`
//! serialized with `JSON.stringify(report, null, 2)` under
//! `reporte-escaneo-<scanId>.json`.
//!
//! The user-visible copy is Spanish, like the app UI. Every string derived
//! from the scan (target, finding ids and descriptions) is HTML-escaped.

use std::fmt::Write as _;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::domain::ScanMode;

/// Maximum number of findings listed in the summary.
const TOP_FINDINGS: usize = 10;

/// Severities from most to least severe; also the order of the counts.
const SEVERITIES: [(&str, &str); 6] = [
    ("critical", "Crítica"),
    ("high", "Alta"),
    ("medium", "Media"),
    ("low", "Baja"),
    ("info", "Informativa"),
    ("unknown", "Desconocida"),
];

/// Same wording as the report view in the front (`PATCH_STATE_NOT_VERIFIED`).
const PATCH_NOTE: &str = "Estado de parches no verificado: este escaneo se hizo solo con la IP, sin credenciales SSH. Los hallazgos se basan en la versión de los servicios y pueden incluir vulnerabilidades ya corregidas.";

/// Everything the renderer needs about one completed scan.
#[derive(Debug, Clone, Copy)]
pub struct ReportEmailInput<'a> {
    /// Scan identifier, used in the attachment filename.
    pub scan_id: &'a str,
    /// Scan target as requested by the user.
    pub target: &'a str,
    /// Scan mode (`ssh` or `network`).
    pub mode: ScanMode,
    /// When the scan finished, shown in the summary.
    pub finished_at: DateTime<Utc>,
    /// Stored scan result, as returned by `Repository::find_scan_result`.
    pub result: &'a Value,
}

/// The JSON file attached to the email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportAttachment {
    /// File name, same convention as the browser export.
    pub filename: String,
    /// MIME type of the content.
    pub content_type: &'static str,
    /// File content (UTF-8 JSON, two-space indentation).
    pub bytes: Vec<u8>,
}

/// A fully rendered report email.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportEmail {
    /// Single-line subject.
    pub subject: String,
    /// HTML body.
    pub html: String,
    /// Plain-text alternative with the same content as the HTML body.
    pub text: String,
    /// JSON attachment.
    pub attachment: ReportAttachment,
}

/// Why a report email could not be rendered.
#[derive(Debug, thiserror::Error)]
pub enum ReportEmailError {
    /// The stored result does not have the scan result shape.
    #[error("the stored scan result is not a valid report: {0}")]
    InvalidResult(&'static str),
    /// The result could not be serialized for the attachment.
    #[error("could not serialize the report attachment: {0}")]
    Serialize(#[from] serde_json::Error),
}

struct Finding {
    id: String,
    severity: usize,
    description: String,
}

/// Renders the report email for a completed scan.
///
/// Findings verified as fixed by a backport (`patch_state == "fixed"`) are
/// left out of the counts and the list, as the report view does; the
/// attachment still carries the full result.
///
/// # Errors
///
/// [`ReportEmailError::InvalidResult`] when `result` has no `vulnerabilities`
/// array.
pub fn render_report_email(input: &ReportEmailInput<'_>) -> Result<ReportEmail, ReportEmailError> {
    let findings = parse_findings(input.result)?;
    let counts: Vec<usize> = (0..SEVERITIES.len())
        .map(|s| findings.iter().filter(|f| f.severity == s).count())
        .collect();
    let mut top: Vec<&Finding> = findings.iter().collect();
    top.sort_by(|a, b| (a.severity, &a.id).cmp(&(b.severity, &b.id)));
    top.truncate(TOP_FINDINGS);

    let target = single_line(input.target);
    let date = input.finished_at.format("%Y-%m-%d %H:%M UTC").to_string();
    let mode = match input.mode {
        ScanMode::Ssh => "SSH (con credenciales)",
        ScanMode::Network => "Red (solo IP)",
    };
    let summary = Summary {
        target: &target,
        date: &date,
        mode,
        patch_note: (input.mode == ScanMode::Network).then_some(PATCH_NOTE),
        total: findings.len(),
        counts: &counts,
        top: &top,
    };

    let subject = if findings.is_empty() {
        format!("Informe de escaneo: {target} (sin hallazgos)")
    } else {
        format!(
            "Informe de escaneo: {target} ({})",
            findings_label(findings.len())
        )
    };

    Ok(ReportEmail {
        subject,
        html: summary.html(),
        text: summary.text(),
        attachment: ReportAttachment {
            filename: format!("reporte-escaneo-{}.json", input.scan_id),
            content_type: "application/json",
            bytes: serde_json::to_string_pretty(input.result)?.into_bytes(),
        },
    })
}

fn parse_findings(result: &Value) -> Result<Vec<Finding>, ReportEmailError> {
    let items = result
        .get("vulnerabilities")
        .and_then(Value::as_array)
        .ok_or(ReportEmailError::InvalidResult("missing vulnerabilities"))?;
    Ok(items
        .iter()
        .filter(|v| v.get("patch_state").and_then(Value::as_str) != Some("fixed"))
        .map(|v| {
            let text = |key: &str| v.get(key).and_then(Value::as_str).unwrap_or_default();
            let severity = SEVERITIES
                .iter()
                .position(|(key, _)| *key == text("severity"))
                .unwrap_or(SEVERITIES.len() - 1);
            let id = match text("id") {
                "" => "Sin identificador",
                id => id,
            };
            Finding {
                id: id.to_owned(),
                severity,
                description: text("description").to_owned(),
            }
        })
        .collect())
}

fn findings_label(count: usize) -> String {
    if count == 1 {
        "1 hallazgo".to_owned()
    } else {
        format!("{count} hallazgos")
    }
}

/// Collapses control characters (notably CR/LF) so the value is safe in a
/// header-like single line.
fn single_line(value: &str) -> String {
    value
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

struct Summary<'a> {
    target: &'a str,
    date: &'a str,
    mode: &'a str,
    patch_note: Option<&'a str>,
    total: usize,
    counts: &'a [usize],
    top: &'a [&'a Finding],
}

impl Summary<'_> {
    fn shown_note(&self) -> Option<String> {
        (self.total > self.top.len())
            .then(|| format!("Se muestran los {TOP_FINDINGS} hallazgos más severos."))
    }

    fn text(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "Informe de escaneo");
        let _ = writeln!(out, "Objetivo: {}", self.target);
        let _ = writeln!(out, "Fecha: {}", self.date);
        let _ = writeln!(out, "Modo: {}", self.mode);
        if let Some(note) = self.patch_note {
            let _ = writeln!(out, "\n{note}");
        }
        let _ = writeln!(out, "\nResumen: {}", findings_label(self.total));
        for ((_, label), count) in SEVERITIES.iter().zip(self.counts) {
            let _ = writeln!(out, "- {label}: {count}");
        }
        if !self.top.is_empty() {
            let _ = writeln!(out, "\nHallazgos principales:");
            for (n, f) in self.top.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{}. [{}] {} - {}",
                    n + 1,
                    SEVERITIES[f.severity].1,
                    f.id,
                    f.description
                );
            }
            if let Some(note) = self.shown_note() {
                let _ = writeln!(out, "{note}");
            }
        }
        let _ = writeln!(out, "\nEl informe completo va adjunto en formato JSON.");
        out
    }

    fn html(&self) -> String {
        let mut out = String::from(
            "<!DOCTYPE html>\n<html lang=\"es\">\n<body style=\"font-family: sans-serif;\">\n",
        );
        let _ = writeln!(out, "<h1>Informe de escaneo</h1>");
        let _ = writeln!(
            out,
            "<p><strong>Objetivo:</strong> {}<br>",
            escape_html(self.target)
        );
        let _ = writeln!(
            out,
            "<strong>Fecha:</strong> {}<br>",
            escape_html(self.date)
        );
        let _ = writeln!(out, "<strong>Modo:</strong> {}</p>", escape_html(self.mode));
        if let Some(note) = self.patch_note {
            let _ = writeln!(out, "<p><em>{}</em></p>", escape_html(note));
        }
        let _ = writeln!(
            out,
            "<h2>Resumen: {}</h2>\n<ul>",
            findings_label(self.total)
        );
        for ((_, label), count) in SEVERITIES.iter().zip(self.counts) {
            let _ = writeln!(out, "<li>{label}: {count}</li>");
        }
        out.push_str("</ul>\n");
        if !self.top.is_empty() {
            out.push_str("<h2>Hallazgos principales</h2>\n<ol>\n");
            for f in self.top {
                let _ = writeln!(
                    out,
                    "<li>[{}] <strong>{}</strong> - {}</li>",
                    SEVERITIES[f.severity].1,
                    escape_html(&f.id),
                    escape_html(&f.description)
                );
            }
            out.push_str("</ol>\n");
            if let Some(note) = self.shown_note() {
                let _ = writeln!(out, "<p>{note}</p>");
            }
        }
        out.push_str("<p>El informe completo va adjunto en formato JSON.</p>\n</body>\n</html>\n");
        out
    }
}

#[cfg(test)]
mod tests;
