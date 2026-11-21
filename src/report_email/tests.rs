use chrono::{TimeZone, Utc};
use serde_json::{json, Value};

use super::{render_report_email, ReportEmail, ReportEmailError, ReportEmailInput};
use crate::domain::ScanMode;

fn finding(id: &str, severity: &str, description: &str) -> Value {
    json!({
        "id": id,
        "severity": severity,
        "description": description,
        "nse_script": "vulners",
        "source": "nmap_nse",
        "references": [],
    })
}

fn result_with(vulnerabilities: Vec<Value>) -> Value {
    json!({
        "host": "10.0.0.5",
        "ports": [{
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 8.0",
            "cpes": [],
        }],
        "vulnerabilities": vulnerabilities,
        "scanned_at": "2026-11-20T15:30:00Z",
    })
}

fn render(mode: ScanMode, target: &str, result: &Value) -> ReportEmail {
    let input = ReportEmailInput {
        scan_id: "scan-123",
        target,
        mode,
        finished_at: Utc.with_ymd_and_hms(2026, 11, 20, 15, 30, 0).unwrap(),
        result,
    };
    render_report_email(&input).expect("a valid result renders")
}

fn as_snapshot(email: &ReportEmail) -> String {
    format!(
        "SUBJECT: {}\n\nFILENAME: {}\n\n--- TEXT ---\n{}\n--- HTML ---\n{}",
        email.subject, email.attachment.filename, email.text, email.html
    )
}

#[test]
fn report_email_ssh_completed_with_findings() {
    let result = result_with(vec![
        finding("CVE-2024-0001", "medium", "Medium finding"),
        finding("CVE-2024-0002", "critical", "Critical finding"),
        finding("CVE-2024-0003", "low", "Low finding"),
        finding("CVE-2024-0004", "high", "High finding"),
    ]);
    let email = render(ScanMode::Ssh, "10.0.0.5", &result);
    assert!(!email.html.contains("parches no verificado"));
    insta::assert_snapshot!(as_snapshot(&email));
}

#[test]
fn report_email_network_mode_includes_patch_note() {
    let result = result_with(vec![finding("CVE-2024-0002", "high", "High finding")]);
    let email = render(ScanMode::Network, "10.0.0.5", &result);
    assert!(email.html.contains("Estado de parches no verificado"));
    assert!(email.text.contains("Estado de parches no verificado"));
    insta::assert_snapshot!(as_snapshot(&email));
}

#[test]
fn report_email_zero_findings() {
    let email = render(ScanMode::Ssh, "10.0.0.5", &result_with(vec![]));
    assert!(email.subject.contains("sin hallazgos"));
    insta::assert_snapshot!(as_snapshot(&email));
}

#[test]
fn report_email_shows_only_top_ten_but_counts_all() {
    let mut findings = Vec::new();
    for n in 0..8 {
        findings.push(finding(&format!("CVE-2024-1{n:03}"), "low", "Low finding"));
    }
    for n in 0..2 {
        findings.push(finding(
            &format!("CVE-2024-2{n:03}"),
            "medium",
            "Mid finding",
        ));
    }
    findings.push(finding("CVE-2024-3000", "critical", "Critical finding"));
    findings.push(finding("CVE-2024-3001", "high", "High finding"));
    let email = render(ScanMode::Ssh, "10.0.0.5", &result_with(findings));

    // 12 findings: the two lowest (alphabetically last "low" ids) are cut.
    assert!(email.html.contains("CVE-2024-3000"));
    assert!(email.html.contains("CVE-2024-1005"));
    assert!(!email.html.contains("CVE-2024-1006"));
    assert!(!email.html.contains("CVE-2024-1007"));
    assert!(email.text.contains("12 hallazgos"));
    assert!(email
        .text
        .contains("Se muestran los 10 hallazgos más severos"));
    insta::assert_snapshot!(as_snapshot(&email));
}

#[test]
fn report_email_escapes_html_in_scan_derived_strings() {
    let result = result_with(vec![
        finding(
            "<script>alert(1)</script>",
            "high",
            "<script>alert('xss')</script> & \"quotes\"",
        ),
        finding("CVE-2024-0009", "low", "<img src=x onerror=alert(1)>"),
    ]);
    let email = render(ScanMode::Ssh, "<script>evil()</script>", &result);

    assert!(!email.html.contains("<script>"));
    assert!(!email.html.contains("<img"));
    assert!(email.html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert!(email.html.contains("&amp; &quot;quotes&quot;"));
    insta::assert_snapshot!(as_snapshot(&email));
}

#[test]
fn report_email_subject_never_contains_line_breaks() {
    let email = render(
        ScanMode::Ssh,
        "10.0.0.5\r\nBcc: attacker@example.test",
        &result_with(vec![]),
    );
    assert!(!email.subject.contains('\r'));
    assert!(!email.subject.contains('\n'));
}

#[test]
fn report_email_attachment_matches_browser_export() {
    // Browser: `JSON.stringify(report, null, 2)` under
    // `reporte-escaneo-<scanId>.json` (front buildReportExport.ts).
    let result = result_with(vec![finding("CVE-2024-0002", "high", "High finding")]);
    let email = render(ScanMode::Ssh, "10.0.0.5", &result);

    assert_eq!(email.attachment.filename, "reporte-escaneo-scan-123.json");
    assert_eq!(email.attachment.content_type, "application/json");
    let expected = r#"{
  "host": "10.0.0.5",
  "ports": [
    {
      "cpes": [],
      "port": 22,
      "protocol": "tcp",
      "service": "ssh",
      "state": "open",
      "version": "OpenSSH 8.0"
    }
  ],
  "scanned_at": "2026-11-20T15:30:00Z",
  "vulnerabilities": [
    {
      "description": "High finding",
      "id": "CVE-2024-0002",
      "nse_script": "vulners",
      "references": [],
      "severity": "high",
      "source": "nmap_nse"
    }
  ]
}"#;
    assert_eq!(String::from_utf8(email.attachment.bytes).unwrap(), expected);
}

#[test]
fn report_email_rejects_a_result_that_is_not_a_scan_result() {
    let input = ReportEmailInput {
        scan_id: "scan-123",
        target: "10.0.0.5",
        mode: ScanMode::Ssh,
        finished_at: Utc.with_ymd_and_hms(2026, 11, 20, 15, 30, 0).unwrap(),
        result: &json!({"unexpected": true}),
    };
    assert!(matches!(
        render_report_email(&input),
        Err(ReportEmailError::InvalidResult(_))
    ));
}
