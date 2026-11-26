//! Contract parity of `ReportEmailRequest` (RF-20): what user-service publishes
//! validates against `../broker/contracts/report-email-request.schema.json`, the
//! valid examples of `../broker/contracts/examples/report-email-request/`
//! deserialize into the type, and the invalid ones are refused by the consumer's
//! parser. A schema change breaks this build instead of diverging silently (no
//! service depends on the `broker` crate).
//!
//! The tests read the sibling `../broker` checkout at run time; if it is absent
//! (this repo cloned alone) they print a notice and pass, as
//! `security_event_contract.rs` does.

use std::path::PathBuf;

use jsonschema::Validator;
use serde_json::Value;
use user_service::report_email::queue::{parse_request_body, ReportEmailRequest};

fn broker_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../broker/contracts")
        .join(relative)
}

/// The compiled schema, or `None` (with a notice) if `../broker` is missing.
fn schema_validator() -> Option<Validator> {
    let path = broker_path("report-email-request.schema.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        eprintln!(
            "SKIP: {} not found (sibling broker checkout absent)",
            path.display()
        );
        return None;
    };
    let schema: Value = serde_json::from_str(&text).expect("the schema is valid JSON");
    Some(jsonschema::validator_for(&schema).expect("the schema compiles"))
}

/// The `.json` files of an examples folder, as `(file name, text)`.
fn examples(folder: &str) -> Vec<(String, String)> {
    let dir = broker_path(&format!("examples/report-email-request/{folder}"));
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut found: Vec<(String, String)> = entries
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read_to_string(&path).expect("example"))
        })
        .collect();
    found.sort();
    found
}

#[test]
fn a_published_request_validates_against_the_broker_schema() {
    let Some(validator) = schema_validator() else {
        return;
    };
    for scan_id in ["scan-42", "9b2f6c1e-3d4a-4e8b-9c7a-1f2e3d4c5b6a", "é ñ"] {
        let value = serde_json::to_value(ReportEmailRequest::new(scan_id)).expect("serialize");
        let errors: Vec<String> = validator
            .iter_errors(&value)
            .map(|e| format!("{e} at {}", e.instance_path()))
            .collect();
        assert!(errors.is_empty(), "{value} does not validate: {errors:?}");
    }
}

#[test]
fn the_valid_broker_examples_validate_and_deserialize() {
    let Some(validator) = schema_validator() else {
        return;
    };
    // The valid examples sit next to the `invalid/` folder, not inside it.
    let valid = examples("");
    assert!(!valid.is_empty(), "no valid examples found");
    for (name, text) in valid {
        let value: Value = serde_json::from_str(&text).expect("json");
        assert!(validator.is_valid(&value), "{name} must validate");
        parse_request_body(&text).unwrap_or_else(|e| panic!("{name} must deserialize: {e}"));
    }
}

#[test]
fn the_invalid_broker_examples_fail_the_schema_and_the_parser() {
    let Some(validator) = schema_validator() else {
        return;
    };
    let invalid = examples("invalid");
    assert!(!invalid.is_empty(), "no invalid examples found");
    for (name, text) in invalid {
        let value: Value = serde_json::from_str(&text).expect("json");
        assert!(!validator.is_valid(&value), "{name} must not validate");
        assert!(
            parse_request_body(&text).is_err(),
            "{name} must be refused by the consumer parser"
        );
    }
}
