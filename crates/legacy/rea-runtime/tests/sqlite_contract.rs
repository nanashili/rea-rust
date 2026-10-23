#![cfg(unix)]

use serde_json::Value;

#[test]
fn sqlite_contract_advertises_extended_observation_fields() {
    let contract: Value =
        serde_json::from_str(include_str!("../contracts/inspect_sqlite_database.json"))
            .expect("valid SQLite contract JSON");
    let schema = &contract["x-rea-observationResultSchema"];
    assert_eq!(schema["type"], "object");
    for field in [
        "artifact",
        "engine",
        "database_encoding",
        "schema",
        "limitations",
    ] {
        assert!(
            schema["required"]
                .as_array()
                .expect("required fields")
                .iter()
                .any(|value| value == field),
            "missing observation field {field}"
        );
    }
    for field in ["tables", "indexes", "foreign_keys", "unique_constraints"] {
        let required = schema["properties"]["schema"]["required"]
            .as_array()
            .expect("schema required fields");
        assert!(
            required.iter().any(|value| value == field),
            "missing schema field {field}"
        );
    }
}
