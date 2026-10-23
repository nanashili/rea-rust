use rea_rust_analysis::go::module::{self as go_module, GoModule, Replacement, Setting};
use serde_json::json;

#[test]
fn parses_module_records_settings_and_empty_fields_in_source_order() {
    let result = go_module::parse(
        b"path\texample.invalid/app\nmod\texample.invalid/app\t(devel)\t\ndep\texample.invalid/lib\tv1.2.3\th1:bytes\n=>\t../local lib\t\t\nbuild\tGOOS=linux\nbuild\tGOOS=custom\nbuild\t__proto__=kept\nbuild\tDefaultGODEBUG=panicnil=1,asynctimerchan=1\n",
    );

    assert_eq!(result.path.as_deref(), Some("example.invalid/app"));
    assert_eq!(
        result.main,
        Some(GoModule {
            path: "example.invalid/app".to_owned(),
            version: "(devel)".to_owned(),
            sum: Some(String::new()),
            replacement: None,
        })
    );
    assert_eq!(
        result.dependencies,
        vec![GoModule {
            path: "example.invalid/lib".to_owned(),
            version: "v1.2.3".to_owned(),
            sum: Some("h1:bytes".to_owned()),
            replacement: Some(Replacement {
                path: "../local lib".to_owned(),
                version: String::new(),
                sum: Some(String::new()),
            }),
        }]
    );
    assert_eq!(
        result.settings,
        vec![
            Setting {
                key: "GOOS".to_owned(),
                value: "linux".to_owned(),
            },
            Setting {
                key: "GOOS".to_owned(),
                value: "custom".to_owned(),
            },
            Setting {
                key: "__proto__".to_owned(),
                value: "kept".to_owned(),
            },
            Setting {
                key: "DefaultGODEBUG".to_owned(),
                value: "panicnil=1,asynctimerchan=1".to_owned(),
            },
        ]
    );
    assert!(result.complete);
}

#[test]
fn decodes_go_quoted_strings_and_rejects_invalid_escaped_utf8() {
    let input = b"build\t\"key=quoted\"=\"\\a\\v\\xC3\\xA9\\303\\251\\u263a\\U0001F680\"\nbuild\traw=`a\rb`\nbuild\tbad=\"\\xff\"\n";
    let result = go_module::parse(input);

    assert_eq!(
        result.settings,
        vec![
            Setting {
                key: "key=quoted".to_owned(),
                value: "\x07\x0béé☺🚀".to_owned(),
            },
            Setting {
                key: "raw".to_owned(),
                value: "ab".to_owned(),
            },
        ]
    );
    assert_eq!(result.unparsed_lines, ["build\tbad=\"\\xff\""]);
    assert!(!result.complete);
}

#[test]
fn preserves_malformed_records_duplicates_and_unterminated_lines() {
    let result = go_module::parse(
        b"path\tfirst\npath\tsecond\nmod\tfirst\tv1\nmod\tsecond\tv2\nbuild\tGOARCH=amd64",
    );

    assert_eq!(result.path.as_deref(), Some("first"));
    assert_eq!(
        result.main.as_ref().map(|module| module.path.as_str()),
        Some("first")
    );
    assert_eq!(
        result.unparsed_lines,
        ["path\tsecond", "mod\tsecond\tv2", "build\tGOARCH=amd64"]
    );
    assert!(!result.complete);

    let malformed = go_module::parse(b"dep\tfirst\tv1\ndep\tmalformed\n=>\tlocal\t\t\n");
    assert_eq!(malformed.dependencies.len(), 1);
    assert_eq!(malformed.dependencies[0].replacement, None);
    assert_eq!(
        malformed.unparsed_lines,
        ["dep\tmalformed", "=>\tlocal\t\t"]
    );
}

#[test]
fn preserves_invalid_utf8_lines_and_resets_only_module_record_context() {
    let bad_setting = b"build\t-tags=\xff";
    let bad_dependency = b"dep\t\xff\tv2\t";
    let result = go_module::parse(
        &[
            b"dep\tfirst\tv1\n".as_slice(),
            bad_setting,
            b"\n=>\tlocal\t\t\n".as_slice(),
            bad_dependency,
            b"\n=>\tother\t\t\n".as_slice(),
            b"\xfe".as_slice(),
        ]
        .concat(),
    );

    assert_eq!(result.dependencies.len(), 1);
    assert_eq!(
        result.dependencies[0].replacement,
        Some(Replacement {
            path: "local".to_owned(),
            version: String::new(),
            sum: Some(String::new()),
        })
    );
    assert_eq!(result.unparsed_lines, ["=>\tother\t\t"]);
    assert_eq!(
        result.unparsed_line_bytes_base64,
        ["YnVpbGQJLXRhZ3M9/w==", "ZGVwCf8JdjIJ", "/g=="]
    );
    assert!(!result.complete);
}

#[test]
fn serializes_the_existing_go_metadata_shape() {
    let value = serde_json::to_value(go_module::parse(b"mod\tapp\tv1\n")).unwrap();
    assert_eq!(
        value,
        json!({
            "path": null,
            "main": {
                "path": "app",
                "version": "v1",
                "sum": null,
                "replacement": null
            },
            "dependencies": [],
            "settings": [],
            "unparsed_lines": [],
            "unparsed_line_bytes_base64": [],
            "complete": true
        })
    );
}
