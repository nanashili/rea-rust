//! Result-wire compatibility and representation expansion, independent of RPC routing.
use rea_core::json_output;
use rea_runtime::mcp_result::{EncodeError, Representation, ToolResult};
use serde::Deserialize;
use serde_json::{Value, value::RawValue};
use std::io::{self, Write};

#[derive(Deserialize)]
struct Text {
    r#type: String,
    text: String,
}
#[derive(Deserialize)]
struct Decoded {
    content: Vec<Text>,
    #[serde(rename = "structuredContent")]
    structured: Option<Box<RawValue>>,
    #[serde(rename = "isError")]
    error: Option<bool>,
    #[serde(rename = "_meta")]
    meta: Option<Value>,
}

#[test]
fn complete_wire_keeps_lone_surrogates_and_accounts_for_both_representations() {
    let raw = RawValue::from_string(r#"{"text":"\ud800\"\\\n😀","nested":[1,true,null]}"#.into())
        .unwrap();
    for (representation, is_error) in [
        (Representation::Success, false),
        (Representation::Failure, true),
    ] {
        for target_content in [false, true] {
            let value = ToolResult {
                value: &raw,
                representation,
                target_content,
            };
            let length = value.admitted_length(4096).unwrap();
            assert!(matches!(
                value.admitted_length(length - 1),
                Err(json_output::Error::Limit { .. })
            ));
            assert_eq!(value.admitted_length(length).unwrap(), length);
            let mut bytes = Vec::new();
            value.write(&mut bytes).unwrap();
            assert_eq!(bytes.len(), length);
            let decoded: Decoded = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(decoded.content.len(), 1);
            assert_eq!(decoded.content[0].r#type, "text");
            assert_eq!(decoded.content[0].text, raw.get());
            assert_eq!(decoded.error, if is_error { Some(true) } else { None });
            assert_eq!(
                decoded.structured.as_deref().map(RawValue::get),
                if is_error { None } else { Some(raw.get()) }
            );
            assert_eq!(
                decoded.meta,
                if target_content {
                    Some(
                        serde_json::json!({"provenance":{"untrusted_content":true,"source":"analysis_target"}}),
                    )
                } else {
                    None
                }
            );
        }
    }
}

#[test]
fn writing_a_result_preserves_a_closed_transport_error() {
    struct Closed;
    impl Write for Closed {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed peer"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let value = ToolResult {
        value: &true,
        representation: Representation::Success,
        target_content: true,
    };
    assert!(
        matches!(value.write(&mut Closed),Err(EncodeError::Io(error)) if error.kind()==io::ErrorKind::BrokenPipe)
    );
}

#[test]
fn pretty_raw_documents_remain_one_stdio_frame_without_changing_string_contents() {
    let raw = RawValue::from_string(
        "{\n \"text\": \" a b\\n\\\"\\\\\\ud800 \",\r\n \"list\": [ 1, 2 ]\n}".into(),
    )
    .unwrap();
    let result = ToolResult {
        value: &raw,
        representation: Representation::Success,
        target_content: true,
    };
    let mut wire = Vec::new();
    result.write(&mut wire).unwrap();
    assert!(!wire.iter().any(|byte| matches!(byte, b'\r' | b'\n')));
    let decoded: Decoded = serde_json::from_slice(&wire).unwrap();
    let compact = r#"{"text":" a b\n\"\\\ud800 ","list":[1,2]}"#;
    assert_eq!(decoded.content[0].text, compact);
    assert_eq!(decoded.structured.unwrap().get(), compact);
    assert_eq!(result.admitted_length(wire.len()).unwrap(), wire.len());
}
