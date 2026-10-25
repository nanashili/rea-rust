//! Output admission counts the actual escaping and preserves encoder failures.
use rea_core::{
    JsonText,
    json_output::{self, Error},
};
use serde::{Serialize, Serializer, ser::Error as _};

#[test]
fn admits_exact_wire_bytes_and_does_not_reclassify_encoding_as_capacity() {
    let text: JsonText = serde_json::from_str(r#""\ud800""#).unwrap();
    assert_eq!(json_output::admitted_length(&text, 8).unwrap(), 8);
    assert!(matches!(
        json_output::admitted_length(&text, 7),
        Err(Error::Limit { maximum: 7 })
    ));
    struct Broken;
    impl Serialize for Broken {
        fn serialize<S: Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(S::Error::custom("encoder failure"))
        }
    }
    assert!(
        matches!(json_output::admitted_length(&Broken,1024),Err(Error::Encoding(error)) if error.to_string()=="encoder failure")
    );
}

#[test]
fn a_refused_write_cannot_be_hidden_by_an_encoder_returning_success() {
    let result = json_output::admitted_encoding_length(1, |writer| {
        let _ = writer.write_all(b"oversized");
        Ok::<_, std::io::Error>(())
    });
    assert!(matches!(result, Err(Error::Limit { maximum: 1 })));
}

#[test]
fn utf16_constructor_preserves_pairs_and_unpaired_units() {
    let paired = JsonText::from_utf16_units(&[0xd83d, 0xde00]).unwrap();
    assert_eq!(paired.as_str(), Some("😀"));
    assert_eq!(paired.utf16_units().unwrap(), vec![0xd83d, 0xde00]);

    let unpaired = JsonText::from_utf16_units(&[0xd800, b'x' as u16]).unwrap();
    assert_eq!(unpaired.as_str(), None);
    assert_eq!(unpaired.utf16_units().unwrap(), vec![0xd800, b'x' as u16]);
    assert_eq!(serde_json::to_string(&unpaired).unwrap(), r#""\ud800x""#);

    #[derive(serde::Serialize)]
    struct Nested<'a> {
        text: &'a JsonText,
    }
    assert_eq!(
        serde_json::to_string(&Nested { text: &unpaired }).unwrap(),
        r#"{"text":"\ud800x"}"#
    );
}

#[test]
fn utf16_constructor_preserves_adjacent_unpaired_units() {
    let text = JsonText::from_utf16_units(&[0xdc00, 0xd800]).unwrap();

    assert_eq!(text.utf16_units().unwrap(), vec![0xdc00, 0xd800]);
    assert_eq!(serde_json::to_string(&text).unwrap(), r#""\udc00\ud800""#);

    let roundtrip: JsonText = serde_json::from_str(r#""\udc00\ud800""#).unwrap();
    assert_eq!(roundtrip.utf16_units().unwrap(), vec![0xdc00, 0xd800]);
}
