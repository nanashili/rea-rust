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
