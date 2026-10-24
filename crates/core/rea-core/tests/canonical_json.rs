//! Golden bytes/digests from REA's current TypeScript canonicalization owner.
use rea_core::canonical_json::{self, Error};
use serde_json::value::RawValue;
use std::io;

#[test]
fn agrees_with_original_rea_on_numbers_utf16_order_and_duplicate_keys() {
    // Generated with Node 24.18.0, digestCanonicalValue and canonicalize;
    // neither Rust serializer nor the function under test generated expectations.
    for (input, expected, digest) in [
        (
            r#"{"z":-0,"a":[1e-7,0.000001,1e20,1e21,333333333.33333329]}"#,
            r#"{"a":[1e-7,0.000001,100000000000000000000,1e+21,333333333.3333333],"z":0}"#,
            "e228cf6c0533793a529225a3f6900e055696a95d4acbc15ddde9b25cdd122aba",
        ),
        (
            r#"{"\ue000":1,"\ud83d\ude00":2,"\ud800":3,"a":"\udfff"}"#,
            "{\"a\":\"\\udfff\",\"\\ud800\":3,\"😀\":2,\"\u{e000}\":1}",
            "ae61a85f800a7b1a7cba437e068a6bd27ee0980727e0455cb577b49544e8500a",
        ),
        (
            r#"{"b":1,"a":0,"b":2}"#,
            r#"{"a":0,"b":2}"#,
            "4532eb41f1873840d695d625dc8265deca5ce619b2ffeae20fec10c182ee9a20",
        ),
        (
            r#"[null,true,false,"quote\"slash/\n",9007199254740993]"#,
            r#"[null,true,false,"quote\"slash/\n",9007199254740992]"#,
            "c59b6fb1213c7388443d101a4d5fb6e6274c5a3c84f378dd9c2eb42a49d99282",
        ),
    ] {
        let raw: &RawValue = serde_json::from_str(input).unwrap();
        let mut bytes = Vec::new();
        canonical_json::write(raw, &mut bytes).unwrap();
        assert_eq!(bytes, expected.as_bytes());
        assert_eq!(canonical_json::digest_raw(raw).unwrap(), digest);
    }
    let raw: &RawValue = serde_json::from_str(r#"{"\u0061":1,"a":2}"#).unwrap();
    let mut bytes = Vec::new();
    canonical_json::write(raw, &mut bytes).unwrap();
    assert_eq!(bytes, br#"{"a":2}"#);
}

#[test]
fn limits_depth_without_recursive_traversal_and_rejects_non_finite_numbers() {
    for depth in [1000, 1001] {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let raw: &RawValue = serde_json::from_str(&text).unwrap();
        let result = canonical_json::write(raw, io::sink());
        if depth == 1000 {
            assert!(result.is_ok());
        } else {
            assert!(matches!(result, Err(Error::Depth)));
        }
    }
    let raw: &RawValue = serde_json::from_str("1e400").unwrap();
    assert!(matches!(
        canonical_json::write(raw, io::sink()),
        Err(Error::Json(_))
    ));
}

#[test]
fn does_not_swallow_a_failed_output_write() {
    struct Denied;
    impl io::Write for Denied {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::PermissionDenied.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let raw: &RawValue = serde_json::from_str("{}").unwrap();
    assert!(
        matches!(canonical_json::write(raw, Denied), Err(Error::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[test]
fn container_continuations_preserve_separators_and_nested_order() {
    for (input, expected) in [
        ("[ \n\t ]", "[]"),
        (
            "[ 1 ,\n [ ] , {\"z\":[],\"a\":{}} , 2 ]",
            "[1,[],{\"a\":{},\"z\":[]},2]",
        ),
        (
            r#"["a,b]}","\\",[true,false],null]"#,
            r#"["a,b]}","\\",[true,false],null]"#,
        ),
        (
            r#"{"z":0,"a":{"b":1,"b":2},"c":[{},[]]}"#,
            r#"{"a":{"b":2},"c":[{},[]],"z":0}"#,
        ),
    ] {
        let raw: &RawValue = serde_json::from_str(input).unwrap();
        let mut bytes = Vec::new();
        canonical_json::write(raw, &mut bytes).unwrap();
        assert_eq!(bytes, expected.as_bytes());
    }
}

#[test]
fn unescaped_string_fast_path_matches_lossless_normalization() {
    for (input, expected) in [
        (r#""""#, r#""""#),
        (
            "\"ordinary / 😀 \u{2028}\u{2029}\"",
            "\"ordinary / 😀 \u{2028}\u{2029}\"",
        ),
        (r#""\/\u0061\uD83D\uDE00""#, "\"/a😀\""),
        (r#""\u0000\u000a\uD800""#, r#""\u0000\n\ud800""#),
    ] {
        let raw: &RawValue = serde_json::from_str(input).unwrap();
        let mut bytes = Vec::new();
        canonical_json::write(raw, &mut bytes).unwrap();
        assert_eq!(bytes, expected.as_bytes());
    }
}

#[test]
fn wide_containers_keep_all_children_and_hash_the_emitted_bytes() {
    use sha2::{Digest, Sha256};
    let input = format!(
        "[{}{{\"z\":0,\"a\":1}}]",
        "[null,{},[],123],".repeat(10_000)
    );
    let raw: &RawValue = serde_json::from_str(&input).unwrap();
    let mut bytes = Vec::new();
    canonical_json::write(raw, &mut bytes).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::from_str::<serde_json::Value>(&input).unwrap()
    );
    assert_eq!(
        canonical_json::digest_raw(raw).unwrap(),
        format!("{:x}", Sha256::digest(&bytes))
    );
}
