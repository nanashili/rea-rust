use flate2::{Compression, write::ZlibEncoder};
use rea_rust_analysis::auditable::{self, Error, Metadata, SectionName};
use serde_json::{Value, json};
use std::io::Write;

fn compress(bytes: &[u8], level: Compression) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), level);
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn section(text: &str) -> Result<Metadata, Error> {
    auditable::read(
        SectionName::DepV0,
        64,
        &compress(text.as_bytes(), Compression::default()),
    )
}

#[test]
fn reads_an_independently_encoded_zlib_member_and_rejects_incomplete_members() {
    // Node 24.18.0 node:zlib deflateSync of {"packages":[]}, independent encoder.
    let golden = [
        120, 156, 171, 86, 42, 72, 76, 206, 78, 76, 79, 45, 86, 178, 138, 142, 173, 5, 0, 43, 187,
        5, 110,
    ];
    let parsed = auditable::read(SectionName::DepV0, 0, &golden).unwrap();
    assert_eq!(parsed.uncompressed_bytes, 15);
    assert!(parsed.packages.is_empty());
    assert!(parsed.root_package_index.is_none());
    for size in 0..golden.len() {
        assert!(
            auditable::read(SectionName::DepV0, 0, &golden[..size]).is_err(),
            "prefix {size}"
        );
    }
    for trailing in [&[0][..], &golden[..]] {
        let mut bytes = golden.to_vec();
        bytes.extend_from_slice(trailing);
        assert!(matches!(
            auditable::read(SectionName::DepV0, 0, &bytes),
            Err(Error::Malformed(_))
        ));
    }
    let mut corrupted = golden;
    corrupted[22] ^= 1;
    assert!(auditable::read(SectionName::DepV0, 0, &corrupted).is_err());
}

#[test]
fn retains_order_unknown_revision_omissions_and_duplicate_edges() {
    let document = json!({"format":99, "packages":[
        {"name":"dep","version":"1","source":"https://local/source"},
        {"name":"root","version":"2","source":"local","kind":"build","root":true,"dependencies":[0,0]}
    ]});
    let output = serde_json::to_value(section(&document.to_string()).unwrap()).unwrap();
    assert_eq!(output["format_version"], 99);
    assert_eq!(output["file_offset"], 64);
    assert_eq!(output["root_package_index"], 1);
    assert_eq!(
        output["packages"][0],
        json!({"name":"dep","version":"1","source":"https://local/source", "kind":null,"root":false,"dependencies":[]})
    );
    assert_eq!(
        output["dependency_edges"],
        json!([{"from_index":1,"to_index":0},{"from_index":1,"to_index":0}])
    );
    assert_eq!(output["cyclic_dependency_indices"], json!([]));
    for revision in [0, 1, 8, 99, u32::MAX] {
        assert_eq!(
            section(&format!("{{\"format\":{revision},\"packages\":[]}}"))
                .unwrap()
                .format_version,
            Some(revision)
        );
    }
    assert_eq!(
        section("\u{feff}{\"format\":1.0,\"packages\":[]}")
            .unwrap()
            .format_version,
        Some(1)
    );
    let exponent = section(
        r#"{"packages":[{"name":"a","version":"1","source":"local","dependencies":[0e0]}]}"#,
    )
    .unwrap();
    assert_eq!(exponent.cyclic_dependency_indices, vec![0]);
}

#[test]
fn reports_only_cycle_members_and_handles_long_chains_without_recursion() {
    let graph = [[1, 2].as_slice(), &[0], &[1], &[0], &[4]];
    let packages: Vec<Value> = graph.iter().enumerate().map(|(i, deps)| json!({"name":format!("p{i}"),"version":"1","source":"local","dependencies":deps})).collect();
    assert_eq!(
        section(&json!({"packages":packages}).to_string())
            .unwrap()
            .cyclic_dependency_indices,
        vec![0, 1, 2, 4]
    );
    let count = 20_000;
    let packages: Vec<Value> = (0..count).map(|i| json!({"name":format!("p{i}"),"version":"1","source":"local", "dependencies":if i+1<count {vec![i+1]} else {vec![]}})).collect();
    let result = section(&json!({"packages":packages}).to_string()).unwrap();
    assert_eq!(result.packages.len(), count);
    assert_eq!(result.dependency_edges.len(), count - 1);
    assert!(result.cyclic_dependency_indices.is_empty());
}

#[test]
fn rejects_schema_drift_null_fields_bad_indices_and_multiple_roots() {
    for document in [
        "[]",
        "null",
        "{",
        r#"{"packages":[],"future":true}"#,
        r#"{"packages":[],"format":null}"#,
        r#"{"packages":[],"format":-1}"#,
        r#"{"packages":[],"format":1.5}"#,
        r#"{"packages":[],"format":4294967296}"#,
    ] {
        assert!(section(document).is_err(), "{document}");
    }
    for (field, value) in [
        ("name", json!("")),
        ("kind", Value::Null),
        ("root", Value::Null),
        ("dependencies", Value::Null),
        ("dependencies", json!([-1])),
        ("dependencies", json!([0.1])),
        ("dependencies", json!([null])),
        ("future", json!(true)),
    ] {
        let mut package = json!({"name":"a","version":"1","source":"local"});
        package[field] = value;
        assert!(matches!(
            section(&json!({"packages":[package]}).to_string()),
            Err(Error::InvalidPackage { index: 0, .. })
        ));
    }
    assert!(matches!(
        section(r#"{"packages":[{"name":"a","version":"1","source":"local","dependencies":[1]}]}"#),
        Err(Error::InvalidDependency {
            package: 0,
            target: 1
        })
    ));
    assert!(matches!(
        section(
            r#"{"packages":[{"name":"a","version":"1","source":"local","root":true},{"name":"b","version":"1","source":"local","root":true}]}"#
        ),
        Err(Error::Malformed(_))
    ));
}

#[test]
fn refuses_resource_expansion_before_constructing_graph_edges() {
    let too_large = vec![0; auditable::MAX_SECTION_BYTES + 1];
    assert!(matches!(
        auditable::read(SectionName::DepV0, 0, &too_large),
        Err(Error::Resource {
            stage: "compressed section",
            ..
        })
    ));
    let bomb = compress(&vec![0; 8000], Compression::best());
    assert!(matches!(
        auditable::read(SectionName::DepV0, 0, &bomb),
        Err(Error::Resource {
            stage: "inflated JSON",
            ..
        })
    ));
    let graph = json!({"packages":[{"name":"a","version":"1","source":"local","dependencies":vec![0;400_000]}]});
    let bytes = compress(graph.to_string().as_bytes(), Compression::none());
    assert!(bytes.len() < auditable::MAX_SECTION_BYTES);
    assert!(matches!(
        auditable::read(SectionName::DepV0, 0, &bytes),
        Err(Error::Resource {
            stage: "graph expansion",
            ..
        })
    ));
}

#[test]
fn rejects_invalid_utf8_and_deep_json_but_not_delimiters_inside_strings() {
    let invalid = compress(&[0xff], Compression::none());
    assert!(matches!(
        auditable::read(SectionName::DepV0, 0, &invalid),
        Err(Error::Malformed("dependency JSON is not valid UTF-8"))
    ));
    let deep = format!("{}0{}", "[".repeat(33), "]".repeat(33));
    assert!(matches!(
        section(&deep),
        Err(Error::Malformed(
            "dependency JSON nesting exceeds 32 levels"
        ))
    ));
    let name = format!("{}\\\"{}", "[".repeat(40), "]".repeat(40));
    let parsed =
        section(&json!({"packages":[{"name":name,"version":"1","source":"local"}]}).to_string())
            .unwrap();
    assert_eq!(parsed.packages[0].name.as_str(), Some(name.as_str()));
}

#[test]
fn preserves_json_code_units_that_cannot_fit_a_rust_string() {
    for (raw, expected) in [
        (r#""\uD800""#, r#""\ud800""#),
        (r#""\uDBFF""#, r#""\udbff""#),
        (r#""\uDC00""#, r#""\udc00""#),
        (r#""\uDFFF""#, r#""\udfff""#),
        (r#""\u0061\ud800\n\"\\\u0062""#, r#""a\ud800\n\"\\b""#),
        (r#""\ud800\ud801""#, r#""\ud800\ud801""#),
        (r#""\udc00\ud800""#, r#""\udc00\ud800""#),
        (r#""\ud800\ud83d\ude00""#, "\"\\ud800😀\""),
    ] {
        let input = format!(r#"{{"packages":[{{"name":{raw},"version":"1","source":"local"}}]}}"#);
        let parsed = section(&input).unwrap();
        assert!(parsed.packages[0].name.as_str().is_none());
        assert_eq!(
            serde_json::to_string(&parsed.packages[0].name).unwrap(),
            expected
        );
        // Serialize the complete result directly: converting through Value would
        // impose its narrower Unicode-only string representation again.
        assert!(serde_json::to_string(&parsed).unwrap().contains(expected));
    }
    let paired =
        section(r#"{"packages":[{"name":"\ud83d\ude00","version":"1","source":"local"}]}"#)
            .unwrap();
    assert_eq!(paired.packages[0].name.as_str(), Some("😀"));
}
