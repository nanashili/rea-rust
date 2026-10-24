//! Reproducible release-mode workloads; see docs/performance.md.
use rea_core::canonical_json;
use rea_rust_analysis::{electron_fuses, plist};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{hint::black_box, time::Instant};

fn main() {
    let mode = std::env::args().nth(1).expect("workload");
    let iterations: usize = std::env::args()
        .nth(2)
        .unwrap_or("5".into())
        .parse()
        .unwrap();
    let input = match mode.as_str() {
        "array" => format!("[{}0]", "123,".repeat(1_000_000)).into_bytes(),
        "object" | "object-long-keys" => {
            let prefix = if mode == "object-long-keys" {
                "long_ascii_key_".repeat(8)
            } else {
                String::new()
            };
            let mut text = String::from("{");
            for i in (0..100_000).rev() {
                if text.len() > 1 {
                    text.push(',');
                }
                text.push_str(&format!("\"{prefix}key{i:06}\":{i}"));
            }
            text.push('}');
            text.into_bytes()
        }
        "string" => {
            let chunk = "ordinary text / 😀 ";
            let mut text = String::with_capacity(chunk.len() * 1_000_000 + 2);
            text.push('"');
            for _ in 0..1_000_000 {
                text.push_str(chunk);
            }
            text.push('"');
            text.into_bytes()
        }
        "fuses" => {
            let mut bytes = vec![b'x'; 64 * 1024 * 1024];
            bytes[..4].copy_from_slice(b"\x7fELF");
            bytes
        }
        "plist" => {
            let mut bytes = Vec::with_capacity(32 * 1024 * 1024 + 128);
            bytes.extend_from_slice(b"<?xml version=\"1.0\"?><plist><!--");
            bytes.resize(bytes.len() + 32 * 1024 * 1024, b'x');
            bytes.extend_from_slice(b"--><string>ok</string></plist>");
            bytes
        }
        "plist-entities" => format!(
            "<plist><string>{}</string></plist>",
            "&#65;&#x1f600;&amp;lt;".repeat(3_000)
        )
        .into_bytes(),
        "plist-dates" => {
            let mut text = String::from("<plist><dict>");
            for i in 0..3_000 {
                text.push_str(&format!(
                    "<key>key{i:06}</key><date>2025-01-01T00:00:00Z</date>"
                ));
            }
            text.push_str("</dict></plist>");
            text.into_bytes()
        }
        "plist-text" => {
            let mut bytes = Vec::with_capacity(16 * 1024 * 1024 + 128);
            bytes.extend_from_slice(b"<plist><string>");
            bytes.resize(bytes.len() + 16 * 1024 * 1024, b'x');
            bytes.extend_from_slice(b"</string></plist>");
            bytes
        }
        _ => panic!("unknown workload"),
    };
    let raw: Option<&RawValue> = match mode.as_str() {
        "array" | "object" | "object-long-keys" | "string" => {
            Some(serde_json::from_slice(&input).unwrap())
        }
        _ => None,
    };
    let start = Instant::now();
    let mut result = String::new();
    for _ in 0..iterations {
        if let Some(raw) = raw {
            result = canonical_json::digest_raw(black_box(raw)).unwrap();
        } else if mode == "fuses" {
            let report = electron_fuses::inspect(black_box(&input), String::new()).unwrap();
            assert_eq!(report.slices[0].sentinel_count, 0);
            black_box(report);
        } else {
            let report = plist::read(black_box(&input), "benchmark".into()).unwrap();
            result = if let Some(text) = report.value.as_str() {
                format!("{:x}", Sha256::digest(text.as_bytes()))
            } else {
                format!(
                    "{:x}",
                    Sha256::digest(serde_json::to_vec(&report.value).unwrap())
                )
            };
            black_box(report);
        }
    }
    println!(
        "{mode}\t{iterations}\t{:.3}\t{result}",
        start.elapsed().as_secs_f64() * 1000.0 / iterations as f64
    );
}
