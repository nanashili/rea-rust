//! Reproducible release-mode workloads; see docs/performance.md.
use rea_core::canonical_json;
use rea_rust_analysis::{electron_fuses, plist};
use serde_json::value::RawValue;
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
        "object" => {
            let mut text = String::from("{");
            for i in (0..100_000).rev() {
                if text.len() > 1 {
                    text.push(',');
                }
                text.push_str(&format!("\"key{i:06}\":{i}"));
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
        _ => panic!("unknown workload"),
    };
    let raw: Option<&RawValue> = match mode.as_str() {
        "array" | "object" | "string" => Some(serde_json::from_slice(&input).unwrap()),
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
            black_box(plist::read(black_box(&input), "benchmark".into()).unwrap());
        }
    }
    println!(
        "{mode}\t{iterations}\t{:.3}\t{result}",
        start.elapsed().as_secs_f64() * 1000.0 / iterations as f64
    );
}
