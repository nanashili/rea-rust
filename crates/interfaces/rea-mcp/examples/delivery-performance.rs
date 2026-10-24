//! MCP encoding benchmark, including rejected results and Unicode escaping.
use rea_mcp::delivery::{self, Encoding};
use serde_json::{Map, Value};
use std::{hint::black_box, time::Instant};

fn main() {
    let mode = std::env::args().nth(1).expect("workload");
    let iterations: usize = std::env::args()
        .nth(2)
        .unwrap_or("5".into())
        .parse()
        .unwrap();
    let (text, budget) = match mode.as_str() {
        "delivery-fit" => ("a\"\\\n😀".repeat(350_000), 10 * 1024 * 1024),
        "delivery-reject" => ("a\"\\\n😀".repeat(4_000_000), 10 * 1024 * 1024),
        _ => panic!("unknown workload"),
    };
    let value = Value::Object(Map::from_iter([("data".into(), Value::String(text))]));
    let start = Instant::now();
    let mut result = String::new();
    for _ in 0..iterations {
        result = match delivery::encode(black_box(&value), budget, true, true) {
            Encoding::Fits { text } => {
                let result = format!("fits:{}", text.len());
                black_box(text);
                result
            }
            Encoding::Exceeds {
                bytes_at_least,
                code_units_at_least,
                constraint,
            } => {
                format!("exceeds:{bytes_at_least}:{code_units_at_least}:{constraint}")
            }
        };
    }
    println!(
        "{mode}\t{iterations}\t{:.3}\t{result}",
        start.elapsed().as_secs_f64() * 1000.0 / iterations as f64
    );
}
