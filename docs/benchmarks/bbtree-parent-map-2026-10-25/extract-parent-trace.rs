use std::fs::File;
use std::io::{BufWriter, Write};
use std::ops::ControlFlow;

use oxc_allocator::Allocator;
use rea_application::javascript::ast::{AstContext, AstVisitor, Node, Role, traverse};
use rea_application::javascript::parser::parse_javascript_analysis_program;

struct Trace<W> {
    output: W,
    count: usize,
}

impl<'a, W: Write> AstVisitor<'a> for Trace<W> {
    fn enter(&mut self, node: &Node<'a>, parent: Option<&Node<'a>>, _: &[Node<'a>]) {
        let Some(parent) = parent else { return };
        for value in [node, parent] {
            let key = value.key();
            let encoded =
                ((key.node.index() as u64) << 1) | u64::from(key.role == Role::Synthesized);
            self.output
                .write_all(&encoded.to_le_bytes())
                .expect("write trace");
        }
        self.count += 1;
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    let source = std::fs::read_to_string(&args[1])?;
    let allocator = Allocator::default();
    let parsed = parse_javascript_analysis_program(&allocator, &source, Some(&args[1]))
        .map_err(|errors| format!("parse: {errors:?}"))?;
    let context = AstContext::new(parsed.program);
    let output = BufWriter::new(File::create(&args[2])?);
    let mut trace = Trace { output, count: 0 };
    let _: ControlFlow<()> = traverse(context.root(), &source, &mut trace, || {
        ControlFlow::Continue(())
    });
    trace.output.flush()?;
    println!(
        "{{\"edges\":{},\"node_bytes\":{}}}",
        trace.count,
        size_of::<Node<'_>>()
    );
    Ok(())
}
