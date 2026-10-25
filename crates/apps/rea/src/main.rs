//! `rea`: the native production executable.
//!
//! Routing mirrors the original `scripts/rea.mjs`: bare `mcp`/`--mcp` serves
//! stdio MCP; everything else (including `mcp --http`, `mcp add` and
//! `mcp doctor`) is owned by the CLI.
mod compose;
mod worker_memory;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    if arguments.first().map(String::as_str)
        == Some(rea_application::javascript::worker::WORKER_ARGUMENT)
    {
        let max_heap_mb = arguments.get(1).and_then(|argument| {
            rea_application::javascript::worker::max_heap_mb_from_argument(argument)
        });
        std::process::exit(
            rea_application::javascript::worker::run_worker_from_stdin_with_limit(
                max_heap_mb,
                worker_memory::set_worker_limit,
            ),
        );
    }

    let mcp_entry = matches!(arguments.first().map(String::as_str), Some("mcp" | "--mcp"));
    let code = if mcp_entry && arguments.len() == 1 {
        rea_mcp::run_stdio(&compose::Production)
    } else {
        rea_cli::run(arguments, &compose::Production)
    };
    std::process::exit(code);
}
