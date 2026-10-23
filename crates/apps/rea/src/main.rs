//! `rea`: the native production executable.
//!
//! Routing mirrors the original `scripts/rea.mjs`: bare `mcp`/`--mcp` serves
//! stdio MCP; everything else (including `mcp --http`, `mcp add` and
//! `mcp doctor`) is owned by the CLI.
mod compose;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mcp_entry = matches!(arguments.first().map(String::as_str), Some("mcp" | "--mcp"));
    let code = if mcp_entry && arguments.len() == 1 {
        rea_mcp::run_stdio(&compose::Production)
    } else {
        rea_cli::run(arguments, &compose::Production)
    };
    std::process::exit(code);
}
