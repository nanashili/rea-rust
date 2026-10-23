mod analysis;
mod batch;
mod cache;
mod cache_inventory;
mod configuration;
mod decompiler_facts;
mod decompiler_pool;
mod encoding;
mod failure;
mod inventory;
mod macho_starts;
mod metadata;
mod program_retention;
mod protocol;
mod server;
mod session;
mod target;
mod target_file;
mod transport;

fn main() {
    if let Err(error) = server::run() {
        eprintln!("rea-ghidra-rust-worker: {error:#}");
        std::process::exit(1);
    }
}
