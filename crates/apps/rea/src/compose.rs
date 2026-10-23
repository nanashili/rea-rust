//! Composition of every migrated tool family into one registry.
//!
//! Deep-analysis providers are collected in the original registry order
//! (Hopper, Ghidra, IDA, Kuna, then explicitly opted-in local providers);
//! the binary session owns selection among them.
use rea_analysis::AnalysisProvider;
use rea_mcp::{CompletionProvider, Composition, Registry, Session};
use std::sync::Arc;

/// The production composition used by both MCP and the CLI.
pub struct Production;

fn providers(session: &Arc<Session>) -> Vec<Arc<dyn AnalysisProvider>> {
    let environment = session.environment();
    let mut providers = Vec::new();
    providers.extend(rea_provider_hopper::providers(environment));
    providers.extend(rea_provider_ghidra::providers(environment));
    providers.extend(rea_provider_ida::providers(environment));
    providers.extend(rea_provider_kuna::providers(environment));
    providers
}

impl Composition for Production {
    fn register(&self, registry: &mut Registry, session: &Arc<Session>) {
        rea_tools_ledger::register(registry);
        rea_tools_artifacts::register(registry);
        rea_tools_captures::register(registry);
        rea_tools_android::register(registry);
        rea_tools_web::register(registry);
        rea_tools_managed::register(registry);
        rea_tools_application::register(registry);
        rea_tools_debug::register(registry);
        rea_tools_process::register(registry);
        rea_tools_binary::register(registry, session, providers(session));
        rea_tools_enhanced::register(registry);
    }

    fn completion(&self, session: &Arc<Session>) -> Arc<dyn CompletionProvider> {
        rea_tools_binary::completion(session)
    }
}
