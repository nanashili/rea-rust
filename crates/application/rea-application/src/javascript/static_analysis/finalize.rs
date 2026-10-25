//! Finalization for the JavaScript static-analysis pass.
//!
//! Findings are collected while walking the AST.  This module is the single
//! owner of the post-traversal work: module attribution, deterministic
//! limitations, and parser/semantic status.  Keeping that work here avoids
//! each producer having to duplicate range lookup and status policy.

use crate::javascript::contracts::static_analysis::{
    ElectronFindings, SourcePoint, StaticAnalysis,
};

use super::super::semantic::identity_writes::ELECTRON_IDENTITY_LIMITATION;
use super::findings::ModuleRangeIndex;

pub const RETURNED_REFERENCE_WIDENING_LIMITATION: &str = "Local returned-reference projections were conservatively widened; effects include additional source-local candidates.";

/// Attach the recovered bundle module to every module-attributable finding.
pub fn attribute_modules(analysis: &mut StaticAnalysis, source: &str, modules: &ModuleRangeIndex) {
    for finding in &mut analysis.references {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.endpoints {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.storage {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.role_paths {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    attribute_electron(&mut analysis.electron, source, modules);
}

/// Add the limitations whose source facts are known only after traversal.
pub fn finalize_limitations(
    analysis: &mut StaticAnalysis,
    parser_error_count: usize,
    unknown_findings: u64,
    returned_reference_widened: bool,
    electron_call_paths: bool,
    electron_call_path_limit_reached: bool,
    uncertain_type_only_side_effect: bool,
    has_electron_reference: bool,
) {
    analysis.limitations.clear();
    if returned_reference_widened {
        analysis
            .limitations
            .push(RETURNED_REFERENCE_WIDENING_LIMITATION.to_owned());
    }
    if electron_call_paths {
        analysis.limitations.push(
            "Bundled Electron call paths use static argument and closure substitutions. Conditions, ambient helper overrides, runtime reachability and arbitrary side effects remain unproven.".to_owned(),
        );
    }
    if electron_call_path_limit_reached {
        analysis.limitations.push(
            "Electron wrapper expansion reached its resource budget (1000000 visits/substitutions or depth 128); additional paths remain unknown.".to_owned(),
        );
    }
    if parser_error_count > 0 {
        analysis.limitations.push(
            "The parser recovered from syntax errors; affected facts are partial.".to_owned(),
        );
    }
    if unknown_findings > 0 {
        analysis.limitations.push(
            "One or more static keys, expressions, or Electron boundary values were dynamic and remain unknown.".to_owned(),
        );
    }
    if uncertain_type_only_side_effect {
        analysis.limitations.push(
            "Compiler options are unavailable; inline type-only imports or re-exports may preserve a module side-effect dependency.".to_owned(),
        );
    }
    if has_electron_reference {
        analysis
            .limitations
            .push(ELECTRON_IDENTITY_LIMITATION.to_owned());
    }
    analysis
        .limitations
        .push("JavaScript syntax was parsed as data and was never evaluated.".to_owned());

    analysis.parse_status = if parser_error_count > 0 || unknown_findings > 0 {
        super::super::contracts::static_analysis::ParseStatus::Partial
    } else {
        super::super::contracts::static_analysis::ParseStatus::Complete
    };
    analysis.parse_error_count = parser_error_count as u64;
}

fn attribute_electron(electron: &mut ElectronFindings, source: &str, modules: &ModuleRangeIndex) {
    for finding in &mut electron.browser_windows {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.context_bridge_apis {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.ipc {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.sender_validations {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.utility_processes {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.native_addon_bindings {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            source,
            finding.location.start,
            modules,
        );
    }
}

fn apply_module(
    module_key: &mut Option<String>,
    module_runtime: &mut Option<String>,
    source: &str,
    point: SourcePoint,
    modules: &ModuleRangeIndex,
) {
    let Some(offset) = utf16_offset_for_point(source, point) else {
        return;
    };
    let Some(module) = modules.find(Some(offset)) else {
        return;
    };
    *module_key = Some(module.key.clone());
    *module_runtime = Some(module.runtime.clone());
}

fn utf16_offset_for_point(source: &str, point: SourcePoint) -> Option<i64> {
    if point.line == 0 {
        return None;
    }
    let target_column = usize::try_from(point.column).ok()?;
    let mut line = 1_u32;
    let mut line_column = 0_usize;
    let mut offset = 0_i64;
    let mut characters = source.chars().peekable();

    while let Some(character) = characters.next() {
        if line == point.line {
            if line_column >= target_column {
                return Some(offset);
            }
            line_column = line_column.saturating_add(character.len_utf16());
        }

        offset = offset.saturating_add(i64::from(character.len_utf16() as u32));
        match character {
            '\r' => {
                if characters.peek() == Some(&'\n') {
                    characters.next();
                    offset = offset.saturating_add(1);
                }
                line = line.saturating_add(1);
                line_column = 0;
            }
            '\n' | '\u{2028}' | '\u{2029}' => {
                line = line.saturating_add(1);
                line_column = 0;
            }
            _ => {}
        }
    }

    if line == point.line && line_column >= target_column {
        return Some(offset);
    }
    None
}
