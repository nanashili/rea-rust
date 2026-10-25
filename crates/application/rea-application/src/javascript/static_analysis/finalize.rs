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
    let offsets = Utf16OffsetIndex::new(source);
    for finding in &mut analysis.references {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            &offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.endpoints {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            &offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.storage {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            &offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut analysis.role_paths {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            &offsets,
            finding.location.start,
            modules,
        );
    }
    attribute_electron(&mut analysis.electron, &offsets, modules);
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

fn attribute_electron(
    electron: &mut ElectronFindings,
    offsets: &Utf16OffsetIndex,
    modules: &ModuleRangeIndex,
) {
    for finding in &mut electron.browser_windows {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.context_bridge_apis {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.ipc {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.sender_validations {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.utility_processes {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
    for finding in &mut electron.native_addon_bindings {
        apply_module(
            &mut finding.module_key,
            &mut finding.module_runtime,
            offsets,
            finding.location.start,
            modules,
        );
    }
}

fn apply_module(
    module_key: &mut Option<String>,
    module_runtime: &mut Option<String>,
    offsets: &Utf16OffsetIndex,
    point: SourcePoint,
    modules: &ModuleRangeIndex,
) {
    let Some(offset) = offsets.offset(point) else {
        return;
    };
    let Some(module) = modules.find(Some(offset)) else {
        return;
    };
    *module_key = Some(module.key.clone());
    *module_runtime = Some(module.runtime.clone());
}

struct Utf16OffsetIndex {
    lines: Vec<(i64, usize, Vec<usize>)>,
}

impl Utf16OffsetIndex {
    fn new(source: &str) -> Self {
        let mut lines = Vec::new();
        let mut line_start = 0_i64;
        let mut line_length = 0_usize;
        let mut surrogate_boundaries = Vec::new();
        let mut offset = 0_i64;
        let mut characters = source.chars().peekable();

        while let Some(character) = characters.next() {
            if matches!(character, '\r' | '\n' | '\u{2028}' | '\u{2029}') {
                let newline_length = if character == '\r' && characters.peek() == Some(&'\n') {
                    characters.next();
                    2
                } else {
                    1
                };
                offset += newline_length;
                lines.push((line_start, line_length, surrogate_boundaries));
                line_start = offset;
                line_length = 0;
                surrogate_boundaries = Vec::new();
            } else {
                let units = character.len_utf16();
                if units == 2 {
                    surrogate_boundaries.push(line_length + 1);
                }
                line_length += units;
                offset += i64::try_from(units).unwrap_or(i64::MAX);
            }
        }

        lines.push((line_start, line_length, surrogate_boundaries));
        Self { lines }
    }

    fn offset(&self, point: SourcePoint) -> Option<i64> {
        if point.line == 0 {
            return None;
        }
        let target_column = usize::try_from(point.column).ok()?;
        let (line_start, line_length, surrogate_boundaries) =
            self.lines.get(usize::try_from(point.line - 1).ok()?)?;
        if target_column > *line_length {
            return None;
        }
        let rounded_units = usize::from(surrogate_boundaries.binary_search(&target_column).is_ok());
        Some(*line_start + i64::try_from(target_column + rounded_units).ok()?)
    }
}

#[cfg(test)]
mod tests {
    use super::Utf16OffsetIndex;
    use crate::javascript::contracts::static_analysis::SourcePoint;

    fn legacy_utf16_offset_for_point(source: &str, point: SourcePoint) -> Option<i64> {
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

        (line == point.line && line_column >= target_column).then_some(offset)
    }

    #[test]
    fn utf16_index_preserves_unicode_columns_and_crlf_lines() {
        let index = Utf16OffsetIndex::new("a😀\r\nb");

        assert_eq!(index.offset(SourcePoint { line: 1, column: 0 }), Some(0));
        assert_eq!(index.offset(SourcePoint { line: 1, column: 1 }), Some(1));
        assert_eq!(index.offset(SourcePoint { line: 1, column: 2 }), Some(3));
        assert_eq!(index.offset(SourcePoint { line: 1, column: 3 }), Some(3));
        assert_eq!(index.offset(SourcePoint { line: 2, column: 0 }), Some(5));
        assert_eq!(index.offset(SourcePoint { line: 2, column: 1 }), Some(6));
    }

    #[test]
    fn utf16_index_handles_all_line_terminators_and_rejects_invalid_points() {
        let index = Utf16OffsetIndex::new("a\nb\rc\u{2028}d\u{2029}e");

        assert_eq!(index.offset(SourcePoint { line: 1, column: 1 }), Some(1));
        assert_eq!(index.offset(SourcePoint { line: 2, column: 1 }), Some(3));
        assert_eq!(index.offset(SourcePoint { line: 3, column: 1 }), Some(5));
        assert_eq!(index.offset(SourcePoint { line: 4, column: 1 }), Some(7));
        assert_eq!(index.offset(SourcePoint { line: 5, column: 1 }), Some(9));
        assert_eq!(index.offset(SourcePoint { line: 0, column: 0 }), None);
        assert_eq!(index.offset(SourcePoint { line: 6, column: 0 }), None);
        assert_eq!(index.offset(SourcePoint { line: 1, column: 2 }), None);
    }

    #[test]
    fn utf16_index_matches_the_previous_scanner_for_representative_points() {
        let sources = [
            "a😀\r\nb",
            "\r\n😀\ntext\u{2028}z\u{2029}",
            "😀😀\rplain\n終",
            "",
        ];

        for source in sources {
            let index = Utf16OffsetIndex::new(source);
            for line in 0..=8 {
                for column in 0..=12 {
                    let point = SourcePoint { line, column };
                    assert_eq!(
                        index.offset(point),
                        legacy_utf16_offset_for_point(source, point),
                        "source={source:?}, line={line}, column={column}"
                    );
                }
            }
        }
    }

    #[test]
    fn utf16_index_keeps_single_line_storage_bounded() {
        let source = "x".repeat(100_000);
        let index = Utf16OffsetIndex::new(&source);

        assert_eq!(index.lines.len(), 1);
        assert!(index.lines[0].2.is_empty());
        assert_eq!(
            index.offset(SourcePoint {
                line: 1,
                column: 100_000,
            }),
            Some(100_000)
        );
    }
}
