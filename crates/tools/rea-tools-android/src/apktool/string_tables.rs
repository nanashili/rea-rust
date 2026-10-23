//! Projection of selected decoded string tables.
//!
//! Compatibility owner: `src/apktool/ApktoolStringTables.ts`. Physical reads
//! own parsed counts independently of output allocation; the default and
//! selected locale tables are projected under aggregate byte and entry bounds.

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::Path;

use super::locale::directory_suffix;
use super::strings_xml::{self, DecodedStringEntry};
use super::workspace::{ReadError, Workspace};

const MAX_STRINGS: usize = 2_000;
const MAX_AGGREGATE_STRINGS: usize = 10_000;
const AGGREGATE_STRINGS_XML_MAX_BYTES: usize = 32 * 1024 * 1024;
const STRINGS_XML_MAX_BYTES: usize = 8 * 1024 * 1024;

/// Caller selection for string projection.
#[derive(Clone, Debug)]
pub struct Selection {
    pub include_strings: bool,
    pub string_tables_only: bool,
    pub locale: Option<String>,
    pub locales: Option<Vec<String>>,
}

/// The projected result (`ApktoolStringProjection`).
pub struct StringProjection {
    pub strings: Vec<DecodedStringEntry>,
    pub tables: Vec<StringTable>,
    pub limitations: Vec<String>,
    pub coverage: &'static str,
}

/// One projected table row (`StringTable`), rendered to JSON for the result.
#[derive(Clone, Debug)]
pub struct StringTable {
    pub locale: Option<String>,
    pub status: &'static str,
    pub strings: Vec<DecodedStringEntry>,
    pub total_count: Option<u64>,
    pub unparsed_count: Option<u64>,
    pub coverage: &'static str,
}

impl StringTable {
    pub fn to_json(&self) -> Value {
        json!({
            "locale": self.locale,
            "status": self.status,
            "strings": self
                .strings
                .iter()
                .map(|entry| json!({ "name": entry.name, "value": entry.value }))
                .collect::<Vec<_>>(),
            "total_count": self.total_count,
            "unparsed_count": self.unparsed_count,
            "coverage": self.coverage,
        })
    }
}

enum PhysicalTable {
    Present {
        entries: Vec<DecodedStringEntry>,
        total_count: u64,
        unparsed_count: u64,
    },
    Missing,
    Oversized {
        byte_budget: usize,
    },
    Malformed {
        message: String,
    },
}

struct ReadOutcome {
    fact: PhysicalTable,
    bytes: usize,
}

/// `readTable(resources, path, budget, signal)`.
fn read_table(
    workspace: &Workspace,
    path: &Path,
    budget: usize,
    cancellation: &Cancellation,
) -> Result<ReadOutcome, AnalysisError> {
    let source = workspace
        .read_text(path, budget, cancellation)
        .map_err(read_failure)?;
    let Some(text) = source.text else {
        return Ok(ReadOutcome {
            bytes: 0,
            fact: PhysicalTable::Missing,
        });
    };
    if source.truncated {
        return Ok(ReadOutcome {
            bytes: source.source_bytes,
            fact: PhysicalTable::Oversized {
                byte_budget: budget,
            },
        });
    }
    let bytes = source.source_bytes;
    match strings_xml::parse_decoded_strings(&text) {
        Err(error) => Ok(ReadOutcome {
            bytes,
            fact: PhysicalTable::Malformed {
                message: error.message,
            },
        }),
        Ok(parsed) => {
            let total_count = parsed.entries.len() as u64;
            let mut entries = parsed.entries;
            entries.truncate(MAX_STRINGS);
            Ok(ReadOutcome {
                bytes,
                fact: PhysicalTable::Present {
                    entries,
                    total_count,
                    unparsed_count: parsed.unparsed_count,
                },
            })
        }
    }
}

fn read_failure(error: ReadError) -> AnalysisError {
    match error {
        ReadError::Cancelled => AnalysisError::cancelled("decode_android_resources"),
        ReadError::Protocol(message) => AnalysisError::protocol(message),
        ReadError::Io { path, error } => AnalysisError::protocol(format!(
            "Apktool output could not be read: {}",
            crate::common::files::node_io_message(&error, "read", &path)
        )),
    }
}

fn unavailable_limitation(
    fact: &PhysicalTable,
    directory: &str,
    locale: Option<&str>,
    input: &Selection,
) -> String {
    match fact {
        PhysicalTable::Missing => match locale {
            None => "No default res/values/strings.xml was found in the decoded workspace".into(),
            Some(locale) => format!("No strings.xml was found for locale {locale}"),
        },
        PhysicalTable::Oversized { byte_budget } => {
            if input.locales.is_none() || locale.is_none() {
                format!("strings.xml exceeds the {byte_budget}-byte projection budget")
            } else {
                format!(
                    "strings.xml for locale {} exceeds the {byte_budget}-byte projection budget",
                    locale.unwrap_or_default()
                )
            }
        }
        PhysicalTable::Malformed { message } => format!(
            "String table {} could not be projected: {message}; entry counts are unknown",
            super::version::json_string(&format!("res/{directory}/strings.xml"))
        ),
        PhysicalTable::Present { .. } => String::new(),
    }
}

/// `projectApktoolStringTables(resources, workspace, input, signal)`.
pub fn project_string_tables(
    workspace: &Workspace,
    decoded_root: &Path,
    input: &Selection,
    cancellation: &Cancellation,
) -> Result<StringProjection, (AnalysisError, StringProjection)> {
    if !input.include_strings {
        return Ok(StringProjection {
            strings: Vec::new(),
            tables: Vec::new(),
            limitations: Vec::new(),
            coverage: "complete",
        });
    }

    let primary = input.locale.clone();
    // Unique-preserving order: [primary, ...locales].
    let mut locales: Vec<Option<String>> = Vec::new();
    let mut seen: Vec<Option<String>> = Vec::new();
    let push_locale = |value: Option<String>,
                       locales: &mut Vec<Option<String>>,
                       seen: &mut Vec<Option<String>>| {
        if !seen.contains(&value) {
            seen.push(value.clone());
            locales.push(value);
        }
    };
    push_locale(primary.clone(), &mut locales, &mut seen);
    if let Some(selected) = &input.locales {
        for locale in selected {
            push_locale(Some(locale.clone()), &mut locales, &mut seen);
        }
    }

    let mut physical: BTreeMap<String, PhysicalTableShared> = BTreeMap::new();
    let mut tables: Vec<StringTable> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();
    let add_limitation = |message: String, limitations: &mut Vec<String>| {
        if !limitations.contains(&message) {
            limitations.push(message);
        }
    };
    let mut xml_bytes = 0usize;
    let mut output_entries = 0usize;
    let mut aggregate_capped = false;

    let build_projection = |tables: &[StringTable],
                            limitations: &[String],
                            aggregate_capped: bool|
     -> StringProjection {
        let mut limitations = limitations.to_vec();
        if aggregate_capped {
            let message =
                "Aggregate string table projection stopped due to resource limits".to_owned();
            if !limitations.contains(&message) {
                limitations.push(message);
            }
        }
        let strings = if input.string_tables_only {
            Vec::new()
        } else {
            tables
                .first()
                .map(|table| table.strings.clone())
                .unwrap_or_default()
        };
        let coverage = if tables.iter().any(|table| table.coverage == "partial") {
            "partial"
        } else {
            "complete"
        };
        StringProjection {
            strings,
            tables: tables.to_vec(),
            limitations,
            coverage,
        }
    };

    for (index, locale) in locales.iter().enumerate() {
        if cancellation.reason().is_some() {
            add_limitation(stopped_limitation(&locales, index), &mut limitations);
            let mut partial = build_projection(&tables, &limitations, aggregate_capped);
            partial.coverage = "partial";
            return Err((
                AnalysisError::cancelled("decode_android_resources"),
                partial,
            ));
        }
        let directory = match locale {
            None => "values".to_owned(),
            Some(locale) => format!("values-{}", directory_suffix(locale)),
        };
        let label = match locale {
            None => "default res/values/strings.xml".to_owned(),
            Some(_) => format!("res/{directory}/strings.xml"),
        };

        if !physical.contains_key(&directory) {
            let budget = STRINGS_XML_MAX_BYTES
                .min(AGGREGATE_STRINGS_XML_MAX_BYTES.saturating_sub(xml_bytes));
            if budget == 0 || output_entries >= MAX_AGGREGATE_STRINGS {
                tables.push(StringTable {
                    locale: locale.clone(),
                    status: "skipped",
                    strings: Vec::new(),
                    total_count: None,
                    unparsed_count: None,
                    coverage: "partial",
                });
                add_limitation(
                    format!("Projection for {label} skipped: aggregate resource limit reached"),
                    &mut limitations,
                );
                aggregate_capped = true;
                continue;
            }
            let path = decoded_root
                .join("res")
                .join(&directory)
                .join("strings.xml");
            let read = match read_table(workspace, &path, budget, cancellation) {
                Ok(read) => read,
                Err(cause) => {
                    add_limitation(stopped_limitation(&locales, index), &mut limitations);
                    let mut partial = build_projection(&tables, &limitations, aggregate_capped);
                    partial.coverage = "partial";
                    return Err((cause, partial));
                }
            };
            xml_bytes += read.bytes;
            if matches!(read.fact, PhysicalTable::Oversized { .. })
                && budget < STRINGS_XML_MAX_BYTES
            {
                aggregate_capped = true;
            }
            physical.insert(directory.clone(), PhysicalTableShared::new(read.fact));
        }

        let shared = physical.get(&directory).expect("physical table present");
        match &shared.fact {
            PhysicalTable::Present {
                entries,
                total_count,
                unparsed_count,
            } => {
                // Account the default-batch double copy before selecting.
                let copies = if index == 0 && input.locales.is_some() && !input.string_tables_only {
                    2usize
                } else {
                    1usize
                };
                let remaining = MAX_AGGREGATE_STRINGS.saturating_sub(output_entries);
                let select_count = (remaining / copies).min(entries.len());
                let selected: Vec<DecodedStringEntry> = entries[..select_count].to_vec();
                output_entries += selected.len() * copies;
                let skipped = selected.is_empty() && *total_count > 0;
                let limited = (selected.len() as u64) < (*total_count).min(MAX_STRINGS as u64);
                if limited {
                    aggregate_capped = true;
                }
                let coverage = if (selected.len() as u64) < *total_count || *unparsed_count > 0 {
                    "partial"
                } else {
                    "complete"
                };
                let selected_len = selected.len();
                tables.push(StringTable {
                    locale: locale.clone(),
                    status: if skipped { "skipped" } else { "present" },
                    strings: selected,
                    total_count: Some(*total_count),
                    unparsed_count: Some(*unparsed_count),
                    coverage,
                });
                if skipped {
                    add_limitation(
                        format!("Projection for {label} skipped: aggregate resource limit reached"),
                        &mut limitations,
                    );
                }
                if *unparsed_count > 0 {
                    let message = if input.locales.is_none() || locale.is_none() {
                        format!(
                            "String entries omitted due to unsupported markup or missing names: {unparsed_count}"
                        )
                    } else {
                        format!(
                            "String entries omitted in locale {} due to unsupported markup or missing names: {unparsed_count}",
                            locale.clone().unwrap_or_default()
                        )
                    };
                    add_limitation(message, &mut limitations);
                }
                if limited && !skipped {
                    add_limitation(
                        format!(
                            "Locale {} strings reports {selected_len} entries due to aggregate strings limit",
                            locale.clone().unwrap_or_else(|| "default".to_owned())
                        ),
                        &mut limitations,
                    );
                } else if *total_count > MAX_STRINGS as u64 && !skipped {
                    let message = if input.locales.is_none() || locale.is_none() {
                        format!("strings reports the first {selected_len} of {total_count} entries")
                    } else {
                        format!(
                            "Locale {} strings reports the first {selected_len} of {total_count} entries",
                            locale.clone().unwrap_or_default()
                        )
                    };
                    add_limitation(message, &mut limitations);
                }
            }
            other => {
                let (status, total, unparsed, coverage): (
                    &'static str,
                    Option<u64>,
                    Option<u64>,
                    &'static str,
                ) = match other {
                    PhysicalTable::Missing => ("missing", Some(0), Some(0), "complete"),
                    PhysicalTable::Oversized { .. } => ("oversized", None, None, "partial"),
                    PhysicalTable::Malformed { .. } => ("malformed", None, None, "partial"),
                    PhysicalTable::Present { .. } => unreachable!(),
                };
                tables.push(StringTable {
                    locale: locale.clone(),
                    status,
                    strings: Vec::new(),
                    total_count: total,
                    unparsed_count: unparsed,
                    coverage,
                });
                add_limitation(
                    unavailable_limitation(other, &directory, locale.as_deref(), input),
                    &mut limitations,
                );
            }
        }
    }

    Ok(build_projection(&tables, &limitations, aggregate_capped))
}

fn stopped_limitation(locales: &[Option<String>], index: usize) -> String {
    let current = locales
        .get(index)
        .map(|locale| match locale {
            None => "null".to_owned(),
            Some(value) => super::version::json_string(value),
        })
        .unwrap_or_else(|| "null".to_owned());
    let remaining = locales.len().saturating_sub(index + 1);
    format!(
        "String projection stopped at locale {current}; this selection and {remaining} remaining selections were not projected"
    )
}

/// Owns one physical table read so repeated locale aliases reuse it.
struct PhysicalTableShared {
    fact: PhysicalTable,
}

impl PhysicalTableShared {
    fn new(fact: PhysicalTable) -> Self {
        Self { fact }
    }
}
