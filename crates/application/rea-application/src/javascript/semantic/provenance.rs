//! Provenance constructors and canonicalization for semantic binding values.

use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::ast_values::js_number_string;
use super::state::ModuleOrigin;
use super::value_types::{JsString, Primitive};
use crate::javascript::graph::json::compare_code_points;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BindingProvenance {
    Module {
        origins: Vec<ModuleOrigin>,
    },
    Local,
    Ambiguous {
        origins: Vec<ModuleOrigin>,
        reason: String,
    },
    Unknown {
        reason: String,
    },
    Cycle {
        reason: String,
    },
}

pub type JavaScriptBindingProvenance = BindingProvenance;

impl Serialize for BindingProvenance {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (status, reason) = match self {
            Self::Module { .. } => ("module", None),
            Self::Local => ("local", None),
            Self::Ambiguous { reason, .. } => ("ambiguous", Some(reason)),
            Self::Unknown { reason } => ("unknown", Some(reason)),
            Self::Cycle { reason } => ("cycle", Some(reason)),
        };

        let mut record = serializer.serialize_struct("BindingProvenance", 3)?;
        record.serialize_field("status", status)?;
        record.serialize_field("origins", self.origins())?;
        record.serialize_field("reason", &reason)?;
        record.end()
    }
}

struct ProvenanceFields {
    status: String,
    origins: Vec<ModuleOrigin>,
    reason: ProvenanceReason,
}

impl<'de> Deserialize<'de> for ProvenanceFields {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldsVisitor;

        impl<'de> serde::de::Visitor<'de> for FieldsVisitor {
            type Value = ProvenanceFields;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a provenance object")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                let mut status = None;
                let mut origins = None;
                let mut reason = None;

                while let Some(field) = map.next_key::<String>()? {
                    match field.as_str() {
                        "status" => {
                            if status.is_some() {
                                return Err(serde::de::Error::duplicate_field("status"));
                            }
                            status = Some(map.next_value()?);
                        }
                        "origins" => {
                            if origins.is_some() {
                                return Err(serde::de::Error::duplicate_field("origins"));
                            }
                            origins = Some(map.next_value()?);
                        }
                        "reason" => {
                            if reason.is_some() {
                                return Err(serde::de::Error::duplicate_field("reason"));
                            }
                            reason = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(ProvenanceFields {
                    status: status.ok_or_else(|| serde::de::Error::missing_field("status"))?,
                    origins: origins.ok_or_else(|| serde::de::Error::missing_field("origins"))?,
                    reason: reason.ok_or_else(|| serde::de::Error::missing_field("reason"))?,
                })
            }
        }

        deserializer.deserialize_map(FieldsVisitor)
    }
}

enum ProvenanceReason {
    Null,
    Text(String),
}

impl<'de> Deserialize<'de> for ProvenanceReason {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Ok(match Option::<String>::deserialize(deserializer)? {
            Some(reason) => Self::Text(reason),
            None => Self::Null,
        })
    }
}

impl<'de> Deserialize<'de> for BindingProvenance {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let fields = ProvenanceFields::deserialize(deserializer)?;
        match fields.status.as_str() {
            "module"
                if fields.origins.len() == 1 && matches!(fields.reason, ProvenanceReason::Null) =>
            {
                Ok(Self::Module {
                    origins: fields.origins,
                })
            }
            "local"
                if fields.origins.is_empty() && matches!(fields.reason, ProvenanceReason::Null) =>
            {
                Ok(Self::Local)
            }
            "ambiguous" => match fields.reason {
                ProvenanceReason::Text(reason) => Ok(Self::Ambiguous {
                    origins: fields.origins,
                    reason,
                }),
                ProvenanceReason::Null => Err(serde::de::Error::custom(
                    "ambiguous provenance requires a reason",
                )),
            },
            "unknown" => match (fields.origins.is_empty(), fields.reason) {
                (true, ProvenanceReason::Text(reason)) => Ok(Self::Unknown { reason }),
                _ => Err(serde::de::Error::custom(
                    "unknown provenance requires empty origins and a reason",
                )),
            },
            "cycle" => match (fields.origins.is_empty(), fields.reason) {
                (true, ProvenanceReason::Text(reason)) => Ok(Self::Cycle { reason }),
                _ => Err(serde::de::Error::custom(
                    "cycle provenance requires empty origins and a reason",
                )),
            },
            status => Err(serde::de::Error::custom(format!(
                "invalid provenance fields for status {status:?}"
            ))),
        }
    }
}

pub fn semantic_local_provenance() -> BindingProvenance {
    BindingProvenance::Local
}

pub fn semantic_unresolved_provenance(
    status: &str,
    reason: impl Into<String>,
) -> BindingProvenance {
    match status {
        "unknown" => BindingProvenance::Unknown {
            reason: reason.into(),
        },
        "cycle" => BindingProvenance::Cycle {
            reason: reason.into(),
        },
        other => panic!("invalid unresolved provenance status: {other}"),
    }
}

pub fn semantic_ambiguous_provenance(
    origins: &[ModuleOrigin],
    reason: impl Into<String>,
) -> BindingProvenance {
    BindingProvenance::Ambiguous {
        origins: origins.to_vec(),
        reason: reason.into(),
    }
}

pub fn semantic_origins_provenance(origins: &[ModuleOrigin]) -> BindingProvenance {
    let unique = unique_semantic_origins(origins);
    if unique.len() == 1 {
        BindingProvenance::Module { origins: unique }
    } else {
        semantic_ambiguous_provenance(&unique, "Multiple module origins.")
    }
}

pub fn unique_semantic_origins(origins: &[ModuleOrigin]) -> Vec<ModuleOrigin> {
    let mut unique = Vec::new();
    for origin in origins {
        let key = origin_key(origin);

        if let Some(existing) = unique
            .iter_mut()
            .find(|existing| origin_key(existing) == key)
        {
            // JavaScript's Map constructor keeps the original insertion slot,
            // while assigning the latest value for a duplicate key.
            *existing = origin.clone();
        } else {
            unique.push(origin.clone());
        }
    }
    unique.sort_by(|left, right| compare_code_points(&origin_key(left), &origin_key(right)));
    unique
}

fn origin_key(origin: &ModuleOrigin) -> String {
    serde_json::to_string(&(
        &origin.specifier,
        &origin.imported_path,
        origin
            .resolution_mode
            .map(|mode| mode.as_str())
            .unwrap_or("import"),
    ))
    .expect("module origin is serializable")
}

pub fn semantic_primitive_key(value: &Primitive) -> String {
    let kind = match value {
        Primitive::String(_) => "string",
        Primitive::Number(number) => {
            let encoded = if number.is_finite() {
                js_number_string(*number)
            } else {
                "null".into()
            };
            return format!("number:{encoded}");
        }
        Primitive::Boolean(_) => "boolean",
        Primitive::Null => "null",
    };
    format!(
        "{kind}:{}",
        serde_json::to_string(value).expect("primitive is serializable")
    )
}

pub fn semantic_builtin_namespace_path(imported_path: &[JsString]) -> bool {
    imported_path.is_empty() || (imported_path.len() == 1 && imported_path[0] == "default")
}

impl BindingProvenance {
    pub fn origins(&self) -> &[ModuleOrigin] {
        match self {
            Self::Module { origins } | Self::Ambiguous { origins, .. } => origins.as_slice(),
            Self::Local | Self::Unknown { .. } | Self::Cycle { .. } => &[],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn surrogate_origin() -> ModuleOrigin {
        ModuleOrigin {
            resolution_mode: Some(super::super::state::ResolutionMode::Import),
            specifier: JsString::from_utf16([0xd800]),
            imported_path: vec![JsString::from_utf16([0xdc00])],
        }
    }

    #[test]
    fn provenance_round_trips_javascript_utf16_origins() {
        let values = [
            BindingProvenance::Module {
                origins: vec![surrogate_origin()],
            },
            BindingProvenance::Ambiguous {
                origins: vec![surrogate_origin()],
                reason: "multiple origins".to_owned(),
            },
        ];

        for value in values {
            let encoded = serde_json::to_string(&value).expect("provenance serializes");
            let decoded: BindingProvenance =
                serde_json::from_str(&encoded).expect("provenance deserializes");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn provenance_deserialization_rejects_invalid_variant_shapes() {
        let invalid = [
            r#"{"status":"module","origins":[],"reason":null}"#,
            r#"{"status":"local","origins":[{"specifier":"x","importedPath":[]}],"reason":null}"#,
            r#"{"status":"unknown","origins":[],"reason":null}"#,
            r#"{"status":"ambiguous","origins":[],"reason":null}"#,
            r#"{"status":"other","origins":[],"reason":"x"}"#,
            r#"{"status":"local","origins":[]}"#,
        ];

        for input in invalid {
            assert!(
                serde_json::from_str::<BindingProvenance>(input).is_err(),
                "accepted invalid provenance: {input}"
            );
        }
    }
}
