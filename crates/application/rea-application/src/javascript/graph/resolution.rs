//! The module-resolution port consumed by graph construction.
//!
//! Artifact-confined path resolution (`JavaScriptArtifactPathResolution`) and
//! `moduleResolutionModeForJavaScriptReference` are owned by the resolution
//! package. Graph builders consume their parsed results through this port and
//! never reinterpret declared paths themselves.

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj};

/// One `resolveArtifactPathByContext` request, minus the borrowed file,
/// directory and unanalyzed-file indexes the resolver owns.
#[derive(Clone, Debug)]
pub struct ResolveRequest<'a> {
    /// The exact declared path.
    pub declared_path: JsString,
    /// The artifact path that declares it.
    pub source_path: JsString,
    /// Resolution context.
    pub context: JsString,
    /// HTML `<base href>`, when the declaring document has one (`null` retained).
    pub html_base_href: Option<Json>,
    /// Import/require semantics.
    pub module_kind: Option<String>,
    /// Runtime loader owner.
    pub runtime_path_kind: Option<&'a str>,
}

impl<'a> ResolveRequest<'a> {
    /// A request without optional fields.
    pub fn new(declared_path: &'a str, source_path: &'a str, context: &'a str) -> Self {
        Self::new_exact(
            &JsString::from(declared_path),
            &JsString::from(source_path),
            &JsString::from(context),
        )
    }

    /// Build a request from source strings without decoding or replacing
    /// unpaired UTF-16 units.
    pub fn new_exact(declared_path: &JsString, source_path: &JsString, context: &JsString) -> Self {
        Self {
            declared_path: declared_path.clone(),
            source_path: source_path.clone(),
            context: context.clone(),
            html_base_href: None,
            module_kind: None,
            runtime_path_kind: None,
        }
    }

    /// The request in the TypeScript input field names, for recorded replay.
    pub fn to_json(&self) -> Json {
        let mut object = Obj::new()
            .with_static("declaredPath", Json::String(self.declared_path.clone()))
            .with_static("sourcePath", Json::String(self.source_path.clone()))
            .with_static("context", Json::String(self.context.clone()));
        if let Some(base) = &self.html_base_href {
            object.set("htmlBaseHref", base.clone());
        }
        if let Some(kind) = &self.module_kind {
            object.set("moduleKind", kind.as_str());
        }
        if let Some(kind) = self.runtime_path_kind {
            object.set("runtimePathKind", kind);
        }
        object.into()
    }
}

/// The resolution owner's API as graph construction consumes it.
pub trait ArtifactPathResolver {
    /// `resolveArtifactPathByContext`: an `ArtifactPathResolution` record.
    fn resolve(&self, request: &ResolveRequest<'_>) -> Json;

    /// `moduleResolutionModeForJavaScriptReference`.
    fn module_resolution_mode(
        &self,
        source_path: &JsString,
        reference_kind: &str,
        explicit_mode: Option<&str>,
    ) -> String;
}

/// `artifactPathResolutionProperties`: conditional identities retained as facts.
pub fn resolution_properties(resolution: Option<&Json>) -> Obj {
    let mut properties = Obj::new();
    let Some(resolution) = resolution else {
        return properties;
    };
    if let Some(candidate) = resolution.get("candidate_path") {
        properties.set("candidate_path", candidate.clone());
    }
    if let Some(branches) = resolution.get("conditional_resolutions") {
        let branches = branches
            .arr()
            .iter()
            .map(|branch| {
                let mut value = Obj::new()
                    .with_static("mode", branch.at("mode").clone())
                    .with_static("resolution_status", branch.at("resolution_status").clone())
                    .with_static("resolved_path", branch.at("resolved_path").clone())
                    .with_static("limitations", branch.at("limitations").clone());
                if let Some(candidate) = branch.get("candidate_path") {
                    value.set("candidate_path", candidate.clone());
                }
                Json::from(value)
            })
            .collect();
        properties.set("conditional_resolutions", Json::array(branches));
    }
    properties
}

/// `moduleResolutionModeProperties`.
pub fn resolution_mode_properties(mode: Option<&str>) -> Obj {
    mode.map_or_else(Obj::new, |mode| {
        Obj::new().with_static("resolution_mode", mode)
    })
}

/// Resolution limitations as owned strings.
pub fn limitations(resolution: &Json) -> Vec<JsString> {
    resolution
        .at("limitations")
        .arr()
        .iter()
        .map(|value| value.text().clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_request_preserves_unpaired_utf16_source_text() {
        let declared = JsString::from_utf16(vec![0xd800, b'/' as u16, b'x' as u16]);
        let source = JsString::from("entry.js");
        let context = JsString::from("module-specifier");

        let request = ResolveRequest::new_exact(&declared, &source, &context);

        assert_eq!(request.declared_path, declared);
        assert_eq!(
            request.to_json().stringify(),
            r#"{"declaredPath":"\ud800/x","sourcePath":"entry.js","context":"module-specifier"}"#
        );
    }
}
