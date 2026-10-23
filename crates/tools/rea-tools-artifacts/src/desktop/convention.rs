//! Path-segment desktop layout conventions.
//!
//! Byte-for-byte port of `desktopPathConventions` in
//! `src/domain/nativeConvention.ts`. These are inferences from path segments,
//! never observations of runtime behavior. Original path segments are
//! preserved; only folded (lowercased) copies drive recognition.

/// IL2CPP native library filenames (`DESKTOP_IL2CPP_LIBRARIES`).
const DESKTOP_IL2CPP_LIBRARIES: [&str; 4] = [
    "gameassembly.dll",
    "gameassembly.so",
    "gameassembly.dylib",
    "libil2cpp.so",
];

/// Conventions decoded once from one slash-separated artifact path.
pub(crate) struct DesktopPathConventions {
    /// The `.../*_data/Managed` (or bundle `Contents/Resources/Data/Managed`)
    /// directory, using the original path segments, when present.
    pub unity_managed_directory: Option<String>,
    pub il2cpp_library: bool,
    pub electron_archive: bool,
    pub unreal_container: bool,
}

/// Lowercase one path segment (`foldSegment`, `toLocaleLowerCase("en-US")`).
fn fold_segment(segment: &str) -> String {
    segment.to_lowercase()
}

/// Parse desktop layout conventions while preserving original path segments.
pub(crate) fn desktop_path_conventions(path: &str) -> DesktopPathConventions {
    let segments: Vec<&str> = path.split('/').collect();
    let folded: Vec<String> = segments
        .iter()
        .map(|segment| fold_segment(segment))
        .collect();

    let mut unity_managed_directory: Option<String> = None;
    // `for (let index = 0; index + 2 < folded.length; index++)`
    if folded.len() >= 3 {
        for index in 0..folded.len().saturating_sub(2) {
            let segment = folded[index].as_str();
            let named_data_directory = segment.len() > 5 && segment.ends_with("_data");
            let bundle_data_directory = segment == "data"
                && index >= 2
                && folded[index - 1] == "resources"
                && folded[index - 2] == "contents";
            if (named_data_directory || bundle_data_directory) && folded[index + 1] == "managed" {
                unity_managed_directory = Some(segments[..index + 2].join("/"));
            }
        }
    }

    let name = folded.last().map(String::as_str).unwrap_or("");
    let second_last = if folded.len() >= 2 {
        folded[folded.len() - 2].as_str()
    } else {
        ""
    };

    let electron_archive =
        second_last == "resources" && (name == "app.asar" || name == "default_app.asar");

    let unreal_container = (name.ends_with(".pak") || name.ends_with(".utoc"))
        && folded.iter().enumerate().any(|(index, segment)| {
            segment == "content"
                && folded.get(index + 1).map(String::as_str) == Some("paks")
                && index + 2 < folded.len()
        });

    DesktopPathConventions {
        unity_managed_directory,
        il2cpp_library: DESKTOP_IL2CPP_LIBRARIES.contains(&name),
        electron_archive,
        unreal_container,
    }
}

/// Lowercased-segment match for a `(?:^|\/)word(?:\/|$)` component marker.
/// Matches when any `/`-delimited segment equals `word`.
pub(crate) fn has_path_segment(path: &str, word: &str) -> bool {
    path.split('/')
        .any(|segment| segment.to_lowercase() == word)
}

/// Easy Anti-Cheat marker: `(?:^|\/)easyanticheat(?:_eos)?(?:\/|$)`.
pub(crate) fn has_easy_anti_cheat_segment(path: &str) -> bool {
    path.split('/').any(|segment| {
        let folded = segment.to_lowercase();
        folded == "easyanticheat" || folded == "easyanticheat_eos"
    })
}
