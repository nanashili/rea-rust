//! Module, package, runtime-path and source-map resolution against an
//! inventoried artifact, without filesystem access or execution.
pub mod artifact_path;
pub mod graph_adapter;
pub mod mode;
pub mod package_imports;
pub mod source_map_paths;
pub mod syntax;
pub mod web_url;
