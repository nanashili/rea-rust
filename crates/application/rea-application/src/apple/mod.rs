//! Apple platform workflows: application graphs, asset catalogs, bundles, plists,
//! dyld load paths and code signatures.

pub mod app_bundle_executable;
pub mod application_graph;
pub mod asset_catalog;
pub mod asset_catalog_workflow;
pub mod dyld_paths;
pub mod dylib_resolution;
pub mod dylib_resolution_capture;
pub mod dylib_resolution_inputs;
pub mod keyed_archive;
pub mod plist;
pub mod signature_inspection;
