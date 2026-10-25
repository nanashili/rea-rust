//! Provider adapter for application-owned JavaScript artifact acquisition.

use super::reader::{ArtifactEntry, ArtifactReader, ReaderFailure, RetainedReader};
use rea_application::javascript::acquisition::{
    JavaScriptArtifactFileSet, JavaScriptReader, JavaScriptReaderEntry,
};
use rea_core::JsString;
use rea_core::artifact_inventory::ArtifactInventoryResult;
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};

/// Concrete reader adapter used by the application acquisition port.
pub(crate) struct ProviderJavaScriptReader {
    reader: Option<Box<dyn ArtifactReader>>,
    format: &'static str,
    root_bytes: Option<Vec<u8>>,
}

/// Provider-owned reader lifecycle for JavaScript reconstruction. The
/// application receives authenticated files through `acquire` and explicitly
/// closes this handle after transferring those owned facts to analysis.
pub struct JavaScriptArtifactReaderHandle {
    path: String,
    reader: ProviderJavaScriptReader,
}

impl JavaScriptArtifactReaderHandle {
    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn format(&self) -> &'static str {
        self.reader.format()
    }

    pub fn acquire<'a>(
        &mut self,
        snapshot: &'a ArtifactInventoryResult,
        cancellation: &Cancellation,
        source_paths: Option<&[String]>,
    ) -> Result<JavaScriptArtifactFileSet<'a>, ReaderFailure> {
        rea_application::javascript::acquisition::acquire(
            &mut self.reader,
            snapshot,
            cancellation,
            source_paths,
        )
    }

    pub fn close(&mut self) -> Result<(), ReaderFailure> {
        self.reader.close()
    }
}

pub fn open_javascript_artifact_reader(
    input_path: &str,
    expected_format: &str,
    cancellation: &Cancellation,
) -> Result<JavaScriptArtifactReaderHandle, ReaderFailure> {
    let (path, root_bytes, reader) =
        super::scan::create_reader_for_path(input_path, expected_format, cancellation)?;
    Ok(JavaScriptArtifactReaderHandle {
        path,
        reader: ProviderJavaScriptReader::new(reader, root_bytes),
    })
}

impl ProviderJavaScriptReader {
    pub(crate) fn new(reader: Box<dyn ArtifactReader>, root_bytes: Option<Vec<u8>>) -> Self {
        let format = reader.format();
        Self {
            reader: Some(reader),
            format,
            root_bytes,
        }
    }

    fn reader_mut(&mut self) -> Result<&mut (dyn ArtifactReader + '_), ReaderFailure> {
        match self.reader.as_mut() {
            Some(reader) => Ok(reader.as_mut()),
            None => Err(ReaderFailure::new(
                "io",
                "JavaScript artifact reader is already closed",
            )),
        }
    }
}

impl JavaScriptReader for ProviderJavaScriptReader {
    type Error = ReaderFailure;

    fn format(&self) -> &'static str {
        self.format
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
    ) -> Result<Vec<JavaScriptReaderEntry>, Self::Error> {
        let mut omissions = Vec::new();
        let reader = self.reader_mut()?;
        let entries = reader.entries(cancellation, &mut omissions)?;
        Ok(entries
            .into_iter()
            .map(|entry| {
                let filesystem_backed = reader.entry_is_filesystem_backed(&entry);
                to_application_entry(entry, filesystem_backed)
            })
            .collect())
    }

    fn open(
        &mut self,
        entry: &JavaScriptReaderEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, Self::Error> {
        self.reader_mut()?
            .open(&to_provider_entry(entry), cancellation)
    }

    fn nested_reader(
        &mut self,
        entry: &JavaScriptReaderEntry,
        bytes: Vec<u8>,
        cancellation: &Cancellation,
    ) -> Result<Option<Self>, Self::Error> {
        let _ = (entry, cancellation);
        Ok(Some(Self::new(
            Box::new(super::asar::AsarArtifactReader::new(bytes)),
            None,
        )))
    }

    fn verify_container(
        &mut self,
        expected_sha256: &str,
        expected_bytes: u64,
        _cancellation: &Cancellation,
    ) -> Result<(), Self::Error> {
        let Some(bytes) = self.root_bytes.as_ref() else {
            if self.format == "asar" {
                return Err(ReaderFailure::new(
                    "integrity",
                    "ASAR root bytes were not retained for verification",
                ));
            }
            return Ok(());
        };
        let digest = Sha256::digest(bytes);
        if bytes.len() as u64 != expected_bytes || format!("{digest:x}") != expected_sha256 {
            return Err(ReaderFailure::new(
                "integrity",
                "Artifact container changed after inventory",
            ));
        }
        Ok(())
    }

    fn close(&mut self) -> Result<(), Self::Error> {
        let Some(mut reader) = self.reader.take() else {
            return Ok(());
        };
        match reader.close() {
            Ok(()) => Ok(()),
            Err(mut failure) => {
                failure.retain_reader(RetainedReader::new(
                    format!("{} JavaScript artifact reader", self.format),
                    reader,
                ));
                Err(failure)
            }
        }
    }

    fn failure(reason: &'static str, message: String) -> Self::Error {
        ReaderFailure::new(reason, message)
    }

    fn with_cleanup(primary: Self::Error, cleanup: Self::Error) -> Self::Error {
        primary.with_cleanup_failure(cleanup)
    }
}

pub(crate) fn acquire_javascript_artifact_files<'a>(
    reader: Box<dyn ArtifactReader>,
    root_bytes: Option<Vec<u8>>,
    snapshot: &'a ArtifactInventoryResult,
    cancellation: &Cancellation,
    source_paths: Option<&[String]>,
) -> Result<JavaScriptArtifactFileSet<'a>, ReaderFailure> {
    let mut reader = ProviderJavaScriptReader::new(reader, root_bytes);
    rea_application::javascript::acquisition::acquire(
        &mut reader,
        snapshot,
        cancellation,
        source_paths,
    )
}

fn to_application_entry(entry: ArtifactEntry, filesystem_backed: bool) -> JavaScriptReaderEntry {
    JavaScriptReaderEntry {
        path: entry.path.to_string(),
        kind: entry.kind,
        declared_size: entry.declared_size,
        compressed_size: entry.compressed_size,
        executable: entry.executable,
        encrypted: entry.encrypted,
        byte_offset: entry.byte_offset,
        declared_sha256: entry.declared_sha256,
        unpacked: entry.unpacked,
        limitations: entry.limitations,
        adapter_key: entry.adapter_key.to_string(),
        filesystem_backed,
    }
}

fn to_provider_entry(entry: &JavaScriptReaderEntry) -> ArtifactEntry {
    ArtifactEntry {
        path: JsString::from(entry.path.clone()),
        kind: entry.kind,
        declared_size: entry.declared_size,
        compressed_size: entry.compressed_size,
        executable: entry.executable,
        encrypted: entry.encrypted,
        byte_offset: entry.byte_offset,
        declared_sha256: entry.declared_sha256.clone(),
        unpacked: entry.unpacked,
        limitations: entry.limitations.clone(),
        adapter_key: JsString::from(entry.adapter_key.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::{ProviderJavaScriptReader, acquire_javascript_artifact_files};
    use crate::artifact_graph::directory_reader::DirectoryArtifactReader;
    use crate::artifact_reader::{
        ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderCleanupOwner, ReaderFailure,
    };
    use rea_core::artifact_inventory::parse_validated_result;
    use rea_core::cancellation::Cancellation;
    use rea_mcp::Session;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::fs;

    fn inventory_for_file(
        path: &str,
        bytes: &[u8],
    ) -> rea_core::artifact_inventory::ArtifactInventoryResult {
        let digest = format!("{:x}", Sha256::digest(bytes));
        parse_validated_result(json!({
            "manifest": {
                "manifest_id": format!("agm_{}", "a".repeat(64)),
                "root_artifact_id": format!("art_{}", "d".repeat(64)),
                "root_sha256": "b".repeat(64),
                "root_format": "directory",
                "graph_sha256": "c".repeat(64),
                "node_count": 2,
                "occurrence_count": 1,
                "edge_count": 0
            },
            "nodes": [
                {
                    "artifact_id": format!("art_{}", "d".repeat(64)),
                    "format": "directory",
                    "sha256": "b".repeat(64),
                    "size": 1,
                    "media_type": null,
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                },
                {
                    "artifact_id": format!("art_{}", "e".repeat(64)),
                    "format": "file",
                    "sha256": digest,
                    "size": bytes.len(),
                    "media_type": "text/javascript",
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                }
            ],
            "occurrences": [{
                "occurrence_id": format!("occ_{}", "f".repeat(64)),
                "artifact_id": format!("art_{}", "e".repeat(64)),
                "parent_occurrence_id": null,
                "logical_path": path,
                "entry_kind": "file",
                "artifact_kind": "javascript",
                "artifact_format": "javascript-bundle",
                "declared_size": bytes.len(),
                "compressed_size": null,
                "executable": false,
                "encrypted": false,
                "hash_status": "verified",
                "source_location": null,
                "limitations": []
            }],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "coverage": {"scope": "root", "status": "complete"},
            "limitations": []
        }))
        .expect("test inventory parses")
    }

    #[test]
    fn acquires_javascript_from_real_directory_reader() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let bytes = b"console.log('ok');";
        fs::write(directory.path().join("main.js"), bytes).expect("write source");
        let snapshot = inventory_for_file("main.js", bytes);

        let result = acquire_javascript_artifact_files(
            Box::new(DirectoryArtifactReader::new(
                directory.path().to_str().expect("temporary path"),
            )),
            None,
            &snapshot,
            &Cancellation::default(),
            None,
        )
        .expect("directory acquisition succeeds");

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "main.js");
        assert_eq!(result.files[0].bytes, bytes.len() as u64);
    }

    #[test]
    fn rejects_changed_real_directory_file_as_integrity_failure() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let inventoried = b"console.log('before');";
        fs::write(directory.path().join("main.js"), b"console.log('after');")
            .expect("write changed source");
        let snapshot = inventory_for_file("main.js", inventoried);

        let failure = match acquire_javascript_artifact_files(
            Box::new(DirectoryArtifactReader::new(
                directory.path().to_str().expect("temporary path"),
            )),
            None,
            &snapshot,
            &Cancellation::default(),
            None,
        ) {
            Ok(_) => panic!("changed source must fail closed"),
            Err(failure) => failure,
        };

        assert_eq!(failure.reason, "integrity");
        assert!(failure.message.contains("main.js"));
    }

    #[test]
    fn acquires_verified_javascript_from_real_nested_asar_with_nfc_path() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let source = b"export const decomposed = true;";
        let archive = asar_bytes_with_filename(source, "e\u{301}.js");
        fs::write(directory.path().join("nested.asar"), &archive).expect("write archive");
        let archive_digest = format!("{:x}", Sha256::digest(&archive));
        let source_digest = format!("{:x}", Sha256::digest(source));
        let snapshot = parse_validated_result(json!({
            "manifest": {
                "manifest_id": format!("agm_{}", "1".repeat(64)),
                "root_artifact_id": format!("art_{}", "2".repeat(64)),
                "root_sha256": "3".repeat(64),
                "root_format": "directory",
                "graph_sha256": "4".repeat(64),
                "node_count": 3,
                "occurrence_count": 3,
                "edge_count": 0
            },
            "nodes": [
                {
                    "artifact_id": format!("art_{}", "2".repeat(64)),
                    "format": "directory",
                    "sha256": "3".repeat(64),
                    "size": 1,
                    "media_type": null,
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                },
                {
                    "artifact_id": format!("art_{}", "5".repeat(64)),
                    "format": "file",
                    "sha256": archive_digest,
                    "size": archive.len(),
                    "media_type": null,
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                },
                {
                    "artifact_id": format!("art_{}", "6".repeat(64)),
                    "format": "file",
                    "sha256": source_digest,
                    "size": source.len(),
                    "media_type": "text/javascript",
                    "architecture": null,
                    "content_state": "materialized",
                    "limitations": []
                }
            ],
            "occurrences": [
                {
                    "occurrence_id": format!("occ_{}", "7".repeat(64)),
                    "artifact_id": format!("art_{}", "5".repeat(64)),
                    "parent_occurrence_id": null,
                    "logical_path": "nested.asar",
                    "entry_kind": "file",
                    "artifact_kind": "container",
                    "artifact_format": "asar",
                    "declared_size": archive.len(),
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "verified",
                    "source_location": null,
                    "limitations": []
                },
                {
                    "occurrence_id": format!("occ_{}", "8".repeat(64)),
                    "artifact_id": format!("art_{}", "6".repeat(64)),
                    "parent_occurrence_id": null,
                    "logical_path": "nested.asar/é.js",
                    "entry_kind": "file",
                    "artifact_kind": "javascript",
                    "artifact_format": "javascript-bundle",
                    "declared_size": source.len(),
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "verified",
                    "source_location": null,
                    "limitations": []
                },
                {
                    "occurrence_id": format!("occ_{}", "9".repeat(64)),
                    "artifact_id": null,
                    "parent_occurrence_id": null,
                    "logical_path": ".",
                    "entry_kind": "directory",
                    "artifact_kind": "container",
                    "artifact_format": "directory",
                    "declared_size": null,
                    "compressed_size": null,
                    "executable": false,
                    "encrypted": false,
                    "hash_status": "verified",
                    "source_location": null,
                    "limitations": []
                }
            ],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "coverage": {"scope": "root", "status": "complete"},
            "limitations": []
        }))
        .expect("nested inventory parses");

        let result = acquire_javascript_artifact_files(
            Box::new(DirectoryArtifactReader::new(
                directory.path().to_str().expect("temporary path"),
            )),
            None,
            &snapshot,
            &Cancellation::default(),
            None,
        )
        .expect("nested acquisition succeeds");

        assert_eq!(result.files.len(), 1);
        assert_eq!(result.files[0].path, "nested.asar/é.js");
        assert_eq!(result.files[0].container_sha256, archive_digest);
        assert_eq!(result.files[0].sha256, source_digest);
        assert_eq!(result.files[0].bytes, source.len() as u64);
        assert!(format!("{:?}", result.files[0].text).contains("export const decomposed = true;"));
    }

    #[test]
    fn preserves_close_failure_for_session_retry_after_selection_failure() {
        let close_failures = std::sync::Arc::new(std::sync::Mutex::new(2_u8));
        let close_calls = std::sync::Arc::new(std::sync::Mutex::new(0_u8));
        let bytes = b"console.log('selection');";
        let snapshot = inventory_for_file("main.js", bytes);
        let mut failure = match acquire_javascript_artifact_files(
            Box::new(CloseProbe {
                close_failures: std::sync::Arc::clone(&close_failures),
                close_calls: std::sync::Arc::clone(&close_calls),
            }),
            None,
            &snapshot,
            &Cancellation::default(),
            Some(&["unknown.js".to_owned()]),
        ) {
            Ok(_) => panic!("unknown selection must fail before traversal"),
            Err(failure) => failure,
        };

        assert_eq!(failure.reason, "path");
        assert_eq!(*close_calls.lock().expect("close counter lock"), 1);
        let owner = ReaderCleanupOwner::from_failure(&mut failure)
            .expect("failed close reader must remain session-owned");
        let session = Session::default();
        session.own(owner);
        assert!(session.close().is_err());
        assert_eq!(*close_calls.lock().expect("close counter lock"), 2);
        assert!(session.close().is_ok());
        assert_eq!(*close_calls.lock().expect("close counter lock"), 3);
    }

    #[test]
    fn rejects_asar_root_without_retained_bytes() {
        let reader = ProviderJavaScriptReader::new(
            Box::new(super::super::asar::AsarArtifactReader::new(Vec::new())),
            None,
        );
        let mut reader = reader;
        let failure = <ProviderJavaScriptReader as rea_application::javascript::acquisition::JavaScriptReader>::verify_container(
            &mut reader,
            &"a".repeat(64),
            1,
            &Cancellation::default(),
        )
        .expect_err("ASAR verification requires retained root bytes");

        assert_eq!(failure.reason, "integrity");
    }

    struct CloseProbe {
        close_failures: std::sync::Arc<std::sync::Mutex<u8>>,
        close_calls: std::sync::Arc<std::sync::Mutex<u8>>,
    }

    impl ArtifactReader for CloseProbe {
        fn format(&self) -> &'static str {
            "directory"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<ArtifactTraversalOmission>,
        ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn open(
            &mut self,
            _entry: &ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), ReaderFailure> {
            *self.close_calls.lock().expect("close counter lock") += 1;
            let mut failures = self.close_failures.lock().expect("failure counter lock");
            if *failures > 0 {
                *failures -= 1;
                Err(ReaderFailure::new("io", "close failed"))
            } else {
                Ok(())
            }
        }
    }

    fn asar_bytes_with_filename(payload: &[u8], filename: &str) -> Vec<u8> {
        let header = serde_json::to_vec(&json!({
            "files": {
                filename: {
                    "size": payload.len(),
                    "offset": "0"
                }
            }
        }))
        .expect("ASAR header serializes");
        let padded = (header.len() + 3) & !3;
        let header_bytes = (8 + padded) as u32;
        let mut archive = Vec::new();
        for extent in [4_u32, header_bytes, header_bytes - 4, header.len() as u32] {
            archive.extend_from_slice(&extent.to_le_bytes());
        }
        archive.extend_from_slice(&header);
        archive.resize(16 + padded, 0);
        archive.extend_from_slice(payload);
        archive
    }
}
