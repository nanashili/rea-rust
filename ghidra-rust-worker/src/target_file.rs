use std::fs::File;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};

use crate::protocol::MAX_TARGET_BYTES;

pub fn verify(path: &Path, expected_sha256: &str) -> Result<()> {
    let (file, length) = open(path)?;
    read_chunks(file, length, expected_sha256, |_| Ok(()))
}

pub fn read(path: &Path, expected_sha256: &str) -> Result<Vec<u8>> {
    let (file, length) = open(path)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .context("Reserve the admitted target image")?;
    read_chunks(file, length, expected_sha256, |chunk| {
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(bytes)
}

fn open(path: &Path) -> Result<(File, usize)> {
    let file = File::open(path).context("Open the target image")?;
    let metadata = file.metadata().context("Read target metadata")?;
    ensure!(metadata.is_file(), "Target must be a regular file");
    let length = usize::try_from(metadata.len()).context("Target size is not representable")?;
    ensure!(
        length <= MAX_TARGET_BYTES,
        "Target exceeds the 256 MiB input limit"
    );
    Ok((file, length))
}

fn read_chunks(
    mut file: File,
    expected_length: usize,
    expected_sha256: &str,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<()> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut length = 0_usize;

    loop {
        let count = file.read(&mut buffer).context("Read the admitted target")?;
        if count == 0 {
            break;
        }
        length = length.checked_add(count).context("Target size overflow")?;
        ensure!(
            length <= expected_length,
            "Target size changed while reading"
        );
        hash.update(&buffer[..count]);
        consume(&buffer[..count])?;
    }

    ensure!(
        length == expected_length,
        "Target size changed while reading"
    );
    ensure!(
        format!("{:x}", hash.finalize()) == expected_sha256,
        "Target digest changed"
    );
    Ok(())
}
