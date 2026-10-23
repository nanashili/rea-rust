//! `src/browser/CdpScreenshot.ts` (`captureCdpScreenshot`) with
//! `createWebScreenshotArtifact`, `decodeCanonicalBase64`
//! (`src/domain/webScreenshot.ts`) and `readPngHeaderDimensions`
//! (`src/domain/pngHeader.ts`).
use super::completeness::Completeness;
use super::connection::{Connection, TargetFacts, foreign};
use super::values::{self, Event};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::Progress;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(super) const OPERATION: &str = "capture_web_screenshot";
const PHASE: &str = "browser_observation";

struct Navigation {
    changed: bool,
    left_scope: bool,
    url: Option<String>,
    loader_id: Option<String>,
}

pub(super) fn capture(
    connection: &mut Connection<'_>,
    facts: &TargetFacts<'_>,
    progress: &Progress,
) -> Result<Value, AnalysisError> {
    let origins = &facts.origins;
    progress.report(PHASE, "Authorizing current screenshot frame");
    connection.send("Page.enable", json!({}))?;
    let before = connection.send("Page.getFrameTree", json!({}))?;
    connection.discard()?;
    let before_url =
        values::main_frame_url(&before).map_err(|()| foreign(OPERATION, "protocol_error"))?;
    let authorized = values::allowed_sanitized_url(before_url.as_deref(), origins);
    let main_frame = values::capture_frames(&before, origins, Some(1), None)
        .into_iter()
        .next();
    let (Some(authorized), Some(main_frame)) = (authorized, main_frame) else {
        return Err(foreign(OPERATION, "target_not_allowed"));
    };
    let initial_frame =
        values::record(values::frame_tree_root(&before).and_then(|tree| tree.get("frame")));
    let mut navigation = Navigation {
        changed: false,
        left_scope: false,
        url: before_url.clone(),
        loader_id: values::string(initial_frame.and_then(|frame| frame.get("loaderId")))
            .map(str::to_owned),
    };
    let session_id = connection.session_id().map(str::to_owned);
    let listen = |connection: &mut Connection<'_>,
                  navigation: &mut Navigation|
     -> Result<(), AnalysisError> {
        for event in connection.drain()? {
            if event.session_id == session_id {
                observe_navigation(&event, &main_frame.frame_id, origins, navigation);
            }
        }
        Ok(())
    };
    let shot = connection.send(
        "Page.captureScreenshot",
        json!({ "format": "png", "fromSurface": true, "captureBeyondViewport": false }),
    )?;
    listen(connection, &mut navigation)?;
    let after = connection.send("Page.getFrameTree", json!({}))?;
    listen(connection, &mut navigation)?;
    let bytes = values::string(shot.get("data"))
        .and_then(decode_canonical_base64)
        .ok_or_else(|| foreign(OPERATION, "protocol_error"))?;
    let (width, height) =
        png_dimensions(&bytes).ok_or_else(|| foreign(OPERATION, "protocol_error"))?;
    if navigation.left_scope {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }
    let after_url =
        values::main_frame_url(&after).map_err(|()| foreign(OPERATION, "protocol_error"))?;
    if navigation.changed
        || after_url != before_url
        || values::allowed_sanitized_url(after_url.as_deref(), origins).is_none()
    {
        return Err(foreign(OPERATION, "target_changed"));
    }
    progress.report(PHASE, "Screenshot capture complete");
    let sha256 = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(json!({
        "browser": facts.discovery.version,
        "target": {
            "target_id": facts.target.id,
            "url": authorized.url,
            "origin": authorized.origin.unwrap_or_default(),
        },
        "captured_at": super::iso_now(),
        "viewport": { "width": width, "height": height },
        "artifact": {
            "sha256": sha256,
            "bytes": bytes.len(),
            "media_type": "image/png",
            "data_base64": STANDARD.encode(&bytes),
        },
        "completeness": Completeness::default().snapshot(),
        "limitations": [
            "The screenshot contains the visible viewport, including on-screen content.",
            "REA does not scroll, evaluate JavaScript, or capture beyond the current viewport.",
        ],
    }))
}

/// `observeScreenshotNavigation`.
fn observe_navigation(
    event: &Event,
    main_frame_id: &str,
    origins: &BTreeSet<String>,
    state: &mut Navigation,
) {
    if !values::is_main_frame_navigation(event, main_frame_id) {
        return;
    }
    let Some(params) = event.params.as_object() else {
        return;
    };
    let frame = if event.method == "Page.frameNavigated" {
        values::record(params.get("frame"))
    } else {
        Some(params)
    };
    let frame_url = values::string(frame.and_then(|frame| frame.get("url")));
    if event.method == "Page.frameNavigated"
        && state
            .loader_id
            .as_deref()
            .is_some_and(|loader| !loader.is_empty())
        && values::string(frame.and_then(|frame| frame.get("loaderId")))
            == state.loader_id.as_deref()
        && frame_url == state.url.as_deref()
    {
        return;
    }
    state.changed = true;
    if values::allowed_sanitized_url(frame_url, origins).is_none() {
        state.left_scope = true;
    }
}

/// `decodeCanonicalBase64`.
fn decode_canonical_base64(value: &str) -> Option<Vec<u8>> {
    if value.is_empty() || value.len() % 4 != 0 {
        return None;
    }
    let decoded = STANDARD.decode(value).ok()?;
    (STANDARD.encode(&decoded) == value).then_some(decoded)
}

/// `readPngHeaderDimensions`.
fn png_dimensions(bytes: &[u8]) -> Option<(u32, u32)> {
    const SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];
    if bytes.len() < 24
        || bytes[..8] != SIGNATURE
        || read_u32(bytes, 8) != 13
        || &bytes[12..16] != b"IHDR"
    {
        return None;
    }
    let (width, height) = (read_u32(bytes, 16), read_u32(bytes, 20));
    (width != 0 && height != 0 && width <= 0x7fff_ffff && height <= 0x7fff_ffff)
        .then_some((width, height))
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}
