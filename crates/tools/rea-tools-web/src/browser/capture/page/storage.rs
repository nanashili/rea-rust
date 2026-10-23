//! Redacted storage metadata: `src/browser/CdpCaptureStorage.ts` and
//! `src/browser/CdpCaptureStorageFingerprints.ts`. Values are hashed and
//! discarded; only keys (when approved) and digests are retained.
use super::super::values::{self, Record};
use super::Capture;
use super::events::records;
use crate::cdp::json_text::{canonical_json, decode_padded_base64};
use crate::cdp::urls;
use rea_core::analysis_error::AnalysisError;
use regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

const PAGE_SIZE: u64 = 1_000;
const SAFE_INTEGER: u64 = 9_007_199_254_740_991;

pub(super) struct StorageCapture {
    pub value: Value,
    pub keys_exclusion: Option<&'static str>,
}

struct Items {
    items: Vec<(String, String)>,
    complete: bool,
    exclusion: Option<&'static str>,
}

impl Items {
    fn empty() -> Self {
        Self {
            items: Vec::new(),
            complete: false,
            exclusion: None,
        }
    }
}

struct Cache {
    name: String,
    id: String,
}

/// `captureStorage`.
pub(super) fn capture_storage(
    capture: &mut Capture<'_, '_>,
    page_url: &str,
) -> Result<StorageCapture, AnalysisError> {
    let origin = urls::parse(page_url)
        .map(|url| urls::origin(&url))
        .ok_or_else(|| AnalysisError::output(super::OPERATION, "Invalid URL"))?;
    let include_keys = capture.options.include_storage_keys;
    let quota = capture.optional("Storage.getUsageAndQuota", json!({ "origin": origin }))?;
    let local = if include_keys {
        storage_items(capture, &origin, true)?
    } else {
        Items::empty()
    };
    let session = if include_keys {
        storage_items(capture, &origin, false)?
    } else {
        Items::empty()
    };
    let indexed_raw = if include_keys {
        capture.optional(
            "IndexedDB.requestDatabaseNames",
            json!({ "securityOrigin": origin }),
        )?
    } else {
        None
    };
    let indexed_values = indexed_raw
        .as_ref()
        .and_then(|raw| raw.get("databaseNames"));
    let indexed: Vec<String> = indexed_values
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let cache_raw = if include_keys {
        capture.optional(
            "CacheStorage.requestCacheNames",
            json!({ "securityOrigin": origin }),
        )?
    } else {
        None
    };
    let cache_field = cache_raw.as_ref().and_then(|raw| raw.get("caches"));
    let caches: Vec<Cache> = records(cache_field)
        .into_iter()
        .filter_map(|cache| {
            Some(Cache {
                name: values::string(cache.get("cacheName"))?.to_owned(),
                id: values::string(cache.get("cacheId"))?.to_owned(),
            })
        })
        .collect();
    let (fingerprints, fingerprints_complete) = if capture.options.include_storage_fingerprints {
        fingerprints(
            capture, &origin, page_url, &local, &session, &indexed, &caches,
        )?
    } else {
        (Vec::new(), false)
    };
    let structured_complete = indexed_raw.is_some()
        && indexed_values
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() == indexed.len())
        && cache_field
            .and_then(Value::as_array)
            .is_some_and(|items| items.len() == caches.len());
    let keys_exclusion = if !include_keys {
        None
    } else if local.exclusion == Some("provider_unavailable")
        || session.exclusion == Some("provider_unavailable")
        || indexed_raw.is_none()
        || cache_raw.is_none()
    {
        Some("provider_unavailable")
    } else if !local.complete || !session.complete || !structured_complete {
        Some("invalid_protocol_value")
    } else {
        None
    };
    let quota = quota.as_ref();
    Ok(StorageCapture {
        keys_exclusion,
        value: json!({
            "origin": origin,
            "usage_bytes": values::number(quota.and_then(|quota| quota.get("usage"))).map_or(Value::Null, values::js_number),
            "quota_bytes": values::number(quota.and_then(|quota| quota.get("quota"))).map_or(Value::Null, values::js_number),
            "local_storage_keys": local.items.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            "session_storage_keys": session.items.iter().map(|(key, _)| key).collect::<Vec<_>>(),
            "indexed_db_names": indexed,
            "cache_names": caches.iter().map(|cache| &cache.name).collect::<Vec<_>>(),
            "content_fingerprints": fingerprints,
            "fingerprint_algorithm": "sha256",
            "fingerprints_complete": fingerprints_complete && structured_complete,
            "values_redacted": true,
        }),
    })
}

fn storage_items(
    capture: &mut Capture<'_, '_>,
    origin: &str,
    local: bool,
) -> Result<Items, AnalysisError> {
    let raw = capture.optional(
        "DOMStorage.getDOMStorageItems",
        json!({ "storageId": { "securityOrigin": origin, "isLocalStorage": local } }),
    )?;
    let entries = raw
        .as_ref()
        .and_then(|raw| raw.get("entries"))
        .and_then(Value::as_array);
    let Some(entries) = entries else {
        return Ok(Items {
            items: Vec::new(),
            complete: false,
            exclusion: Some(if raw.is_none() {
                "provider_unavailable"
            } else {
                "invalid_protocol_value"
            }),
        });
    };
    let items: Vec<(String, String)> = entries
        .iter()
        .filter_map(|entry| {
            let entry = entry.as_array()?;
            Some((
                entry.first()?.as_str()?.to_owned(),
                entry.get(1)?.as_str()?.to_owned(),
            ))
        })
        .collect();
    Ok(Items {
        complete: items.len() == entries.len(),
        items,
        exclusion: None,
    })
}

/// A fingerprinted value: raw bytes, a JSON value, or JavaScript `undefined`.
enum Content {
    Bytes(Vec<u8>),
    Json(Value),
    Undefined,
}

struct Fingerprints {
    items: Vec<(String, Value)>,
    complete: bool,
}

impl Fingerprints {
    /// `addFingerprint`. JSON values are always `stableValueComplete`.
    fn add(&mut self, scope: &str, identity: &Value, value: Content, complete: bool) {
        let identity_sha = sha(canonical_json(&stable_value(identity)).as_bytes());
        let value_sha = match value {
            Content::Undefined => Value::Null,
            Content::Bytes(bytes) => json!(sha(&bytes)),
            Content::Json(value) => json!(sha(canonical_json(&stable_value(&value)).as_bytes())),
        };
        self.items.push((
            format!("{scope}:{identity_sha}"),
            json!({ "scope": scope, "identity_sha256": identity_sha, "value_sha256": value_sha, "complete": complete }),
        ));
    }
}

fn sha(bytes: &[u8]) -> String {
    super::documents::hex(&Sha256::digest(bytes))
}

/// `stableValue` over a present JSON value.
fn stable_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(stable_value).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map
                .keys()
                .filter(|key| key.as_str() != "objectId" && key.as_str() != "customPreview")
                .collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), stable_value(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// `stableValue` of a possibly absent field (`String(undefined)`).
fn stable_field(value: Option<&Value>) -> Value {
    value.map_or_else(|| json!("undefined"), stable_value)
}

#[allow(clippy::too_many_arguments)]
fn fingerprints(
    capture: &mut Capture<'_, '_>,
    origin: &str,
    cookie_url: &str,
    local: &Items,
    session: &Items,
    indexed: &[String],
    caches: &[Cache],
) -> Result<(Vec<Value>, bool), AnalysisError> {
    let mut state = Fingerprints {
        items: Vec::new(),
        complete: local.complete && session.complete,
    };
    for (scope, items) in [("local_storage", local), ("session_storage", session)] {
        for (key, value) in &items.items {
            state.add(scope, &json!(key), Content::Json(json!(value)), true);
        }
    }
    add_cookies(capture, &mut state, cookie_url)?;
    add_indexed_db(capture, &mut state, origin, indexed)?;
    add_caches(capture, &mut state, caches)?;
    state.items.sort_by(|left, right| left.0.cmp(&right.0));
    let complete = state.complete && state.items.iter().all(|(_, item)| item["complete"] == true);
    Ok((
        state.items.into_iter().map(|(_, item)| item).collect(),
        complete,
    ))
}

fn add_cookies(
    capture: &mut Capture<'_, '_>,
    state: &mut Fingerprints,
    page_url: &str,
) -> Result<(), AnalysisError> {
    capture.limitations.push(
        "Cookie fingerprints cover cookies applicable to the current main-frame URL, not every path on its origin."
            .to_owned(),
    );
    let Some(raw) = capture.optional("Network.getCookies", json!({ "urls": [page_url] }))? else {
        state.complete = false;
        return Ok(());
    };
    let Some(values_list) = raw.get("cookies").and_then(Value::as_array) else {
        state.complete = false;
        return Ok(());
    };
    let cookies = records(raw.get("cookies"));
    if cookies.len() != values_list.len() {
        state.complete = false;
    }
    for cookie in cookies {
        let fields = (
            values::string(cookie.get("name")),
            values::string(cookie.get("value")),
            values::string(cookie.get("domain")),
            values::string(cookie.get("path")),
        );
        let (Some(name), Some(value), Some(domain), Some(path)) = fields else {
            state.complete = false;
            continue;
        };
        let identity = json!({
            "domain": domain,
            "path": path,
            "name": name,
            "partition_key": cookie.get("partitionKey").cloned().unwrap_or(Value::Null),
        });
        state.add("cookie", &identity, Content::Json(json!(value)), true);
    }
    Ok(())
}

fn add_indexed_db(
    capture: &mut Capture<'_, '_>,
    state: &mut Fingerprints,
    origin: &str,
    names: &[String],
) -> Result<(), AnalysisError> {
    for database_name in names {
        let raw = capture.optional(
            "IndexedDB.requestDatabase",
            json!({ "securityOrigin": origin, "databaseName": database_name }),
        )?;
        let database = values::record(
            raw.as_ref()
                .and_then(|raw| raw.get("databaseWithObjectStores")),
        );
        let Some(database) = database else {
            state.complete = false;
            continue;
        };
        if values::string(database.get("name")) != Some(database_name.as_str()) {
            state.complete = false;
            continue;
        }
        let Some(declared) = database.get("objectStores").and_then(Value::as_array) else {
            state.complete = false;
            continue;
        };
        let stores = records(database.get("objectStores"));
        if stores.len() != declared.len() {
            state.complete = false;
        }
        let schema: Vec<Value> = stores.iter().map(|store| store_schema(store)).collect();
        let complete =
            stores.len() == declared.len() && stores.iter().all(|store| store_complete(store));
        state.add(
            "indexed_db_schema",
            &json!(database_name),
            Content::Json(Value::Array(schema)),
            complete,
        );
        let store_names: Vec<Option<String>> = stores
            .iter()
            .map(|store| values::string(store.get("name")).map(str::to_owned))
            .collect();
        for store_name in store_names {
            let Some(store_name) = store_name else {
                state.complete = false;
                continue;
            };
            add_records(capture, state, origin, database_name, &store_name)?;
        }
    }
    Ok(())
}

fn store_schema(store: &Record) -> Value {
    json!({
        "name": values::string(store.get("name")),
        "key_path": stable_field(store.get("keyPath")),
        "auto_increment": store.get("autoIncrement") == Some(&Value::Bool(true)),
        "indexes": records(store.get("indexes")).into_iter().map(|index| json!({
            "name": values::string(index.get("name")),
            "key_path": stable_field(index.get("keyPath")),
            "unique": index.get("unique") == Some(&Value::Bool(true)),
            "multi_entry": index.get("multiEntry") == Some(&Value::Bool(true)),
        })).collect::<Vec<_>>(),
    })
}

fn store_complete(store: &Record) -> bool {
    let indexes = store.get("indexes").and_then(Value::as_array);
    values::string(store.get("name")).is_some()
        && key_path_complete(store.get("keyPath"))
        && store.get("autoIncrement").is_some_and(Value::is_boolean)
        && indexes.is_some_and(|items| records(store.get("indexes")).len() == items.len())
        && records(store.get("indexes")).iter().all(|index| {
            values::string(index.get("name")).is_some()
                && key_path_complete(index.get("keyPath"))
                && index.get("unique").is_some_and(Value::is_boolean)
                && index.get("multiEntry").is_some_and(Value::is_boolean)
        })
}

fn key_path_complete(value: Option<&Value>) -> bool {
    let Some(key_path) = values::record(value) else {
        return false;
    };
    match values::string(key_path.get("type")) {
        Some("null") => true,
        Some("string") => key_path.get("string").is_some_and(Value::is_string),
        Some("array") => key_path
            .get("array")
            .and_then(Value::as_array)
            .is_some_and(|keys| keys.iter().all(Value::is_string)),
        _ => false,
    }
}

fn add_records(
    capture: &mut Capture<'_, '_>,
    state: &mut Fingerprints,
    origin: &str,
    database: &str,
    store: &str,
) -> Result<(), AnalysisError> {
    let mut skip: u64 = 0;
    loop {
        let raw = capture.optional(
            "IndexedDB.requestData",
            json!({
                "securityOrigin": origin,
                "databaseName": database,
                "objectStoreName": store,
                "skipCount": skip,
                "pageSize": PAGE_SIZE,
            }),
        )?;
        let Some(result) = raw.as_ref().and_then(Value::as_object) else {
            state.complete = false;
            return Ok(());
        };
        let (Some(declared), Some(has_more)) = (
            result
                .get("objectStoreDataEntries")
                .and_then(Value::as_array),
            result.get("hasMore").and_then(Value::as_bool),
        ) else {
            state.complete = false;
            return Ok(());
        };
        let entries = records(result.get("objectStoreDataEntries"));
        if entries.len() != declared.len() {
            state.complete = false;
        }
        for entry in &entries {
            let identity = json!({
                "database": database,
                "store": store,
                "key": stable_field(entry.get("key")),
                "primaryKey": stable_field(entry.get("primaryKey")),
            });
            let value = entry
                .get("value")
                .map_or(Content::Undefined, |value| Content::Json(value.clone()));
            let complete = remote_object_complete(entry.get("key"))
                && remote_object_complete(entry.get("primaryKey"))
                && remote_object_complete(entry.get("value"));
            state.add("indexed_db_record", &identity, value, complete);
        }
        if !has_more {
            return Ok(());
        }
        let count = entries.len() as u64;
        if count == 0 || skip > SAFE_INTEGER - count {
            state.complete = false;
            return Ok(());
        }
        skip += count;
    }
}

fn add_caches(
    capture: &mut Capture<'_, '_>,
    state: &mut Fingerprints,
    caches: &[Cache],
) -> Result<(), AnalysisError> {
    for cache in caches {
        let mut skip: u64 = 0;
        let mut return_count: Option<u64> = None;
        while return_count.is_none_or(|count| skip < count) {
            let raw = capture.optional(
                "CacheStorage.requestEntries",
                json!({ "cacheId": cache.id, "skipCount": skip, "pageSize": PAGE_SIZE }),
            )?;
            let Some(result) = raw.as_ref().and_then(Value::as_object) else {
                state.complete = false;
                break;
            };
            let declared = result.get("cacheDataEntries").and_then(Value::as_array);
            let count_value = values::number(result.get("returnCount")).filter(|count| {
                count.fract() == 0.0 && *count >= 0.0 && *count <= SAFE_INTEGER as f64
            });
            let (Some(declared), Some(total)) = (declared, count_value) else {
                state.complete = false;
                break;
            };
            let entries: Vec<Record> = records(result.get("cacheDataEntries"))
                .into_iter()
                .cloned()
                .collect();
            if entries.len() != declared.len() {
                state.complete = false;
            }
            for entry in &entries {
                add_cache_entry(capture, state, cache, entry)?;
            }
            let total = total as u64;
            return_count = Some(total);
            let count = entries.len() as u64;
            if skip + count >= total {
                break;
            }
            if count == 0 || skip > SAFE_INTEGER - count {
                state.complete = false;
                break;
            }
            skip += count;
        }
    }
    Ok(())
}

fn add_cache_entry(
    capture: &mut Capture<'_, '_>,
    state: &mut Fingerprints,
    cache: &Cache,
    entry: &Record,
) -> Result<(), AnalysisError> {
    let (Some(url), Some(method)) = (
        values::string(entry.get("requestURL")),
        values::string(entry.get("requestMethod")),
    ) else {
        state.complete = false;
        return Ok(());
    };
    let Some(declared) = entry.get("requestHeaders").and_then(Value::as_array) else {
        state.complete = false;
        return Ok(());
    };
    let header_records = records(entry.get("requestHeaders"));
    let headers: Vec<Value> = header_records
        .iter()
        .filter_map(|header| {
            Some(json!({
                "name": values::string(header.get("name"))?,
                "value": values::string(header.get("value"))?,
            }))
        })
        .collect();
    if header_records.len() != declared.len() || headers.len() != header_records.len() {
        state.complete = false;
        return Ok(());
    }
    let raw = capture.optional(
        "CacheStorage.requestCachedResponse",
        json!({ "cacheId": cache.id, "requestURL": url, "requestHeaders": headers }),
    )?;
    let body = values::string(
        values::record(raw.as_ref().and_then(|raw| raw.get("response")))
            .and_then(|response| response.get("body")),
    );
    let decoded = body.and_then(decode_padded_base64);
    let complete = decoded.is_some();
    if !complete {
        state.complete = false;
    }
    let identity = json!({ "cache": cache.name, "requestURL": url, "requestMethod": method, "requestHeaders": headers });
    state.add(
        "cache_entry",
        &identity,
        decoded.map_or(Content::Undefined, Content::Bytes),
        complete,
    );
    Ok(())
}

/// `remoteObjectComplete`.
fn remote_object_complete(value: Option<&Value>) -> bool {
    static BIGINT: OnceLock<Regex> = OnceLock::new();
    let Some(record) = values::record(value) else {
        return false;
    };
    if record.contains_key("objectId")
        || record.contains_key("preview")
        || record.contains_key("customPreview")
    {
        return false;
    }
    let has_value = record.contains_key("value");
    let unserializable = record.get("unserializableValue");
    match values::string(record.get("type")) {
        Some("undefined") => !has_value && unserializable.is_none(),
        Some("string") => {
            record.get("value").is_some_and(Value::is_string) && unserializable.is_none()
        }
        Some("boolean") => {
            record.get("value").is_some_and(Value::is_boolean) && unserializable.is_none()
        }
        Some("number") => match unserializable {
            None => values::number(record.get("value")).is_some(),
            Some(text) => {
                !has_value
                    && text
                        .as_str()
                        .is_some_and(|text| ["-0", "NaN", "Infinity", "-Infinity"].contains(&text))
            }
        },
        Some("bigint") => {
            !has_value
                && unserializable.and_then(Value::as_str).is_some_and(|text| {
                    BIGINT
                        .get_or_init(|| Regex::new(r"^-?[0-9]+n$").expect("bigint"))
                        .is_match(text)
                })
        }
        Some("object") => {
            unserializable.is_none()
                && if values::string(record.get("subtype")) == Some("null") {
                    record.get("value") == Some(&Value::Null)
                } else {
                    record
                        .get("value")
                        .is_some_and(|value| value.is_object() || value.is_array())
                }
        }
        _ => false,
    }
}
