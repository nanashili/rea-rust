//! Structural re-validation ported from the Zod `superRefine` checks.
//!
//! Compatibility owners: `src/domain/native/binaryLayout.ts`
//! (`binaryLayoutSchema.superRefine`), `src/domain/native/recordedCrash.ts`
//! (`recordedCrashSchema.superRefine`) and
//! `src/domain/native/recordedCrashNoteCoverage.ts`.
//!
//! A real bridge reply that is structurally present but semantically
//! inconsistent must fail here with the same first-issue message the Zod
//! refinement reports, since both services re-parse the reply and the first
//! refinement issue becomes the user-visible `AnalysisOutputError` reason.
//! Only the first failing message is returned, matching
//! `error.issues[0]?.message`.
use serde_json::Value;

// ---- shared accessors -------------------------------------------------------

fn hex(value: &Value) -> Option<u128> {
    let text = value.as_str()?;
    let digits = text.strip_prefix("0x")?;
    u128::from_str_radix(digits, 16).ok()
}

fn hex_at(value: &Value, key: &str) -> Option<u128> {
    hex(value.get(key)?)
}

fn range_offset(range: &Value) -> Option<u128> {
    hex(range.get("offset")?)
}

fn range_bytes(range: &Value) -> Option<u128> {
    hex(range.get("bytes")?)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn uint(value: &Value, key: &str) -> Option<u64> {
    value.get(key)?.as_u64()
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key)?.as_str()
}

/// Decoded byte length of a canonical base64 string (as in the Zod checks).
fn decoded_len(raw: &str) -> i128 {
    let pad = if raw.ends_with("==") {
        2
    } else if raw.ends_with('=') {
        1
    } else {
        0
    };
    (raw.len() as i128 / 4) * 3 - pad
}

// ---- binary layout ----------------------------------------------------------

/// `binaryLayoutSchema.superRefine`. Returns the first issue message.
pub fn layout_issues(value: &Value) -> Option<String> {
    let size = uint(value.get("artifact")?, "bytes")? as u128;

    // `check(offset, length)` → range lies within the artifact.
    let check = |offset: u128, length: u128| -> bool { offset <= size && length <= size - offset };
    let check_location = |range: &Value| -> bool {
        match (range_offset(range), range_bytes(range)) {
            (Some(offset), Some(bytes)) => check(offset, bytes),
            _ => false,
        }
    };
    let check_name = |name: &Value| -> bool {
        match name.get("location") {
            Some(Value::Null) | None => true,
            Some(location) => check_location(location),
        }
    };

    // Entry-point meaning.
    let image_type = str_field(value, "image_type").unwrap_or_default();
    let entry = value.get("entry_point")?;
    let reported_value = str_field(entry, "reported_value").unwrap_or_default();
    let expected_entry = if image_type == "ET_REL" {
        "not-applicable"
    } else if reported_value == "0x0" {
        "absent"
    } else {
        "linked-virtual-address"
    };
    if str_field(entry, "meaning") != Some(expected_entry) {
        return Some(
            "Entry meaning must distinguish zero/unused fields from an actual linked address."
                .to_owned(),
        );
    }

    let sections = array(value, "sections");
    for (index, section) in sections.iter().enumerate() {
        let section_type = section.get("type");
        let is_symtab = matches!(
            section_type.and_then(Value::as_str),
            Some("SHT_SYMTAB") | Some("SHT_DYNSYM")
        );
        if is_symtab {
            let link = uint(section, "link");
            let linked_type = link
                .and_then(|link| sections.get(link as usize))
                .and_then(|linked| str_field(linked, "type"));
            if linked_type != Some("SHT_STRTAB") {
                return Some(
                    "Symbol tables must link to an existing string-table section.".to_owned(),
                );
            }
        }
        if uint(section, "index") != Some(index as u64) {
            return Some(
                "Complete section order must preserve original producer indices.".to_owned(),
            );
        }
        if !check_location(section.get("header_location")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
        if !check_name(section.get("name")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
        if str_field(section, "file_backing") == Some("file") {
            let offset = hex_at(section, "offset")?;
            let length = hex_at(section, "size")?;
            if !check(offset, length) {
                return Some(
                    "Reported file-backed range lies outside the selected artifact.".to_owned(),
                );
            }
        }
    }

    let segments = array(value, "segments");
    for (index, segment) in segments.iter().enumerate() {
        if uint(segment, "index") != Some(index as u64) {
            return Some(
                "Complete segment order must preserve original producer indices.".to_owned(),
            );
        }
        if !check_location(segment.get("header_location")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
        let segment_type = str_field(segment, "type");
        let file_size = hex_at(segment, "file_size")?;
        let has_file_bytes = segment_type != Some("PT_NULL") && file_size != 0;
        let expected_backing = if has_file_bytes { "file" } else { "none" };
        if str_field(segment, "file_backing") != Some(expected_backing) {
            return Some(
                "File backing must follow the reported segment type and file size.".to_owned(),
            );
        }
        let is_null = segment_type == Some("PT_NULL");
        let permissions_null = matches!(segment.get("permissions"), Some(Value::Null) | None);
        if is_null != permissions_null {
            return Some(
                "Unused PT_NULL flags have no permission meaning; other segment flags retain their interpretation."
                    .to_owned(),
            );
        }
        if has_file_bytes {
            let offset = hex_at(segment, "offset")?;
            if !check(offset, file_size) {
                return Some(
                    "Reported file-backed range lies outside the selected artifact.".to_owned(),
                );
            }
        }
    }

    for symbol in array(value, "symbols") {
        if !check_location(symbol.get("location")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
        if !check_name(symbol.get("name")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
    }

    for relocation in array(value, "relocations") {
        if !check_location(relocation.get("location")?) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
    }

    if let Some(message) = relocation_references(value, sections) {
        return Some(message);
    }
    if let Some(message) = packed_relative_tables(value, sections, &check_location) {
        return Some(message);
    }

    for facet in ["needed_libraries", "interpreters"] {
        if let Some(linkage) = value.get("linkage") {
            for reported in array(linkage, facet) {
                if !check_name(reported) {
                    return Some(
                        "Reported file-backed range lies outside the selected artifact.".to_owned(),
                    );
                }
            }
        }
    }

    None
}

fn relocation_references(value: &Value, sections: &[Value]) -> Option<String> {
    let image_type = str_field(value, "image_type").unwrap_or_default();
    let symbols: std::collections::HashSet<String> = array(value, "symbols")
        .iter()
        .filter_map(|symbol| {
            Some(format!(
                "{}:{}",
                uint(symbol, "table_index")?,
                uint(symbol, "entry_index")?
            ))
        })
        .collect();

    for relocation in array(value, "relocations") {
        let owner_index = uint(relocation, "section_index");
        let owner = owner_index.and_then(|index| sections.get(index as usize));
        let target = relocation.get("target");
        let reported_offset = str_field(relocation, "reported_offset");
        let owner_info = owner.and_then(|owner| uint(owner, "info"));

        let target_matches = if image_type == "ET_REL" {
            match target.and_then(|t| str_field(t, "kind")) {
                Some("section-offset") => {
                    let target_section = target.and_then(|t| uint(t, "section_index"));
                    let section = target_section.and_then(|index| sections.get(index as usize));
                    target_section.is_some()
                        && target_section != Some(0)
                        && target_section == owner_info
                        && section.is_some()
                        && section.and_then(|s| str_field(s, "type")) != Some("SHT_NULL")
                        && target.and_then(|t| str_field(t, "offset")) == reported_offset
                }
                Some("unknown-section") => {
                    let reported_section = target.and_then(|t| uint(t, "reported_section_index"));
                    let unknown_reason = target.and_then(|t| str_field(t, "unknown_reason"));
                    let base = reported_section == owner_info
                        && target.and_then(|t| str_field(t, "offset")) == reported_offset;
                    if !base {
                        false
                    } else if reported_section == Some(0) {
                        unknown_reason == Some("undefined-section-reference")
                    } else {
                        let section =
                            reported_section.and_then(|index| sections.get(index as usize));
                        section.and_then(|s| str_field(s, "type")) == Some("SHT_NULL")
                            && unknown_reason == Some("inactive-section-header")
                    }
                }
                _ => false,
            }
        } else {
            target.and_then(|t| str_field(t, "kind")) == Some("linked-virtual-address")
                && target.and_then(|t| str_field(t, "address")) == reported_offset
        };

        if !target_matches {
            return Some(
                "Relocation target must preserve its reported offset and owner reference; SHN_UNDEF and inactive headers remain unknown rather than resolved sections."
                    .to_owned(),
            );
        }

        let symbol_table_index = uint(relocation, "symbol_table_index");
        let table = symbol_table_index.and_then(|index| sections.get(index as usize));
        let table_type = table.and_then(|t| str_field(t, "type"));
        let table_exists = symbol_table_index != Some(0)
            && matches!(table_type, Some("SHT_SYMTAB") | Some("SHT_DYNSYM"));

        let symbol_index = uint(relocation, "symbol_index");
        let positive_reference_exists = table_exists
            && table
                .and_then(|t| hex_at(t, "entry_size"))
                .map(|entry| entry >= 24)
                .unwrap_or(false)
            && {
                let size = table.and_then(|t| hex_at(t, "size")).unwrap_or(0);
                let entry = table.and_then(|t| hex_at(t, "entry_size")).unwrap_or(1);
                let count = if entry == 0 { 0 } else { size / entry };
                (symbol_index.unwrap_or(0) as u128) < count
            }
            && symbols.contains(&format!(
                "{}:{}",
                symbol_table_index.unwrap_or(0),
                symbol_index.unwrap_or(0)
            ));

        let owner_type = owner.and_then(|o| str_field(o, "type"));
        let owner_link = owner.and_then(|o| uint(o, "link"));
        let expected_meaning = if symbol_index == Some(0) {
            "zero-symbol-value"
        } else {
            "symbol-table-entry"
        };
        if (owner_type != Some("SHT_REL") && owner_type != Some("SHT_RELA"))
            || owner_link != symbol_table_index
            || (symbol_table_index != Some(0) && !table_exists)
            || (symbol_index != Some(0) && !positive_reference_exists)
            || str_field(relocation, "symbol_reference_meaning") != Some(expected_meaning)
        {
            return Some(
                "Relocation must preserve its REL/RELA owner and resolve positive symbol indices through the linked symbol table; index zero uses a zero symbol value."
                    .to_owned(),
            );
        }
    }
    None
}

fn packed_relative_tables(
    value: &Value,
    sections: &[Value],
    check_location: &dyn Fn(&Value) -> bool,
) -> Option<String> {
    for table in array(value, "packed_relative_relocations") {
        let location = table.get("location")?;
        if !check_location(location) {
            return Some(
                "Reported file-backed range lies outside the selected artifact.".to_owned(),
            );
        }
        let encoded = str_field(table, "encoded_bytes_base64").unwrap_or_default();
        let encoded_bytes = decoded_len(encoded);
        let location_bytes = range_bytes(location).map(|bytes| bytes as i128);
        if encoded_bytes < 0 || Some(encoded_bytes) != location_bytes {
            return Some(
                "Complete packed table bytes must match its original file range.".to_owned(),
            );
        }
        let section_index = uint(table, "section_index");
        let section = section_index.and_then(|index| sections.get(index as usize));
        let offset_matches =
            section.and_then(|s| s.get("offset").and_then(hex_opt)) == range_offset(location);
        let size_matches =
            section.and_then(|s| s.get("size").and_then(hex_opt)) == range_bytes(location);
        if section.and_then(|s| str_field(s, "type")) != Some("SHT_RELR")
            || !offset_matches
            || !size_matches
        {
            return Some(
                "Packed relative evidence must retain its original RELR section identity and range."
                    .to_owned(),
            );
        }
        for (decoded, entry) in array(table, "entries").iter().enumerate() {
            if uint(entry, "decoded_index") != Some(decoded as u64) {
                return Some("Decoded offsets must preserve upstream iterator order.".to_owned());
            }
        }
    }
    None
}

fn hex_opt(value: &Value) -> Option<u128> {
    hex(value)
}

// ---- recorded crash ---------------------------------------------------------

const LINUX_CORE_OWNER_BASE64: &str = "Q09SRQA=";

/// `recordedCrashSchema.superRefine`. Returns the first issue message.
pub fn recorded_crash_issues(value: &Value) -> Option<String> {
    let artifact_bytes = uint(value.get("artifact")?, "bytes")? as u128;
    let within = |range: &Value, start: u128, end: u128| -> bool {
        match (range_offset(range), range_bytes(range)) {
            (Some(offset), Some(bytes)) => {
                offset >= start && offset <= end && bytes <= end - offset
            }
            _ => false,
        }
    };
    let within_artifact = |range: &Value| within(range, 0, artifact_bytes);

    let segments = array(value, "segments");
    let notes = array(value, "notes");
    let padding = array(value, "note_padding");

    // Note coverage (`recordedNoteCoverageIssues`), issues emitted in order.
    if let Some(message) = note_coverage(segments, notes, padding) {
        return Some(message);
    }

    for (position, segment) in segments.iter().enumerate() {
        if uint(segment, "index") != Some(position as u64)
            || !within_artifact(segment.get("header_location")?)
        {
            return Some("Invalid original segment identity or header range.".to_owned());
        }
        if str_field(segment, "file_backing") == Some("file") {
            let offset = hex_at(segment, "offset")?;
            let bytes = hex_at(segment, "file_size")?;
            if !(offset <= artifact_bytes && bytes <= artifact_bytes - offset) {
                return Some("Recorded segment exceeds artifact bytes.".to_owned());
            }
        }
        if str_field(segment, "type") == Some("PT_LOAD")
            && hex_at(segment, "file_size")? > hex_at(segment, "memory_size")?
        {
            return Some("Recorded PT_LOAD file size exceeds memory size.".to_owned());
        }
    }

    for (position, note) in notes.iter().enumerate() {
        let segment = uint(note, "segment_index").and_then(|index| segments.get(index as usize));
        if uint(note, "index") != Some(position as u64)
            || segment.and_then(|s| str_field(s, "type")) != Some("PT_NOTE")
        {
            return Some("Invalid original note identity or segment reference.".to_owned());
        }
        let segment = segment.expect("checked PT_NOTE above");
        let owner_location = note.get("owner_location")?;
        let descriptor_location = note.get("descriptor_location")?;
        let owner_decoded = decoded_len(str_field(note, "owner_bytes_base64").unwrap_or_default());
        let descriptor_decoded =
            decoded_len(str_field(note, "descriptor_bytes_base64").unwrap_or_default());
        if owner_decoded != range_bytes(owner_location)? as i128
            || descriptor_decoded != range_bytes(descriptor_location)? as i128
        {
            return Some("Raw note lengths differ from their source ranges.".to_owned());
        }
        let segment_start = hex_at(segment, "offset")?;
        let segment_end = segment_start + hex_at(segment, "file_size")?;
        let location = note.get("location")?;
        let location_offset = range_offset(location)?;
        let location_end = location_offset + range_bytes(location)?;
        if !within(location, segment_start, segment_end)
            || !within(owner_location, location_offset, location_end)
            || !within(descriptor_location, location_offset, location_end)
        {
            return Some("Note source ranges exceed their recorded segment.".to_owned());
        }
    }

    for item in padding {
        let segment = uint(item, "segment_index").and_then(|index| segments.get(index as usize));
        let valid = match segment {
            Some(segment) if str_field(segment, "type") == Some("PT_NOTE") => {
                let start = hex_at(segment, "offset").unwrap_or(0);
                let end = start + hex_at(segment, "file_size").unwrap_or(0);
                within(item.get("location").unwrap_or(&Value::Null), start, end)
            }
            _ => false,
        };
        if !valid {
            return Some("Invalid recorded note padding range.".to_owned());
        }
    }

    // Exactly one interpretation per supported raw note.
    let threads = array(value, "threads");
    let signals = array(value, "signals");
    for (kind, rows) in [("NT_PRSTATUS", threads), ("NT_SIGINFO", signals)] {
        let matching = notes
            .iter()
            .filter(|note| {
                str_field(note, "type") == Some(kind)
                    && str_field(note, "owner_bytes_base64") == Some(LINUX_CORE_OWNER_BASE64)
            })
            .count();
        let unique: std::collections::HashSet<u64> = rows
            .iter()
            .filter_map(|row| uint(row, "note_index"))
            .collect();
        if rows.len() != matching || unique.len() != rows.len() {
            return Some(
                "Each supported raw note requires exactly one corresponding interpretation."
                    .to_owned(),
            );
        }
    }

    let architecture = str_field(value, "architecture").unwrap_or_default();
    let (registers, register_bytes): (&[&str], u128) = match architecture {
        "x86_64-little-endian" => (AMD64_REGISTERS, 8),
        "aarch64-little-endian" => (AARCH64_REGISTERS, 8),
        _ => (&[], 8),
    };
    let register_set: std::collections::HashSet<&str> = registers.iter().copied().collect();

    for thread in threads {
        let note = uint(thread, "note_index").and_then(|index| notes.get(index as usize));
        let note_ok = note.map(|note| {
            str_field(note, "type") == Some("NT_PRSTATUS")
                && note.get("owner_display").and_then(Value::as_str) == Some("CORE")
                && str_field(note, "owner_bytes_base64") == Some(LINUX_CORE_OWNER_BASE64)
        }) == Some(true);
        if !note_ok {
            return Some("Thread references a different note kind.".to_owned());
        }
        let note = note.expect("checked above");
        let thread_registers = array(thread, "registers");
        let names: std::collections::HashSet<&str> = thread_registers
            .iter()
            .filter_map(|register| str_field(register, "name"))
            .collect();
        let all_known = thread_registers.iter().all(|register| {
            str_field(register, "name").is_some_and(|name| register_set.contains(name))
        });
        if thread_registers.len() != registers.len()
            || !all_known
            || names.len() != thread_registers.len()
        {
            return Some(
                "Each recorded thread requires every supported register exactly once.".to_owned(),
            );
        }
        let descriptor = note.get("descriptor_location")?;
        let descriptor_offset = range_offset(descriptor)?;
        let descriptor_end = descriptor_offset + range_bytes(descriptor)?;
        for register in thread_registers {
            let location = register.get("location")?;
            if range_bytes(location)? != register_bytes
                || !within(location, descriptor_offset, descriptor_end)
            {
                return Some("Register source exceeds its descriptor.".to_owned());
            }
        }
    }

    for signal in signals {
        let note = uint(signal, "note_index").and_then(|index| notes.get(index as usize));
        let note_ok = note.map(|note| {
            str_field(note, "type") == Some("NT_SIGINFO")
                && note.get("owner_display").and_then(Value::as_str) == Some("CORE")
                && str_field(note, "owner_bytes_base64") == Some(LINUX_CORE_OWNER_BASE64)
        }) == Some(true);
        if !note_ok {
            return Some("Signal references a different note kind.".to_owned());
        }
        let number = signal.get("number").and_then(Value::as_i64);
        let code = signal.get("code").and_then(Value::as_i64);
        let fault = signal.get("fault_address");
        let has_fault = !matches!(fault, Some(Value::Null) | None);
        let known = number == Some(11) && (code == Some(1) || code == Some(2));
        let meaning = str_field(signal, "fault_address_meaning");
        if known != has_fault || has_fault != (meaning == Some("recorded-sigsegv-address")) {
            return Some("Signal union meaning does not match recorded SIGSEGV code.".to_owned());
        }
    }

    if value.get("debugger").and_then(|d| str_field(d, "status")) == Some("available") {
        for map in array(value.get("debugger")?, "maps") {
            let start = hex_at(map, "start")?;
            let end = hex_at(map, "end")?;
            if end < start {
                return Some("Debugger mapping end precedes its start.".to_owned());
            }
            let reported_flags = uint(map, "reported_flags")?;
            match map.get("permissions") {
                Some(Value::Object(permissions)) => {
                    let bit =
                        |value: Option<&Value>| value.and_then(Value::as_bool).unwrap_or(false);
                    if bit(permissions.get("read")) != ((reported_flags & 4) != 0)
                        || bit(permissions.get("write")) != ((reported_flags & 2) != 0)
                        || bit(permissions.get("execute")) != ((reported_flags & 1) != 0)
                    {
                        return Some("Mapping permissions differ from reported flags.".to_owned());
                    }
                }
                _ => {}
            }
            let permissions_null = matches!(map.get("permissions"), Some(Value::Null) | None);
            if (reported_flags == 0 || reported_flags > 7) != permissions_null {
                return Some(
                    "Unreported or unfamiliar map flags require unknown permissions.".to_owned(),
                );
            }
        }
    }

    None
}

fn align(size: u128) -> u128 {
    ((size + 3) / 4) * 4
}

/// `recordedNoteCoverageIssues`: first offending message in emission order.
fn note_coverage(segments: &[Value], notes: &[Value], padding: &[Value]) -> Option<String> {
    // `all` and per-segment collections, built in iteration order.
    let mut by_segment: std::collections::HashMap<u64, Vec<(u128, u128)>> =
        std::collections::HashMap::new();
    let mut all: Vec<(u128, u128)> = Vec::new();

    for note in notes {
        let location = note.get("location").unwrap_or(&Value::Null);
        let start = range_offset(location);
        let owner = range_bytes(note.get("owner_location").unwrap_or(&Value::Null));
        let descriptor = range_bytes(note.get("descriptor_location").unwrap_or(&Value::Null));
        let owner_offset = range_offset(note.get("owner_location").unwrap_or(&Value::Null));
        let descriptor_offset =
            range_offset(note.get("descriptor_location").unwrap_or(&Value::Null));
        let location_bytes = range_bytes(location);
        let layout_matches = match (
            start,
            owner,
            descriptor,
            owner_offset,
            descriptor_offset,
            location_bytes,
        ) {
            (
                Some(start),
                Some(owner),
                Some(descriptor),
                Some(owner_off),
                Some(desc_off),
                Some(loc_bytes),
            ) => {
                owner_off == start + 12
                    && desc_off == start + 12 + align(owner)
                    && loc_bytes == 12 + align(owner) + align(descriptor)
            }
            _ => false,
        };
        if !layout_matches {
            return Some(
                "Recorded note layout differs from its aligned header/owner/descriptor ranges."
                    .to_owned(),
            );
        }
        if let (Some(offset), Some(bytes)) = (range_offset(location), range_bytes(location)) {
            let segment = uint(note, "segment_index").unwrap_or(u64::MAX);
            by_segment.entry(segment).or_default().push((offset, bytes));
            all.push((offset, bytes));
        }
    }

    for item in padding {
        let segment_index = uint(item, "segment_index").unwrap_or(u64::MAX);
        let segment = segments.get(segment_index as usize);
        if !padding_matches(item, segment) {
            return Some(
                "Recorded note padding must be a short zero-filled segment tail.".to_owned(),
            );
        }
        if let Some(location) = item.get("location") {
            if let (Some(offset), Some(bytes)) = (range_offset(location), range_bytes(location)) {
                by_segment
                    .entry(segment_index)
                    .or_default()
                    .push((offset, bytes));
                all.push((offset, bytes));
            }
        }
    }

    // Overlap/repeat over all physical ranges, sorted by offset.
    let mut sorted = all.clone();
    sorted.sort_by_key(|(offset, _)| *offset);
    let mut end = 0_u128;
    for (start, bytes) in &sorted {
        if *start < end {
            return Some("Physical recorded note/padding ranges overlap or repeat.".to_owned());
        }
        if start + bytes > end {
            end = start + bytes;
        }
    }

    // Per-segment contiguous coverage of each PT_NOTE segment.
    for segment in segments {
        if str_field(segment, "type") != Some("PT_NOTE") {
            continue;
        }
        let index = uint(segment, "index").unwrap_or(u64::MAX);
        let mut ranges = by_segment.get(&index).cloned().unwrap_or_default();
        ranges.sort_by_key(|(offset, _)| *offset);
        let segment_offset = hex_at(segment, "offset").unwrap_or(0);
        let mut cursor = segment_offset;
        for (offset, bytes) in &ranges {
            if *offset != cursor {
                return Some(
                    "Recorded note/padding ranges leave a gap or overlap in their segment."
                        .to_owned(),
                );
            }
            cursor = offset + bytes;
        }
        if cursor != segment_offset + hex_at(segment, "file_size").unwrap_or(0) {
            return Some(
                "Recorded note/padding ranges do not completely cover their segment.".to_owned(),
            );
        }
    }

    None
}

fn padding_matches(item: &Value, segment: Option<&Value>) -> bool {
    let location = match item.get("location") {
        Some(location) => location,
        None => return false,
    };
    let (Some(offset), Some(bytes)) = (range_offset(location), range_bytes(location)) else {
        return false;
    };
    let raw = str_field(item, "bytes_base64").unwrap_or_default();
    let decoded = decoded_len(raw);
    // `/^A*={0,2}$/`: any number of A, then up to two = at the end only.
    let pattern_ok = pattern_a_eq(raw);
    let Some(segment) = segment else { return false };
    let segment_offset = match hex_at(segment, "offset") {
        Some(value) => value,
        None => return false,
    };
    let segment_file_size = match hex_at(segment, "file_size") {
        Some(value) => value,
        None => return false,
    };
    bytes > 0
        && bytes < 12
        && decoded == bytes as i128
        && pattern_ok
        && offset + bytes == segment_offset + segment_file_size
}

/// `/^A*={0,2}$/`.
fn pattern_a_eq(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] == b'A' {
        index += 1;
    }
    let mut equals = 0;
    while index < bytes.len() && bytes[index] == b'=' {
        equals += 1;
        index += 1;
    }
    index == bytes.len() && equals <= 2
}

const AMD64_REGISTERS: &[&str] = &[
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];
const AARCH64_REGISTERS: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "sp", "pc", "pstate",
];
