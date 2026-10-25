use serde_json::Value;

#[derive(Debug, Clone)]
struct ObjectNode {
    start: usize,
    end: usize,
    members: Vec<Member>,
}

#[derive(Debug, Clone)]
struct Member {
    key: String,
    key_start: usize,
    value_start: usize,
    value_end: usize,
    member_end: usize,
}

/// Apply a JSONC registration edit without reserializing the document.
///
/// The parser records byte spans for objects and properties while skipping
/// comments and trailing commas. Edits are then applied from right to left,
/// so every unrelated byte (including comments and whitespace) is retained.
pub fn edit(
    source: &str,
    server_path: &[&str],
    registration: Option<&Value>,
) -> Result<Vec<u8>, String> {
    if source.trim().is_empty() {
        let Some(value) = registration else {
            return Ok(source.as_bytes().to_vec());
        };
        let mut registration_object = serde_json::Map::new();
        registration_object.insert("rea".to_owned(), value.clone());
        let mut nested = Value::Object(registration_object);
        for key in server_path.iter().rev() {
            let mut object = serde_json::Map::new();
            object.insert((*key).to_owned(), nested);
            nested = Value::Object(object);
        }
        return serde_json::to_vec(&nested)
            .map_err(|error| format!("serialize JSONC registration: {error}"));
    }

    let mut parser = Parser::new(source);
    let root = parser.parse_object()?;
    parser.skip_space_and_comments()?;
    if parser.position != source.len() {
        return Err("unexpected JSONC data after root object".to_owned());
    }

    let mut current = root;
    let mut missing_from = None;
    for (index, key) in server_path.iter().enumerate() {
        if current
            .members
            .iter()
            .filter(|member| member.key == *key)
            .count()
            > 1
        {
            return Err(format!("configuration contains duplicate member {key}"));
        }
        let Some(member) = current.members.iter().find(|member| member.key == *key) else {
            missing_from = Some((index, current.clone()));
            break;
        };
        let node = Parser::new(&source[member.value_start..member.value_end])
            .parse_object()
            .map_err(|error| format!("configuration member {key} is not an object: {error}"))?;
        current = ObjectNode {
            start: member.value_start + node.start,
            end: member.value_start + node.end,
            members: node
                .members
                .into_iter()
                .map(|mut nested| {
                    nested.key_start += member.value_start;
                    nested.value_start += member.value_start;
                    nested.value_end += member.value_start;
                    nested.member_end += member.value_start;
                    nested
                })
                .collect(),
        };
    }

    let mut edits = Vec::new();
    match missing_from {
        Some((index, parent)) => {
            let Some(value) = registration else {
                return Ok(source.as_bytes().to_vec());
            };
            let mut registration_object = serde_json::Map::new();
            registration_object.insert("rea".to_owned(), value.clone());
            let mut nested = Value::Object(registration_object);
            for key in server_path[index..].iter().rev() {
                let mut object = serde_json::Map::new();
                object.insert((*key).to_owned(), nested);
                nested = Value::Object(object);
            }
            let object_text = serde_json::to_string(&nested)
                .map_err(|error| format!("serialize JSONC registration: {error}"))?;
            let property = object_text
                .strip_prefix('{')
                .and_then(|text| text.strip_suffix('}'))
                .ok_or_else(|| "internal JSONC registration shape was not an object".to_owned())?;
            edits.push(insert_member(source, &parent, property)?);
        }
        None => {
            if current
                .members
                .iter()
                .filter(|member| member.key == "rea")
                .count()
                > 1
            {
                return Err("configuration contains duplicate member rea".to_owned());
            }
            let Some(member) = current.members.iter().find(|member| member.key == "rea") else {
                if let Some(value) = registration {
                    let text = serde_json::to_string(value)
                        .map_err(|error| format!("serialize JSONC registration: {error}"))?;
                    edits.push(insert_member(source, &current, &format!("\"rea\":{text}"))?);
                }
                return Ok(apply_edits(source.as_bytes(), edits));
            };
            match registration {
                Some(value) => {
                    let text = serde_json::to_string(value)
                        .map_err(|error| format!("serialize JSONC registration: {error}"))?;
                    edits.push((member.value_start, member.value_end, text));
                }
                None => edits.push(removal_edit(source, &current, member)),
            }
        }
    }
    Ok(apply_edits(source.as_bytes(), edits))
}

fn insert_member(
    source: &str,
    object: &ObjectNode,
    member: &str,
) -> Result<(usize, usize, String), String> {
    let close = object.end;
    let body = &source[object.start + 1..close];
    let multiline = body.contains('\n');
    let has_member = !object.members.is_empty();
    let has_trailing_comma = object
        .members
        .last()
        .is_some_and(|member| source.as_bytes().get(member.member_end) == Some(&b','));
    let indent = if multiline {
        let closing_indent = closing_indent(source, object.start);
        format!("{closing_indent}  ")
    } else {
        String::new()
    };
    let insertion = if multiline {
        let separator = if has_member && !has_trailing_comma {
            ","
        } else {
            ""
        };
        format!(
            "{separator}\n{indent}{member}\n{}",
            closing_indent(source, object.start)
        )
    } else {
        let separator = if has_member && !has_trailing_comma {
            ", "
        } else {
            ""
        };
        format!("{separator}{member}")
    };
    Ok((close, close, insertion))
}

fn closing_indent(source: &str, object_start: usize) -> &str {
    let line = source[..object_start]
        .rsplit_once('\n')
        .map_or(source, |(_, line)| line);
    let leading = line.len() - line.trim_start_matches([' ', '\t']).len();
    &line[..leading]
}

fn removal_edit(source: &str, object: &ObjectNode, member: &Member) -> (usize, usize, String) {
    let after = skip_space_and_comments(source, member.value_end);
    if source.as_bytes().get(after) == Some(&b',') {
        return (
            member.key_start,
            after + 1,
            source[member.value_end..after].to_owned(),
        );
    }
    if let Some(previous) = object
        .members
        .iter()
        .rev()
        .find(|candidate| candidate.value_end <= member.key_start)
    {
        let comma = skip_space_and_comments(source, previous.member_end);
        if source.as_bytes().get(comma) == Some(&b',') {
            return (
                comma,
                member.value_end,
                source[comma + 1..member.key_start].to_owned(),
            );
        }
    }
    (member.key_start, member.value_end, String::new())
}

fn apply_edits(source: &[u8], mut edits: Vec<(usize, usize, String)>) -> Vec<u8> {
    edits.sort_by_key(|(start, _, _)| *start);
    let mut output = source.to_vec();
    for (start, end, replacement) in edits.into_iter().rev() {
        output.splice(start..end, replacement.into_bytes());
    }
    output
}

fn skip_space_and_comments(source: &str, mut position: usize) -> usize {
    let bytes = source.as_bytes();
    loop {
        while bytes.get(position).is_some_and(u8::is_ascii_whitespace) {
            position += 1;
        }
        if bytes.get(position..position + 2) == Some(b"//") {
            position += 2;
            while bytes.get(position).is_some_and(|byte| *byte != b'\n') {
                position += 1;
            }
        } else if bytes.get(position..position + 2) == Some(b"/*") {
            position += 2;
            while position < bytes.len() && bytes.get(position..position + 2) != Some(b"*/") {
                position += 1;
            }
            if position == bytes.len() {
                return position;
            }
            position += 2;
        } else {
            return position;
        }
    }
}

struct Parser<'a> {
    source: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            position: 0,
        }
    }

    fn parse_object(&mut self) -> Result<ObjectNode, String> {
        self.skip_space_and_comments()?;
        let start = self.position;
        self.expect(b'{')?;
        let mut members = Vec::new();
        loop {
            self.skip_space_and_comments()?;
            if self.consume(b'}') {
                return Ok(ObjectNode {
                    start,
                    end: self.position - 1,
                    members,
                });
            }
            let key_start = self.position;
            let key = self.parse_string()?;
            self.skip_space_and_comments()?;
            self.expect(b':')?;
            self.skip_space_and_comments()?;
            let value_start = self.position;
            self.parse_value()?;
            let value_end = self.position;
            let member_end = skip_space_and_comments(self.source, value_end);
            members.push(Member {
                key,
                key_start,
                value_start,
                value_end,
                member_end,
            });
            self.position = member_end;
            if self.consume(b',') {
                continue;
            }
            if self.consume(b'}') {
                return Ok(ObjectNode {
                    start,
                    end: self.position - 1,
                    members,
                });
            }
            return Err("expected comma or closing brace".to_owned());
        }
    }

    fn parse_value(&mut self) -> Result<(), String> {
        self.skip_space_and_comments()?;
        match self.source.as_bytes().get(self.position) {
            Some(b'{') => {
                let nested = self.parse_object()?;
                self.position = nested.end + 1;
            }
            Some(b'[') => self.parse_array()?,
            Some(b'"') => {
                self.parse_string()?;
            }
            Some(_) => {
                while let Some(byte) = self.source.as_bytes().get(self.position) {
                    let starts_comment = *byte == b'/'
                        && matches!(
                            self.source.as_bytes().get(self.position + 1),
                            Some(b'/' | b'*')
                        );
                    if matches!(byte, b',' | b'}' | b']')
                        || byte.is_ascii_whitespace()
                        || starts_comment
                    {
                        break;
                    }
                    self.position += 1;
                }
            }
            None => return Err("unexpected end of JSONC value".to_owned()),
        }
        Ok(())
    }

    fn parse_array(&mut self) -> Result<(), String> {
        self.expect(b'[')?;
        loop {
            self.skip_space_and_comments()?;
            if self.consume(b']') {
                return Ok(());
            }
            self.parse_value()?;
            self.skip_space_and_comments()?;
            if self.consume(b',') {
                continue;
            }
            if self.consume(b']') {
                return Ok(());
            }
            return Err("expected comma or closing bracket".to_owned());
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        let start = self.position;
        self.expect(b'"')?;
        let mut escaped = false;
        while let Some(byte) = self.source.as_bytes().get(self.position) {
            self.position += 1;
            if escaped {
                escaped = false;
                continue;
            }
            if *byte == b'\\' {
                escaped = true;
                continue;
            }
            if *byte == b'"' {
                return serde_json::from_str(&self.source[start..self.position])
                    .map_err(|error| format!("invalid JSON string: {error}"));
            }
        }
        Err("unterminated JSON string".to_owned())
    }

    fn skip_space_and_comments(&mut self) -> Result<(), String> {
        self.position = skip_space_and_comments(self.source, self.position);
        if self.source.as_bytes().get(self.position..self.position + 2) == Some(b"/*")
            && !self.source[self.position + 2..].contains("*/")
        {
            return Err("unterminated JSONC comment".to_owned());
        }
        Ok(())
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(format!("expected '{}'", byte as char))
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.source.as_bytes().get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_entry_and_preserves_comments_and_siblings() {
        let source = "{\n  // keep this\n  \"mcpServers\": {\n    \"other\": {\"command\": \"tool\"},\n    \"rea\": {\"command\": \"npx\", \"args\": []}, // trailing\n  },\n}\n";
        let value = serde_json::json!({"command":"npx","args":["-y","rea-agents@latest","mcp"]});
        let output = String::from_utf8(edit(source, &["mcpServers"], Some(&value)).expect("edit"))
            .expect("utf8");
        assert!(output.contains("// keep this"));
        assert!(output.contains("// trailing"));
        assert!(output.contains("\"other\""));
        assert!(output.contains("rea-agents@latest"));
    }

    #[test]
    fn inserts_missing_path_without_rewriting_existing_comment() {
        let source = "{\n  // unrelated\n  \"settings\": true\n}\n";
        let value = serde_json::json!({"command":"npx","args":[]});
        let output = String::from_utf8(edit(source, &["mcpServers"], Some(&value)).expect("edit"))
            .expect("utf8");
        assert!(output.contains("// unrelated"));
        assert!(output.contains("\"mcpServers\":{"));
    }

    #[test]
    fn inserts_registration_inside_missing_nested_server_path() {
        let source = "{\n  // keep this sibling\n  \"settings\": true\n}\n";
        let value = serde_json::json!({"command": "npx", "args": []});
        let output =
            String::from_utf8(edit(source, &["mcp", "servers"], Some(&value)).expect("edit"))
                .expect("utf8");
        let normalized = crate::maintenance_client_config::normalize_jsonc(&output);
        let document: Value = serde_json::from_str(&normalized).expect("valid JSONC");
        assert_eq!(document["mcp"]["servers"]["rea"]["command"], "npx");
        assert!(output.contains("// keep this sibling"));
    }

    #[test]
    fn rejects_duplicate_registration_keys_instead_of_choosing_one() {
        let source = "{\"mcpServers\":{\"rea\":{},\"r\\u0065a\":{}}}";
        let value = serde_json::json!({"command": "npx", "args": []});
        let error = edit(source, &["mcpServers"], Some(&value)).expect_err("duplicate key");
        assert!(error.contains("duplicate member rea"));
    }

    #[test]
    fn removes_entry_without_dangling_commas() {
        let source = "{\"mcpServers\":{\"other\":1,\"rea\":{\"command\":\"npx\"}}}";
        let output =
            String::from_utf8(edit(source, &["mcpServers"], None).expect("edit")).expect("utf8");
        assert_eq!(output, "{\"mcpServers\":{\"other\":1}}");
    }
}
