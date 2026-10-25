//! Inert HTML script references, inline JavaScript bodies and the first
//! document base href, with parse5-compatible source locations.
//!
//! Compatibility owner: `src/domain/javascript/htmlArtifactReferences.ts`
//! (parse5 8 with `sourceCodeLocationInfo`).
//!
//! html5ever 0.35 (tokenizer and tree builder, WHATWG HTML) owns
//! tokenization and tree construction. It is pinned below 0.39 because later
//! releases implement customizable `<select>`, which parse5 8.0.1 does not:
//! there, tags outside the select content model are dropped, so a script
//! after `<select><title>` stays a script.
//!
//! parse5 matches the in-body "any other end tag" by tag id even while a
//! foreign element is open. html5ever follows the foreign-content
//! specification, so collection also checks the retained arena ancestry for
//! HTML-namespaced scripts that parse5 leaves in SVG content. The ancestry
//! check preserves HTML integration subtrees while retaining SVG special
//! elements after malformed markup has crossed an integration point.
//!
//! html5ever it reports only line numbers, so token locations are
//! recovered here at the token boundary. Input is fed one character at a
//! time, so every token is observed at the character that completed it:
//!
//! - A tag token ends just after the `>` being fed.
//! - Tokens are contiguous and text is emitted as soon as it can no longer
//!   start markup, so a tag's `<` is the first `<` (followed by an ASCII
//!   letter, or by `/` and a letter for an end tag) at or after the character
//!   whose feed produced the previous token.
//! - A script body ends where the token that pops the element starts: its
//!   `</script` end tag, or end of input.
//!
//! Points use parse5 coordinates: one-based lines counted at LF and at a CR
//! not followed by LF, and UTF-16 columns, reported zero-based.
//!
//! parse5 8.0.1 counts a newline twice when it directly follows an `&` that
//! the tokenizer treated as a character reference start (data and RCDATA
//! text, attribute values): the character-reference state consumes the
//! newline, advancing the line, then reconsumes it. Later points carry that
//! extra line, so it is reproduced here.
mod sink;

use std::cell::{Cell, RefCell};

use html5ever::TokenizerResult;
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::{
    BufferQueue, Token, TokenSink, TokenSinkResult, Tokenizer, TokenizerOpts,
};
use html5ever::tree_builder::{TreeBuilder, TreeBuilderOpts};
use serde::Serialize;

use crate::javascript::contracts::static_analysis::{SourcePoint, SourceRange};
use sink::{Arena, NodeKind};

/// Inline bodies whose exact locations are retained per HTML file. Every
/// body is still counted; locations beyond this bound are omitted.
pub const HTML_INLINE_SCRIPT_LOCATION_LIMIT: usize = 100;

/// One script element that loads JavaScript by URL.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlScriptReference {
    pub script_path: String,
    /// The opening tag's range.
    pub location: SourceRange,
}

/// How an inline script body would be evaluated.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum InlineScriptType {
    Classic,
    Module,
}

/// JavaScript written directly in a script element.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlInlineScript {
    pub script_type: InlineScriptType,
    /// The body's range, between the opening and closing tags.
    pub location: SourceRange,
}

/// References extracted from one HTML document.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlArtifactReferences {
    pub base_href: Option<String>,
    pub scripts: Vec<HtmlScriptReference>,
    /// The first inline bodies in document order, up to the location limit.
    pub inline_scripts: Vec<HtmlInlineScript>,
    pub inline_script_count: usize,
}

/// The JavaScript MIME type essences from the WHATWG MIME Sniffing standard.
const JAVASCRIPT_MIME_TYPES: &[&str] = &[
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
];

/// Classify a script type as HTML "prepare the script element" does. Only a
/// `type` attribute is whitespace-stripped, and only for the MIME check.
fn inline_script_type(attrs: &[(String, String)]) -> Option<InlineScriptType> {
    let find = |name: &str| {
        attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let type_attr = find("type");
    let language = find("language");
    let type_string = match (type_attr, language) {
        (Some(value), _) => value.to_owned(),
        (None, Some(language)) if !language.is_empty() => format!("text/{language}"),
        _ => String::new(),
    };
    if type_string.is_empty() {
        return Some(InlineScriptType::Classic);
    }
    let mime_candidate = if type_attr.is_some() {
        type_string.trim_matches(['\t', '\n', '\u{c}', '\r', ' '])
    } else {
        &type_string
    };
    if JAVASCRIPT_MIME_TYPES.contains(&mime_candidate.to_ascii_lowercase().as_str()) {
        return Some(InlineScriptType::Classic);
    }
    type_string
        .eq_ignore_ascii_case("module")
        .then_some(InlineScriptType::Module)
}

/// ECMAScript `\s`: WhiteSpace and LineTerminator.
fn is_js_whitespace(character: char) -> bool {
    matches!(
        character,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

/// Token-boundary location state shared with the tree sink.
#[derive(Default)]
pub(crate) struct TokenLocations {
    /// Byte offset of the character being fed.
    feeding: Cell<usize>,
    /// Byte offset of the character whose feed produced the latest token.
    last_token_at: Cell<usize>,
    /// Byte span of the start tag being processed.
    pub(crate) start_tag: Cell<Option<(usize, usize)>>,
    /// Byte offset where the token being processed starts (end tags, EOF).
    pub(crate) token_start: Cell<usize>,
    /// Byte offsets of newlines that parse5 counts twice (see module docs).
    double_newlines: RefCell<Vec<usize>>,
}

fn is_html_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | b'\x0c' | b'\r' | b' ')
}

struct LocatingSink<'a> {
    text: &'a str,
    locations: &'a TokenLocations,
    builder: TreeBuilder<usize, Arena<'a>>,
}

impl LocatingSink<'_> {
    /// The first `<` at or after the previous token's character that opens
    /// a tag of the given kind, before `end`.
    fn tag_start(&self, end: usize, end_tag: bool) -> usize {
        let bytes = self.text.as_bytes();
        let from = self.locations.last_token_at.get();
        (from..end)
            .find(|&index| {
                bytes[index] == b'<'
                    && if end_tag {
                        bytes.get(index + 1) == Some(&b'/')
                            && bytes.get(index + 2).is_some_and(u8::is_ascii_alphabetic)
                    } else {
                        bytes.get(index + 1).is_some_and(u8::is_ascii_alphabetic)
                    }
            })
            .unwrap_or(from)
    }

    /// Record the newline at `offset` if it directly follows an `&`.
    fn note_double_newline(&self, offset: usize) {
        let bytes = self.text.as_bytes();
        // html5ever may only settle a CR once the LF of a CRLF is fed.
        let offset =
            if offset > 1 && bytes.get(offset) == Some(&b'\n') && bytes[offset - 1] == b'\r' {
                offset - 1
            } else {
                offset
            };
        if offset > 0
            && bytes[offset - 1] == b'&'
            && matches!(bytes.get(offset), Some(b'\n' | b'\r'))
        {
            self.locations.double_newlines.borrow_mut().push(offset);
        }
    }

    /// Attribute values reference characters but produce no text token, so
    /// the completed start tag's attribute values are scanned instead. This
    /// follows the tokenizer's attribute states over the tag's source span.
    fn note_attribute_double_newlines(&self, start: usize, end: usize) {
        let bytes = &self.text.as_bytes()[start..end];
        let mut index = 1; // `<`
        while index < bytes.len()
            && !is_html_space(bytes[index])
            && !matches!(bytes[index], b'/' | b'>')
        {
            index += 1;
        }
        loop {
            while index < bytes.len() && (is_html_space(bytes[index]) || bytes[index] == b'/') {
                index += 1;
            }
            if index >= bytes.len() || bytes[index] == b'>' {
                return;
            }
            // An attribute name's first character may be `=`.
            index += 1;
            while index < bytes.len()
                && !is_html_space(bytes[index])
                && !matches!(bytes[index], b'/' | b'>' | b'=')
            {
                index += 1;
            }
            while index < bytes.len() && is_html_space(bytes[index]) {
                index += 1;
            }
            if bytes.get(index) != Some(&b'=') {
                continue;
            }
            index += 1;
            while index < bytes.len() && is_html_space(bytes[index]) {
                index += 1;
            }
            let (value_start, value_end) = match bytes.get(index) {
                Some(&quote @ (b'"' | b'\'')) => {
                    let value_start = index + 1;
                    let value_end = (value_start..bytes.len())
                        .find(|&at| bytes[at] == quote)
                        .unwrap_or(bytes.len());
                    index = value_end + 1;
                    (value_start, value_end)
                }
                _ => {
                    let value_start = index;
                    while index < bytes.len()
                        && !is_html_space(bytes[index])
                        && bytes[index] != b'>'
                    {
                        index += 1;
                    }
                    (value_start, index)
                }
            };
            for (at, &byte) in bytes.iter().enumerate().take(value_end).skip(value_start) {
                if byte == b'&' {
                    self.note_double_newline(start + at + 1);
                }
            }
        }
    }
}

impl TokenSink for LocatingSink<'_> {
    type Handle = usize;

    fn process_token(&self, token: Token, line_number: u64) -> TokenSinkResult<usize> {
        let feeding = self.locations.feeding.get();
        let end = feeding
            + self.text[feeding..]
                .chars()
                .next()
                .map_or(0, char::len_utf8);
        match &token {
            Token::TagToken(tag) => {
                let end_tag = tag.kind == html5ever::tokenizer::TagKind::EndTag;
                let start = self.tag_start(end, end_tag);
                self.locations.token_start.set(start);
                if end_tag {
                    self.builder.sink.note_explicit_end_tag(tag.name.as_ref());
                }
                if !end_tag {
                    self.locations.start_tag.set(Some((start, end)));
                    self.note_attribute_double_newlines(start, end);
                }
            }
            Token::EOFToken => self.locations.token_start.set(self.text.len()),
            // A text `&` that started no reference is flushed while the
            // character after it is fed.
            Token::CharacterTokens(chars) if chars.starts_with('&') => {
                self.note_double_newline(feeding)
            }
            _ => {}
        }
        if !matches!(token, Token::ParseError(_)) {
            self.locations.last_token_at.set(feeding);
        }
        let result = self.builder.process_token(token, line_number);
        self.locations.start_tag.set(None);
        result
    }

    fn end(&self) {
        self.builder.end();
    }

    /// Decides whether `<![CDATA[` opens a CDATA section. parse5 8.0.1
    /// (`_setContextModes`) treats a foreign current node that is an
    /// integration point as HTML here, so it starts a bogus comment instead.
    fn adjusted_current_node_present_but_not_in_html_namespace(&self) -> bool {
        let sink = &self.builder.sink;
        self.builder
            .adjusted_current_node_present_but_not_in_html_namespace()
            && !sink
                .last_named()
                .is_some_and(|id| sink.is_integration_point(id))
    }
}

/// Convert sorted byte offsets to parse5 points in one sweep.
fn points(text: &str, offsets: &[usize], double_newlines: &[usize]) -> Vec<SourcePoint> {
    let mut doubles = double_newlines.iter().peekable();
    let mut out = Vec::with_capacity(offsets.len());
    let mut line = 1_u32;
    let mut column = 0_u32;
    let mut iter = text.char_indices().peekable();
    for &offset in offsets {
        while let Some(&(index, character)) = iter.peek() {
            if index >= offset {
                break;
            }
            iter.next();
            if doubles.next_if(|&&at| at == index).is_some() {
                line += 1;
            }
            let next_is_lf = iter.peek().is_some_and(|&(_, next)| next == '\n');
            if character == '\n' || (character == '\r' && !next_is_lf) {
                line += 1;
                column = 0;
            } else if character != '\r' {
                column += u32::try_from(character.len_utf16()).unwrap_or(1);
            }
        }
        out.push(SourcePoint { line, column });
    }
    out
}

/// `htmlArtifactReferences`.
pub fn html_artifact_references(text: &str) -> HtmlArtifactReferences {
    let locations = TokenLocations::default();
    let arena = Arena::new(&locations);
    let builder = TreeBuilder::new(arena, TreeBuilderOpts::default());
    let tokenizer = Tokenizer::new(
        LocatingSink {
            text,
            locations: &locations,
            builder,
        },
        // parse5 keeps a leading BOM as document text (so it ends
        // `frameset-ok`); html5ever's streaming flag would also discard a
        // BOM at the start of every fed chunk.
        TokenizerOpts {
            discard_bom: false,
            ..TokenizerOpts::default()
        },
    );
    let queue = BufferQueue::default();
    for (index, character) in text.char_indices() {
        locations.feeding.set(index);
        queue.push_back(StrTendril::from_char(character));
        while let TokenizerResult::Script(_) = tokenizer.feed(&queue) {}
    }
    locations.feeding.set(text.len());
    tokenizer.end();
    let arena = &tokenizer.sink.builder.sink;
    let mut doubles = locations.double_newlines.take();
    doubles.sort_unstable();
    doubles.dedup();
    collect(text, arena, &doubles)
}

/// Pre-order traversal of the document, excluding inert template contents.
fn collect(text: &str, arena: &Arena<'_>, double_newlines: &[usize]) -> HtmlArtifactReferences {
    let nodes = arena.nodes();
    let mut base_href: Option<String> = None;
    let mut pending: Vec<(usize, usize)> = Vec::new(); // (start, end) byte spans
    let mut scripts: Vec<(String, usize)> = Vec::new();
    let mut inline: Vec<(InlineScriptType, usize)> = Vec::new();
    let mut inline_count = 0;
    let mut stack = vec![0_usize];
    while let Some(id) = stack.pop() {
        let node = &nodes[id];
        if let NodeKind::Element(element) = &node.kind
            && element.html
            && !(element.local == "script" && arena.is_in_foreign_svg(id))
        {
            let attr = |name: &str| {
                element
                    .attrs
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            };
            if element.local == "base" && base_href.is_none() {
                base_href = attr("href").cloned();
            }
            if element.local == "script" {
                let src = attr("src");
                if let (Some(src), Some(span)) = (src, element.start_tag)
                    && !src.is_empty()
                {
                    scripts.push((src.clone(), pending.len()));
                    pending.push(span);
                }
                if src.is_none()
                    && let Some(span) = element.start_tag
                {
                    let mut blank = true;
                    let mut has_text = false;
                    for &child in &node.children {
                        if let NodeKind::Text(value) = &nodes[child].kind {
                            has_text = true;
                            if blank && value.chars().any(|character| !is_js_whitespace(character))
                            {
                                blank = false;
                            }
                        }
                    }
                    if !blank
                        && has_text
                        && let Some(script_type) = inline_script_type(&element.attrs)
                    {
                        inline_count += 1;
                        if inline.len() < HTML_INLINE_SCRIPT_LOCATION_LIMIT {
                            // An unclosed script ends at end of input.
                            inline.push((script_type, pending.len()));
                            pending.push((span.1, element.end.unwrap_or(text.len())));
                        }
                    }
                }
            }
        }
        stack.extend(node.children.iter().rev());
    }
    let mut offsets: Vec<usize> = pending
        .iter()
        .flat_map(|(start, end)| [*start, *end])
        .collect();
    offsets.sort_unstable();
    offsets.dedup();
    let converted = points(text, &offsets, double_newlines);
    let point = |offset: usize| converted[offsets.binary_search(&offset).unwrap_or_default()];
    let range = |index: usize| SourceRange {
        start: point(pending[index].0),
        end: point(pending[index].1),
    };
    HtmlArtifactReferences {
        base_href,
        scripts: scripts
            .into_iter()
            .map(|(script_path, index)| HtmlScriptReference {
                script_path,
                location: range(index),
            })
            .collect(),
        inline_scripts: inline
            .into_iter()
            .map(|(script_type, index)| HtmlInlineScript {
                script_type,
                location: range(index),
            })
            .collect(),
        inline_script_count: inline_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn first_script_line(text: &str) -> u32 {
        html_artifact_references(text).scripts[0]
            .location
            .start
            .line
    }

    /// Expected lines were produced by parse5 8.0.1 (the TS owner).
    #[test]
    fn newline_after_reference_ampersand_counts_twice_like_parse5() {
        assert_eq!(first_script_line("&\n<script src=a>"), 3);
        assert_eq!(first_script_line("&\r\n<script src=a>"), 3);
        assert_eq!(first_script_line("& \n<script src=a>"), 2);
        assert_eq!(first_script_line("<p title=&\n><script src=a>"), 3);
        assert_eq!(first_script_line("<style>&\n</style><script src=a>"), 2);
        assert_eq!(first_script_line("<!--&\n--><script src=a>"), 2);
    }

    #[test]
    fn annotation_xml_html_encoding_is_an_integration_point() {
        let out =
            html_artifact_references("<math><annotation-xml encoding=text/html><script src=a.js>");
        assert_eq!(out.scripts.len(), 1);
        let out = html_artifact_references("<math><annotation-xml><script src=a.js>");
        assert!(out.scripts.is_empty());
    }

    #[test]
    fn cdata_in_mathml_text_integration_point_is_a_bogus_comment_like_parse5() {
        let out = html_artifact_references("<math><mi><![CDATA[x><script>a</script>");
        assert_eq!(out.inline_script_count, 1);
        let out = html_artifact_references("<math><![CDATA[x><script>a</script>]]>");
        assert_eq!(out.inline_script_count, 0);
    }

    #[test]
    fn leading_bom_is_text_and_ends_frameset_ok_like_parse5() {
        let out = html_artifact_references("\u{feff}<frameset><base href=x>");
        assert_eq!(out.base_href.as_deref(), Some("x"));
        let out = html_artifact_references("\u{feff}<script src=a>");
        assert_eq!(
            out.scripts[0].location.start,
            SourcePoint { line: 1, column: 1 }
        );
    }

    /// parse5 8.0.1 predates customizable `<select>`; html5ever 0.35 does too.
    #[test]
    fn select_ignores_tags_outside_its_content_model_like_parse5() {
        let out = html_artifact_references(
            "<select><title><script src=a.js></script></title><base href=x>",
        );
        assert_eq!(out.scripts.len(), 1);
        assert_eq!(out.base_href, None);
    }

    #[test]
    fn foreign_end_tags_keep_later_script_outside_html_like_parse5() {
        let text = "<foreignObject><script src=''> </math><script>x</script><script type=importmap><template shadowrootmode=open><xmp><template></SCRIPT></i>--!><svg><script async defer src=c.js type=module></xmp><title><b></head><base></title></script>--!><script src=d.js>inline</script>";
        let out = html_artifact_references(text);

        assert!(out.scripts.is_empty());
        assert_eq!(out.inline_script_count, 0);
    }
}
