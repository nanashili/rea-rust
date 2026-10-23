//! Cell attribute words, ported from xterm.js `common/buffer/AttributeData.ts`
//! and `common/buffer/Constants.ts`.
//!
//! The predicates intentionally return the raw masked words xterm returns
//! (`fg & BOLD`, `1` for an extended underline, ...): the serializer compares
//! those values for equality, so collapsing them to `bool` would change its
//! output.

pub const CODEPOINT_MASK: u32 = 0x1F_FFFF;
pub const IS_COMBINED_MASK: u32 = 0x20_0000;
pub const HAS_CONTENT_MASK: u32 = 0x3F_FFFF;
pub const WIDTH_MASK: u32 = 0xC0_0000;
pub const WIDTH_SHIFT: u32 = 22;

pub const PCOLOR_MASK: u32 = 0xFF;
pub const RGB_MASK: u32 = 0xFF_FFFF;
pub const CM_MASK: u32 = 0x300_0000;
pub const CM_P16: u32 = 0x100_0000;
pub const CM_P256: u32 = 0x200_0000;
pub const CM_RGB: u32 = 0x300_0000;

pub const FG_INVERSE: u32 = 0x400_0000;
pub const FG_BOLD: u32 = 0x800_0000;
pub const FG_UNDERLINE: u32 = 0x1000_0000;
pub const FG_BLINK: u32 = 0x2000_0000;
pub const FG_INVISIBLE: u32 = 0x4000_0000;
pub const FG_STRIKETHROUGH: u32 = 0x8000_0000;

pub const BG_ITALIC: u32 = 0x400_0000;
pub const BG_DIM: u32 = 0x800_0000;
pub const BG_HAS_EXTENDED: u32 = 0x1000_0000;
pub const BG_PROTECTED: u32 = 0x2000_0000;
pub const BG_OVERLINE: u32 = 0x4000_0000;

const EXT_UNDERLINE_STYLE: u32 = 0x1C00_0000;

pub const UNDERLINE_NONE: u32 = 0;
pub const UNDERLINE_SINGLE: u32 = 1;
pub const UNDERLINE_DOUBLE: u32 = 2;
pub const UNDERLINE_DASHED: u32 = 5;

/// xterm `ExtendedAttrs` (underline style/color, variant, hyperlink id).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExtendedAttrs {
    ext: u32,
    pub url_id: u32,
}

impl ExtendedAttrs {
    pub fn underline_style(&self) -> u32 {
        if self.url_id != 0 {
            return UNDERLINE_DASHED;
        }
        (self.ext & EXT_UNDERLINE_STYLE) >> 26
    }

    pub fn set_underline_style(&mut self, value: u32) {
        self.ext &= !EXT_UNDERLINE_STYLE;
        self.ext |= (value << 26) & EXT_UNDERLINE_STYLE;
    }

    /// Underline color word; xterm stores `-1` (all mode/RGB bits) for "none".
    pub fn underline_color(&self) -> u32 {
        self.ext & (CM_MASK | RGB_MASK)
    }

    pub fn set_underline_color(&mut self, value: u32) {
        self.ext &= !(CM_MASK | RGB_MASK);
        self.ext |= value & (CM_MASK | RGB_MASK);
    }

    pub fn is_empty(&self) -> bool {
        self.underline_style() == UNDERLINE_NONE && self.url_id == 0
    }
}

/// xterm `AttributeData`: `fg`/`bg` words plus extended attributes.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attr {
    pub fg: u32,
    pub bg: u32,
    pub extended: ExtendedAttrs,
}

impl Attr {
    pub fn is_inverse(&self) -> u32 {
        self.fg & FG_INVERSE
    }
    pub fn is_bold(&self) -> u32 {
        self.fg & FG_BOLD
    }
    pub fn is_underline(&self) -> u32 {
        if self.has_extended_attrs() != 0 && self.extended.underline_style() != UNDERLINE_NONE {
            return 1;
        }
        self.fg & FG_UNDERLINE
    }
    pub fn is_blink(&self) -> u32 {
        self.fg & FG_BLINK
    }
    pub fn is_invisible(&self) -> u32 {
        self.fg & FG_INVISIBLE
    }
    pub fn is_italic(&self) -> u32 {
        self.bg & BG_ITALIC
    }
    pub fn is_dim(&self) -> u32 {
        self.bg & BG_DIM
    }
    pub fn is_strikethrough(&self) -> u32 {
        self.fg & FG_STRIKETHROUGH
    }
    pub fn is_overline(&self) -> u32 {
        self.bg & BG_OVERLINE
    }
    pub fn fg_color_mode(&self) -> u32 {
        self.fg & CM_MASK
    }
    pub fn bg_color_mode(&self) -> u32 {
        self.bg & CM_MASK
    }
    pub fn is_fg_rgb(&self) -> bool {
        self.fg & CM_MASK == CM_RGB
    }
    pub fn is_bg_rgb(&self) -> bool {
        self.bg & CM_MASK == CM_RGB
    }
    pub fn is_fg_palette(&self) -> bool {
        matches!(self.fg & CM_MASK, CM_P16 | CM_P256)
    }
    pub fn is_bg_palette(&self) -> bool {
        matches!(self.bg & CM_MASK, CM_P16 | CM_P256)
    }
    pub fn is_attribute_default(&self) -> bool {
        self.fg == 0 && self.bg == 0
    }
    /// Palette index, RGB value, or `-1` for the default color.
    pub fn fg_color(&self) -> i64 {
        color_of(self.fg)
    }
    pub fn bg_color(&self) -> i64 {
        color_of(self.bg)
    }
    pub fn has_extended_attrs(&self) -> u32 {
        self.bg & BG_HAS_EXTENDED
    }
    pub fn update_extended(&mut self) {
        if self.extended.is_empty() {
            self.bg &= !BG_HAS_EXTENDED;
        } else {
            self.bg |= BG_HAS_EXTENDED;
        }
    }
}

fn color_of(word: u32) -> i64 {
    match word & CM_MASK {
        CM_P16 | CM_P256 => i64::from(word & PCOLOR_MASK),
        CM_RGB => i64::from(word & RGB_MASK),
        _ => -1,
    }
}

/// xterm `CellData`: one loaded cell (content word, attributes, combined text).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Cell {
    pub content: u32,
    pub attr: Attr,
    pub combined: String,
}

impl Cell {
    /// The null cell xterm fills blank lines with: no code point, width 1.
    pub fn null(attr: Attr) -> Self {
        Self {
            content: 1 << WIDTH_SHIFT,
            attr,
            combined: String::new(),
        }
    }

    pub fn width(&self) -> u32 {
        self.content >> WIDTH_SHIFT
    }

    pub fn is_combined(&self) -> bool {
        self.content & IS_COMBINED_MASK != 0
    }

    /// Cell text: combined data, the code point, or empty for null cells.
    pub fn chars(&self) -> String {
        if self.is_combined() {
            return self.combined.clone();
        }
        char_string(self.content & CODEPOINT_MASK)
    }
}

/// `stringFromCodePoint` for stored code points (0 renders as empty).
pub fn char_string(code_point: u32) -> String {
    if code_point == 0 {
        return String::new();
    }
    char::from_u32(code_point).map_or_else(|| "\u{FFFD}".to_owned(), String::from)
}
