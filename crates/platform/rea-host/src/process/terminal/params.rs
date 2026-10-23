//! CSI/DCS parameter storage, ported from xterm.js `common/parser/Params.ts`
//! (32 params, 32 sub-params, values clamped to 2^31-1, `-1` for an empty
//! sub-parameter, ZDM `0` for an empty parameter).

const MAX_VALUE: i32 = 0x7FFF_FFFF;
const MAX_LENGTH: usize = 32;
const MAX_SUB_LENGTH: usize = 32;

#[derive(Clone, Debug)]
pub struct Params {
    params: [i32; MAX_LENGTH],
    pub length: usize,
    sub_params: [i32; MAX_SUB_LENGTH],
    sub_length: usize,
    /// Per-parameter `start << 8 | end` into `sub_params`.
    sub_idx: [u16; MAX_LENGTH],
    reject_digits: bool,
    reject_sub_digits: bool,
    digit_is_sub: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            params: [0; MAX_LENGTH],
            length: 0,
            sub_params: [0; MAX_SUB_LENGTH],
            sub_length: 0,
            sub_idx: [0; MAX_LENGTH],
            reject_digits: false,
            reject_sub_digits: false,
            digit_is_sub: false,
        }
    }
}

impl Params {
    pub fn reset(&mut self) {
        self.length = 0;
        self.sub_length = 0;
        self.reject_digits = false;
        self.reject_sub_digits = false;
        self.digit_is_sub = false;
    }

    pub fn add_param(&mut self, value: i32) {
        self.digit_is_sub = false;
        if self.length >= MAX_LENGTH {
            self.reject_digits = true;
            return;
        }
        self.sub_idx[self.length] = ((self.sub_length as u16) << 8) | self.sub_length as u16;
        self.params[self.length] = value.min(MAX_VALUE);
        self.length += 1;
    }

    pub fn add_sub_param(&mut self, value: i32) {
        self.digit_is_sub = true;
        if self.length == 0 {
            return;
        }
        if self.reject_digits || self.sub_length >= MAX_SUB_LENGTH {
            self.reject_sub_digits = true;
            return;
        }
        self.sub_params[self.sub_length] = value.min(MAX_VALUE);
        self.sub_length += 1;
        self.sub_idx[self.length - 1] = self.sub_idx[self.length - 1].wrapping_add(1);
    }

    pub fn add_digit(&mut self, value: i32) {
        let length = if self.digit_is_sub {
            self.sub_length
        } else {
            self.length
        };
        if self.reject_digits || length == 0 || (self.digit_is_sub && self.reject_sub_digits) {
            return;
        }
        let store = if self.digit_is_sub {
            &mut self.sub_params[..]
        } else {
            &mut self.params[..]
        };
        let current = store[length - 1];
        store[length - 1] = if current != -1 {
            (i64::from(current) * 10 + i64::from(value)).min(i64::from(MAX_VALUE)) as i32
        } else {
            value
        };
    }

    /// `params.params[index]`; reads past `length` see stale storage like xterm.
    pub fn get(&self, index: usize) -> i32 {
        self.params.get(index).copied().unwrap_or(0)
    }

    pub fn has_sub_params(&self, index: usize) -> bool {
        let idx = self.sub_idx.get(index).copied().unwrap_or(0);
        (idx & 0xFF) > (idx >> 8)
    }

    pub fn sub_params(&self, index: usize) -> &[i32] {
        let idx = self.sub_idx.get(index).copied().unwrap_or(0);
        let (start, end) = (usize::from(idx >> 8), usize::from(idx & 0xFF));
        if end > start {
            &self.sub_params[start..end]
        } else {
            &[]
        }
    }
}
