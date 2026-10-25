//! VT500 escape-sequence parser, ported from xterm.js
//! `common/parser/EscapeSequenceParser.ts` (Paul Williams' state machine with
//! xterm's transition table, ZDM params, sub-params, two intermediates, and
//! its read-ahead loops). OSC payloads are collected for the handler; DCS
//! payloads are consumed (xterm's only DCS handler, DECRQSS, answers on the
//! input channel and never changes screen state).

use std::sync::OnceLock;

use super::params::Params;

const GROUND: u8 = 0;
const ESCAPE: u8 = 1;
const ESCAPE_INTERMEDIATE: u8 = 2;
const CSI_ENTRY: u8 = 3;
const CSI_PARAM: u8 = 4;
const CSI_INTERMEDIATE: u8 = 5;
const CSI_IGNORE: u8 = 6;
const SOS_PM_APC_STRING: u8 = 7;
const OSC_STRING: u8 = 8;
const DCS_ENTRY: u8 = 9;
const DCS_PARAM: u8 = 10;
const DCS_IGNORE: u8 = 11;
const DCS_INTERMEDIATE: u8 = 12;
const DCS_PASSTHROUGH: u8 = 13;

const A_IGNORE: u8 = 0;
const A_ERROR: u8 = 1;
const A_PRINT: u8 = 2;
const A_EXECUTE: u8 = 3;
const A_OSC_START: u8 = 4;
const A_OSC_PUT: u8 = 5;
const A_OSC_END: u8 = 6;
const A_CSI_DISPATCH: u8 = 7;
const A_PARAM: u8 = 8;
const A_COLLECT: u8 = 9;
const A_ESC_DISPATCH: u8 = 10;
const A_CLEAR: u8 = 11;
const A_DCS_HOOK: u8 = 12;
const A_DCS_PUT: u8 = 13;
const A_DCS_UNHOOK: u8 = 14;

const NON_ASCII_PRINTABLE: u32 = 0xA0;
/// xterm `PAYLOAD_LIMIT` (UTF-16 code units) for OSC data.
const PAYLOAD_LIMIT: usize = 10_000_000;

struct Table([u8; 4095]);

impl Table {
    fn add(&mut self, code: usize, state: u8, action: u8, next: u8) {
        self.0[(usize::from(state) << 8) | code] = (action << 4) | next;
    }
    fn add_many(
        &mut self,
        codes: impl IntoIterator<Item = usize>,
        state: u8,
        action: u8,
        next: u8,
    ) {
        for code in codes {
            self.add(code, state, action, next);
        }
    }
}

fn table() -> &'static Table {
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(build_table)
}

fn build_table() -> Table {
    let mut t = Table([(A_ERROR << 4) | GROUND; 4095]);
    let printables = || 0x20..0x7f;
    let executables = || (0x00..0x18).chain([0x19]).chain(0x1c..0x20);
    t.add_many(printables(), GROUND, A_PRINT, GROUND);
    for state in GROUND..=DCS_PASSTHROUGH {
        t.add_many([0x18, 0x1a, 0x99, 0x9a], state, A_EXECUTE, GROUND);
        t.add_many(0x80..0x90, state, A_EXECUTE, GROUND);
        t.add_many(0x90..0x98, state, A_EXECUTE, GROUND);
        t.add(0x9c, state, A_IGNORE, GROUND);
        t.add(0x1b, state, A_CLEAR, ESCAPE);
        t.add(0x9d, state, A_OSC_START, OSC_STRING);
        t.add_many([0x98, 0x9e, 0x9f], state, A_IGNORE, SOS_PM_APC_STRING);
        t.add(0x9b, state, A_CLEAR, CSI_ENTRY);
        t.add(0x90, state, A_CLEAR, DCS_ENTRY);
    }
    t.add_many(executables(), GROUND, A_EXECUTE, GROUND);
    t.add_many(executables(), ESCAPE, A_EXECUTE, ESCAPE);
    t.add(0x7f, ESCAPE, A_IGNORE, ESCAPE);
    t.add_many(executables(), OSC_STRING, A_IGNORE, OSC_STRING);
    t.add_many(executables(), CSI_ENTRY, A_EXECUTE, CSI_ENTRY);
    t.add(0x7f, CSI_ENTRY, A_IGNORE, CSI_ENTRY);
    t.add_many(executables(), CSI_PARAM, A_EXECUTE, CSI_PARAM);
    t.add(0x7f, CSI_PARAM, A_IGNORE, CSI_PARAM);
    t.add_many(executables(), CSI_IGNORE, A_EXECUTE, CSI_IGNORE);
    t.add_many(executables(), CSI_INTERMEDIATE, A_EXECUTE, CSI_INTERMEDIATE);
    t.add(0x7f, CSI_INTERMEDIATE, A_IGNORE, CSI_INTERMEDIATE);
    t.add_many(
        executables(),
        ESCAPE_INTERMEDIATE,
        A_EXECUTE,
        ESCAPE_INTERMEDIATE,
    );
    t.add(0x7f, ESCAPE_INTERMEDIATE, A_IGNORE, ESCAPE_INTERMEDIATE);
    // osc
    t.add(0x5d, ESCAPE, A_OSC_START, OSC_STRING);
    t.add_many(printables(), OSC_STRING, A_OSC_PUT, OSC_STRING);
    t.add(0x7f, OSC_STRING, A_OSC_PUT, OSC_STRING);
    t.add_many(
        [0x9c, 0x1b, 0x18, 0x1a, 0x07],
        OSC_STRING,
        A_OSC_END,
        GROUND,
    );
    t.add_many(0x1c..0x20, OSC_STRING, A_IGNORE, OSC_STRING);
    // sos/pm/apc
    t.add_many([0x58, 0x5e, 0x5f], ESCAPE, A_IGNORE, SOS_PM_APC_STRING);
    t.add_many(printables(), SOS_PM_APC_STRING, A_IGNORE, SOS_PM_APC_STRING);
    t.add_many(
        executables(),
        SOS_PM_APC_STRING,
        A_IGNORE,
        SOS_PM_APC_STRING,
    );
    t.add(0x9c, SOS_PM_APC_STRING, A_IGNORE, GROUND);
    t.add(0x7f, SOS_PM_APC_STRING, A_IGNORE, SOS_PM_APC_STRING);
    // csi
    t.add(0x5b, ESCAPE, A_CLEAR, CSI_ENTRY);
    t.add_many(0x40..0x7f, CSI_ENTRY, A_CSI_DISPATCH, GROUND);
    t.add_many(0x30..0x3c, CSI_ENTRY, A_PARAM, CSI_PARAM);
    t.add_many([0x3c, 0x3d, 0x3e, 0x3f], CSI_ENTRY, A_COLLECT, CSI_PARAM);
    t.add_many(0x30..0x3c, CSI_PARAM, A_PARAM, CSI_PARAM);
    t.add_many(0x40..0x7f, CSI_PARAM, A_CSI_DISPATCH, GROUND);
    t.add_many([0x3c, 0x3d, 0x3e, 0x3f], CSI_PARAM, A_IGNORE, CSI_IGNORE);
    t.add_many(0x20..0x40, CSI_IGNORE, A_IGNORE, CSI_IGNORE);
    t.add(0x7f, CSI_IGNORE, A_IGNORE, CSI_IGNORE);
    t.add_many(0x40..0x7f, CSI_IGNORE, A_IGNORE, GROUND);
    t.add_many(0x20..0x30, CSI_ENTRY, A_COLLECT, CSI_INTERMEDIATE);
    t.add_many(0x20..0x30, CSI_INTERMEDIATE, A_COLLECT, CSI_INTERMEDIATE);
    t.add_many(0x30..0x40, CSI_INTERMEDIATE, A_IGNORE, CSI_IGNORE);
    t.add_many(0x40..0x7f, CSI_INTERMEDIATE, A_CSI_DISPATCH, GROUND);
    t.add_many(0x20..0x30, CSI_PARAM, A_COLLECT, CSI_INTERMEDIATE);
    // esc_intermediate
    t.add_many(0x20..0x30, ESCAPE, A_COLLECT, ESCAPE_INTERMEDIATE);
    t.add_many(
        0x20..0x30,
        ESCAPE_INTERMEDIATE,
        A_COLLECT,
        ESCAPE_INTERMEDIATE,
    );
    t.add_many(0x30..0x7f, ESCAPE_INTERMEDIATE, A_ESC_DISPATCH, GROUND);
    t.add_many(0x30..0x50, ESCAPE, A_ESC_DISPATCH, GROUND);
    t.add_many(0x51..0x58, ESCAPE, A_ESC_DISPATCH, GROUND);
    t.add_many([0x59, 0x5a, 0x5c], ESCAPE, A_ESC_DISPATCH, GROUND);
    t.add_many(0x60..0x7f, ESCAPE, A_ESC_DISPATCH, GROUND);
    // dcs
    t.add(0x50, ESCAPE, A_CLEAR, DCS_ENTRY);
    t.add_many(executables(), DCS_ENTRY, A_IGNORE, DCS_ENTRY);
    t.add(0x7f, DCS_ENTRY, A_IGNORE, DCS_ENTRY);
    t.add_many(0x1c..0x20, DCS_ENTRY, A_IGNORE, DCS_ENTRY);
    t.add_many(0x20..0x30, DCS_ENTRY, A_COLLECT, DCS_INTERMEDIATE);
    t.add_many(0x30..0x3c, DCS_ENTRY, A_PARAM, DCS_PARAM);
    t.add_many([0x3c, 0x3d, 0x3e, 0x3f], DCS_ENTRY, A_COLLECT, DCS_PARAM);
    t.add_many(executables(), DCS_IGNORE, A_IGNORE, DCS_IGNORE);
    t.add_many(0x20..0x80, DCS_IGNORE, A_IGNORE, DCS_IGNORE);
    t.add_many(0x1c..0x20, DCS_IGNORE, A_IGNORE, DCS_IGNORE);
    t.add_many(executables(), DCS_PARAM, A_IGNORE, DCS_PARAM);
    t.add(0x7f, DCS_PARAM, A_IGNORE, DCS_PARAM);
    t.add_many(0x1c..0x20, DCS_PARAM, A_IGNORE, DCS_PARAM);
    t.add_many(0x30..0x3c, DCS_PARAM, A_PARAM, DCS_PARAM);
    t.add_many([0x3c, 0x3d, 0x3e, 0x3f], DCS_PARAM, A_IGNORE, DCS_IGNORE);
    t.add_many(0x20..0x30, DCS_PARAM, A_COLLECT, DCS_INTERMEDIATE);
    t.add_many(executables(), DCS_INTERMEDIATE, A_IGNORE, DCS_INTERMEDIATE);
    t.add(0x7f, DCS_INTERMEDIATE, A_IGNORE, DCS_INTERMEDIATE);
    t.add_many(0x1c..0x20, DCS_INTERMEDIATE, A_IGNORE, DCS_INTERMEDIATE);
    t.add_many(0x20..0x30, DCS_INTERMEDIATE, A_COLLECT, DCS_INTERMEDIATE);
    t.add_many(0x30..0x40, DCS_INTERMEDIATE, A_IGNORE, DCS_IGNORE);
    t.add_many(0x40..0x7f, DCS_INTERMEDIATE, A_DCS_HOOK, DCS_PASSTHROUGH);
    t.add_many(0x40..0x7f, DCS_PARAM, A_DCS_HOOK, DCS_PASSTHROUGH);
    t.add_many(0x40..0x7f, DCS_ENTRY, A_DCS_HOOK, DCS_PASSTHROUGH);
    t.add_many(executables(), DCS_PASSTHROUGH, A_DCS_PUT, DCS_PASSTHROUGH);
    t.add_many(printables(), DCS_PASSTHROUGH, A_DCS_PUT, DCS_PASSTHROUGH);
    t.add(0x7f, DCS_PASSTHROUGH, A_IGNORE, DCS_PASSTHROUGH);
    t.add_many(
        [0x1b, 0x9c, 0x18, 0x1a],
        DCS_PASSTHROUGH,
        A_DCS_UNHOOK,
        GROUND,
    );
    // unicode
    let non_ascii = NON_ASCII_PRINTABLE as usize;
    t.add(non_ascii, GROUND, A_PRINT, GROUND);
    t.add(non_ascii, OSC_STRING, A_OSC_PUT, OSC_STRING);
    t.add(non_ascii, CSI_IGNORE, A_IGNORE, CSI_IGNORE);
    t.add(non_ascii, DCS_IGNORE, A_IGNORE, DCS_IGNORE);
    t.add(non_ascii, DCS_PASSTHROUGH, A_DCS_PUT, DCS_PASSTHROUGH);
    t
}

/// Actions the input handler performs for parsed sequences.
pub trait Perform {
    fn print(&mut self, data: &[u32]);
    fn execute(&mut self, code: u32);
    /// `ident` is `collect << 8 | final` as in xterm.
    fn csi_dispatch(&mut self, ident: u32, params: &Params);
    fn esc_dispatch(&mut self, ident: u32);
    /// A completed OSC whose numeric id parsed; `data` is `None` when the
    /// payload exceeded xterm's limit.
    fn osc_dispatch(&mut self, id: i64, data: Option<&str>);
    /// The parser cleared xterm's `precedingJoinState`.
    fn clear_join_state(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OscState {
    Start,
    Id,
    Payload,
    Abort,
}

#[derive(Debug)]
pub struct Parser {
    state: u8,
    params: Params,
    collect: u32,
    osc_state: OscState,
    osc_id: i64,
    osc_data: String,
    osc_units: usize,
    osc_hit_limit: bool,
}

impl Default for Parser {
    fn default() -> Self {
        let mut params = Params::default();
        params.add_param(0);
        Self {
            state: GROUND,
            params,
            collect: 0,
            osc_state: OscState::Start,
            osc_id: -1,
            osc_data: String::new(),
            osc_units: 0,
            osc_hit_limit: false,
        }
    }
}

impl Parser {
    fn clear_params(&mut self) {
        self.params.reset();
        self.params.add_param(0);
        self.collect = 0;
    }

    fn osc_reset(&mut self) {
        self.osc_state = OscState::Start;
        self.osc_id = -1;
        self.osc_data.clear();
        self.osc_units = 0;
        self.osc_hit_limit = false;
    }

    fn osc_put(&mut self, data: &[u32]) {
        let mut data = data;
        if self.osc_state == OscState::Abort {
            return;
        }
        if self.osc_state == OscState::Id {
            while let Some((&code, rest)) = data.split_first() {
                data = rest;
                if code == 0x3b {
                    self.osc_state = OscState::Payload;
                    break;
                }
                if !(0x30..=0x39).contains(&code) {
                    self.osc_state = OscState::Abort;
                    return;
                }
                if self.osc_id == -1 {
                    self.osc_id = 0;
                }
                self.osc_id = self
                    .osc_id
                    .saturating_mul(10)
                    .saturating_add(i64::from(code - 48));
            }
        }
        if self.osc_state == OscState::Payload && !data.is_empty() && !self.osc_hit_limit {
            for &code in data {
                let ch = char::from_u32(code).unwrap_or('\u{FFFD}');
                self.osc_units += ch.len_utf16();
                self.osc_data.push(ch);
            }
            if self.osc_units > PAYLOAD_LIMIT {
                self.osc_data.clear();
                self.osc_hit_limit = true;
            }
        }
    }

    fn osc_end(&mut self, success: bool, perform: &mut impl Perform) {
        if self.osc_state != OscState::Start && self.osc_state != OscState::Abort && success {
            let data = (!self.osc_hit_limit).then_some(self.osc_data.as_str());
            perform.osc_dispatch(self.osc_id, data);
        }
        self.osc_reset();
    }

    /// Parse UTF-32 code points (xterm `parse`, synchronous handlers only).
    pub fn parse(&mut self, data: &[u32], perform: &mut impl Perform) {
        let table = &table().0;
        let length = data.len();
        let mut i = 0;
        while i < length {
            let mut code = data[i];
            let column = if code < 0xa0 {
                code
            } else {
                NON_ASCII_PRINTABLE
            } as usize;
            let mut transition = table[(usize::from(self.state) << 8) | column];
            match transition >> 4 {
                A_PRINT => {
                    let mut j = i + 1;
                    while j < length {
                        code = data[j];
                        if code < 0x20 || (code > 0x7e && code < NON_ASCII_PRINTABLE) {
                            break;
                        }
                        j += 1;
                    }
                    perform.print(&data[i..j]);
                    i = j - 1;
                }
                A_EXECUTE => {
                    perform.execute(code);
                    perform.clear_join_state();
                }
                A_IGNORE | A_ERROR => {}
                A_CSI_DISPATCH => {
                    perform.csi_dispatch((self.collect << 8) | code, &self.params);
                    perform.clear_join_state();
                }
                A_PARAM => {
                    loop {
                        match code {
                            0x3b => self.params.add_param(0),
                            0x3a => self.params.add_sub_param(-1),
                            _ => self.params.add_digit(code as i32 - 48),
                        }
                        i += 1;
                        if i >= length {
                            break;
                        }
                        code = data[i];
                        if !(code > 0x2f && code < 0x3c) {
                            break;
                        }
                    }
                    i -= 1;
                }
                A_COLLECT => {
                    self.collect = (self.collect << 8) | code;
                }
                A_ESC_DISPATCH => {
                    let ident = (self.collect << 8) | code;
                    perform.esc_dispatch(ident);
                    perform.clear_join_state();
                }
                A_CLEAR => self.clear_params(),
                A_DCS_HOOK => {}
                A_DCS_PUT => {
                    let mut j = i + 1;
                    while j < length {
                        code = data[j];
                        if code == 0x18
                            || code == 0x1a
                            || code == 0x1b
                            || (code > 0x7f && code < NON_ASCII_PRINTABLE)
                        {
                            break;
                        }
                        j += 1;
                    }
                    i = j - 1;
                }
                A_DCS_UNHOOK => {
                    if code == 0x1b {
                        transition |= ESCAPE;
                    }
                    self.clear_params();
                    perform.clear_join_state();
                }
                A_OSC_START => {
                    self.osc_reset();
                    self.osc_state = OscState::Id;
                }
                A_OSC_PUT => {
                    let mut j = i + 1;
                    while j < length {
                        code = data[j];
                        if code < 0x20 || (code > 0x7f && code < NON_ASCII_PRINTABLE) {
                            break;
                        }
                        j += 1;
                    }
                    self.osc_put(&data[i..j]);
                    i = j - 1;
                }
                A_OSC_END => {
                    self.osc_end(code != 0x18 && code != 0x1a, perform);
                    if code == 0x1b {
                        transition |= ESCAPE;
                    }
                    self.clear_params();
                    perform.clear_join_state();
                }
                _ => {}
            }
            self.state = transition & 15;
            i += 1;
        }
    }
}
