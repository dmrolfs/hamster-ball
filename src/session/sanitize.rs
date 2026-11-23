// ABOUTME: Removes from the agent's output the escape sequences whose reply carries text the agent chose.
// ABOUTME: A byte-stream state machine (the VT parser of Paul Williams) that also drops C1 controls, so the terminal and hb agree.
//! Filtering what the agent may ask the user's terminal (design D67).
//!
//! The agent's output reaches the user's real terminal. Some terminals answer some queries with
//! text the asker supplied: a title report returns the title the agent just set, a status-string
//! request returns the request, and so on. The answer is typed into the terminal's input as if the
//! user had typed it (CVE-2003-0063 xterm, CVE-2022-45872 iTerm2, CVE-2024-56803 Ghostty). While
//! `hb` runs, that input goes back to the agent, which is harmless. The answer is dangerous when
//! it arrives after `hb` has given the terminal back to the shell.
//!
//! Terminal bugs of this kind keep appearing in new places (kitty's colour-control and DCS
//! handlers and iTerm2's graphics-protocol error replies were all reported in 2026), so the filter
//! does not try to name the bad sequences. For the string sequences, where the bugs are, it names the
//! good ones and drops the rest:
//!
//! - OSC passes only for the numbers agents use: title and icon (0, 1, 2), colours and palette
//!   (4, 10 to 12, 104, 110 to 112), working directory (7), hyperlinks (8), notifications (9, 99, 777),
//!   shell-integration marks (133) and clipboard *writes* (52). A clipboard read (`?`) is dropped.
//! - DCS passes only for sixel graphics (`DCS ... q`, no intermediate) and synchronized output
//!   (`DCS = 1 s`, `DCS = 2 s`). Status-string and capability requests (`$ q`, `+ q`) are among
//!   those dropped.
//! - APC, PM and SOS are dropped. (APC carries the kitty graphics protocol, whose error replies echo
//!   what the sender wrote.)
//!
//! For CSI, whose replies are fixed numbers except one, it removes the one: `CSI 20 t` and
//! `CSI 21 t` (report the icon label or the window title). Device attributes, cursor position, mode
//! reports and colour queries pass, because terminal programs need them.
//!
//! Also removed: `ENQ` (answerback) and every C1 control, in both the single-byte and the UTF-8
//! spelling, because terminals differ on whether they honour them.
//!
//! The parser follows the DEC state machine that terminals reverse-engineered from the VT500
//! series, because a filter that disagrees with the terminal about where a sequence ends can be
//! walked around. Where terminals differ the filter takes the safe side: an oversized or
//! malformed sequence is dropped whole.

use std::mem;

/// The most bytes of one sequence's start the filter will hold while it decides.
const MAX_HELD: usize = 64;
/// The longest OSC number it reads (`5522`, `1337`, `52`, `50` and room for leading zeros).
const MAX_OSC_NUMBER: usize = 8;
/// The longest first field of an `OSC 52` (the clipboard names) it will wait to see the end of.
const MAX_OSC_PREFIX: usize = 32;

const ESC: u8 = 0x1b;
const CAN: u8 = 0x18;
const SUB: u8 = 0x1a;
const BEL: u8 = 0x07;
const ENQ: u8 = 0x05;
const DEL: u8 = 0x7f;

/// What the second stage is in the middle of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ground,
    /// After `ESC`: waiting for the byte that says what kind of sequence this is.
    Escape,
    /// `ESC` and intermediate bytes (`ESC ( B`).
    EscapeIntermediate,
    /// An escape sequence with too many intermediates: swallowed up to its final byte.
    EscapeIgnore,
    /// After `CSI`: collecting parameters, intermediates and the final byte. Held until decided.
    Csi,
    /// A CSI that is too long or malformed: swallowed up to its final byte.
    CsiIgnore,
    /// After `DCS`: the header up to its final byte. Held until decided.
    DcsHeader,
    /// Inside a DCS that was let through.
    DcsPass,
    /// Inside a DCS (or PM, SOS, ...) that is being removed, up to its terminator.
    StringDrop,
    /// After `OSC`: the first bytes, held until the filter knows which OSC it is.
    OscHead,
    /// Inside an OSC (or APC) that was let through.
    StringPass,
    /// An `ESC` arrived inside a string that was let through: the string ends, and what follows
    /// decides whether this was its terminator (`ESC \`) or the start of something else.
    StringEscape,
}

/// Whether the agent may set the user's clipboard (`OSC 52` with data).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ClipboardPolicy {
    /// Writes pass. Most terminals apply their own policy to them.
    #[default]
    Allow,
    /// Writes are removed.
    Deny,
}

/// What the agent did with the clipboard, as the filter saw it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClipboardUse {
    /// Writes that were let through.
    pub allowed: usize,
    /// Writes that were removed because the policy denies them.
    pub blocked: usize,
}

impl std::ops::Add for ClipboardUse {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            allowed: self.allowed + other.allowed,
            blocked: self.blocked + other.blocked,
        }
    }
}

/// A streaming filter. Feed it the agent's output in any chunking; the result does not depend on it.
#[derive(Debug, Clone)]
pub struct Sanitizer {
    /// The bytes of a multi-byte character seen so far, and how many more it needs.
    character: Vec<u8>,
    needed: usize,
    mode: Mode,
    /// Bytes of the sequence being decided, not yet sent on.
    held: Vec<u8>,
    /// Whether the terminal has been sent the start of a sequence that it has not seen the end of.
    open: bool,
    clipboard: ClipboardPolicy,
    used: ClipboardUse,
}

impl Default for Sanitizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Sanitizer {
    /// A filter at the start of a stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            character: Vec::with_capacity(4),
            needed: 0,
            mode: Mode::Ground,
            held: Vec::new(),
            open: false,
            clipboard: ClipboardPolicy::Allow,
            used: ClipboardUse::default(),
        }
    }

    /// Filters `input` and appends what may go on to `out`.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) {
        for &byte in input {
            self.byte(byte, out);
        }
    }

    /// A filter with the given clipboard policy.
    #[must_use]
    pub fn with_clipboard(clipboard: ClipboardPolicy) -> Self {
        Self {
            clipboard,
            ..Self::new()
        }
    }

    /// What the agent has done with the clipboard so far.
    #[must_use]
    pub fn clipboard_use(&self) -> ClipboardUse {
        self.used
    }

    /// How many clipboard writes have been let through so far.
    #[must_use]
    pub fn clipboard_writes(&self) -> usize {
        self.used.allowed
    }

    /// Whether the terminal has been left in the middle of a sequence. `hb` cancels it at the end.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.open
    }

    // ---- stage 1: strict UTF-8, so no byte means a control to the terminal and not to the filter ----

    fn byte(&mut self, byte: u8, out: &mut Vec<u8>) {
        if self.needed > 0 {
            if is_continuation(byte, self.character.first().copied(), self.character.len()) {
                self.character.push(byte);
                self.needed -= 1;
                if self.needed == 0 {
                    self.character_done(out);
                }
                return;
            }
            // The character was cut short or is malformed: drop it and read this byte afresh.
            self.character.clear();
            self.needed = 0;
        }
        match byte {
            0x00..=0x7f => self.control(byte, out),
            0xc2..=0xdf => self.begin_character(byte, 1),
            0xe0..=0xef => self.begin_character(byte, 2),
            0xf0..=0xf4 => self.begin_character(byte, 3),
            // A raw C1 control, a stray continuation byte, or a byte that cannot be in UTF-8
            // (0xC0, 0xC1, 0xF5 to 0xFF; a lenient decoder reads those as controls or overlong forms).
            _ => {}
        }
    }

    fn begin_character(&mut self, lead: u8, more: usize) {
        self.character.clear();
        self.character.push(lead);
        self.needed = more;
    }

    /// A whole, valid character. A C1 control (U+0080 to U+009F) is dropped. Anything else is text,
    /// which means something only in the ground state and inside a string that was let through.
    fn character_done(&mut self, out: &mut Vec<u8>) {
        let character = mem::take(&mut self.character);
        if character.len() == 2 && character[0] == 0xc2 && character[1] < 0xa0 {
            return;
        }
        match self.mode {
            Mode::Ground => out.extend_from_slice(&character),
            Mode::DcsPass | Mode::StringPass => out.extend_from_slice(&character),
            // Anywhere else text is not allowed inside the sequence. It is dropped, as a terminal
            // that ignores it would, and a sequence that cannot be completed is dropped with it.
            _ => {}
        }
        self.character = character;
        self.character.clear();
    }

    // ---- stage 2: the escape sequence machine ----

    /// Handles one byte that is not a C1 control.
    fn control(&mut self, byte: u8, out: &mut Vec<u8>) {
        // These end whatever is going on, in every state.
        match byte {
            CAN | SUB => {
                // They cancel a string at the terminal too, so they are sent on once, as they are.
                self.held.clear();
                self.mode = Mode::Ground;
                self.open = false;
                out.push(byte);
                return;
            }
            ESC => {
                if self.mode == Mode::StringEscape {
                    // The ESC before this one already ended the string; give the terminal its ST.
                    out.extend_from_slice(&[ESC, b'\\']);
                    self.open = false;
                }
                self.escape();
                return;
            }
            _ => {}
        }
        match self.mode {
            Mode::Ground => ground(byte, out),
            Mode::Escape => self.after_escape(byte, out),
            Mode::EscapeIntermediate => self.escape_intermediate(byte, out),
            Mode::EscapeIgnore => {
                if (0x30..=0x7e).contains(&byte) {
                    self.mode = Mode::Ground;
                }
            }
            Mode::Csi => self.csi(byte, out),
            Mode::CsiIgnore => {
                if (0x40..=0x7e).contains(&byte) {
                    self.mode = Mode::Ground;
                }
            }
            Mode::DcsHeader => self.dcs_header(byte, out),
            Mode::DcsPass | Mode::StringPass => self.pass_string(byte, out),
            Mode::StringEscape => {
                // The string ends here, whichever way. If this is the `\` of `ESC \` that is its terminator.
                // Otherwise the filter ends the string itself, so the terminal never sees a
                // string cut off by a new sequence (terminals disagree about what that means).
                out.extend_from_slice(&[ESC, b'\\']);
                self.open = false;
                self.mode = Mode::Ground;
                if byte != b'\\' {
                    self.escape();
                    self.control(byte, out);
                }
            }
            Mode::StringDrop => {
                if byte == BEL {
                    self.mode = Mode::Ground;
                }
            }
            Mode::OscHead => self.osc_head(byte, out),
        }
    }

    /// `ESC` arrived. It starts a new sequence, and ends a string if one is open.
    fn escape(&mut self) {
        self.held.clear();
        self.mode = match self.mode {
            Mode::DcsPass | Mode::StringPass => Mode::StringEscape,
            _ => Mode::Escape,
        };
    }

    /// Sends what was held, and marks the terminal as having a sequence open or not.
    fn release(&mut self, out: &mut Vec<u8>, still_open: bool) {
        out.append(&mut self.held);
        self.open = still_open;
    }

    fn after_escape(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            b'[' => {
                self.held.clear();
                self.held.extend_from_slice(&[ESC, byte]);
                self.mode = Mode::Csi;
            }
            b'P' => {
                self.held.clear();
                self.held.extend_from_slice(&[ESC, byte]);
                self.mode = Mode::DcsHeader;
            }
            b']' => {
                self.held.clear();
                self.held.extend_from_slice(&[ESC, byte]);
                self.mode = Mode::OscHead;
            }
            b'_' | b'X' | b'^' => {
                // APC, SOS and PM. APC carries the kitty graphics protocol, whose replies echo what
                // the sender wrote; the others have no use, and terminals disagree about them.
                self.mode = Mode::StringDrop;
            }
            b'\\' => {
                // A string terminator. If it ended a string that was removed it goes with it, and
                // a bare one is harmless.
                self.mode = Mode::Ground;
            }
            0x20..=0x2f => {
                self.held.clear();
                self.held.extend_from_slice(&[ESC, byte]);
                self.mode = Mode::EscapeIntermediate;
            }
            0x30..=0x7e => {
                out.extend_from_slice(&[ESC, byte]);
                self.mode = Mode::Ground;
                self.open = false;
            }
            // A control character inside an escape sequence runs at once, as it does for the terminal.
            // (DEL is ignored there.)
            _ => ground_control(byte, out),
        }
    }

    fn escape_intermediate(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            0x20..=0x2f => {
                if self.held.len() < MAX_HELD {
                    self.held.push(byte);
                } else {
                    self.held.clear();
                    self.mode = Mode::EscapeIgnore;
                }
            }
            0x30..=0x7e => {
                self.held.push(byte);
                self.release(out, false);
                self.mode = Mode::Ground;
            }
            _ => ground_control(byte, out),
        }
    }

    fn csi(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            0x20..=0x3f => {
                if self.held.len() < MAX_HELD {
                    self.held.push(byte);
                } else {
                    self.held.clear();
                    self.mode = Mode::CsiIgnore;
                }
            }
            0x40..=0x7e => {
                self.held.push(byte);
                if is_title_report(&self.held) {
                    self.held.clear();
                } else {
                    self.release(out, false);
                }
                self.mode = Mode::Ground;
            }
            _ => ground_control(byte, out),
        }
    }

    fn dcs_header(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            0x20..=0x3f => {
                if self.held.len() < MAX_HELD {
                    self.held.push(byte);
                } else {
                    self.held.clear();
                    self.mode = Mode::StringDrop;
                }
            }
            0x40..=0x7e => {
                self.held.push(byte);
                if is_allowed_dcs(&self.held) {
                    self.release(out, true);
                    self.mode = Mode::DcsPass;
                } else {
                    self.held.clear();
                    self.mode = Mode::StringDrop;
                }
            }
            _ => ground_control(byte, out),
        }
    }

    fn osc_head(&mut self, byte: u8, out: &mut Vec<u8>) {
        if byte == BEL {
            // An OSC that ended before it said which one it is: not one the filter allows.
            self.held.clear();
            self.mode = Mode::Ground;
            return;
        }
        // Any other control is not a digit or a separator, so `decide_osc` removes the OSC.
        self.held.push(byte);
        let body = &self.held[2..];
        match decide_osc(body) {
            OscVerdict::Drop => {
                self.held.clear();
                self.mode = Mode::StringDrop;
            }
            OscVerdict::Pass => {
                self.release(out, true);
                self.mode = Mode::StringPass;
            }
            OscVerdict::PassClipboard => match self.clipboard {
                ClipboardPolicy::Allow => {
                    self.used.allowed += 1;
                    self.release(out, true);
                    self.mode = Mode::StringPass;
                }
                ClipboardPolicy::Deny => {
                    self.used.blocked += 1;
                    self.held.clear();
                    self.mode = Mode::StringDrop;
                }
            },
            // `decide_osc` drops what it cannot place within a bounded prefix, so this stays short.
            OscVerdict::Undecided => {}
        }
    }

    fn pass_string(&mut self, byte: u8, out: &mut Vec<u8>) {
        match byte {
            BEL => {
                out.push(byte);
                self.mode = Mode::Ground;
                self.open = false;
            }
            DEL => {}
            // The other controls inside a string are ignored by the terminal; they are not passed on
            // so that what the terminal does with them cannot differ from what the filter assumes.
            0x00..=0x1f => {}
            _ => out.push(byte),
        }
    }

    /// What to send when the stream ends: a cancel if the terminal is inside a sequence.
    pub fn finish(&mut self, out: &mut Vec<u8>) {
        let was_open = self.open;
        self.held.clear();
        self.character.clear();
        self.needed = 0;
        self.mode = Mode::Ground;
        self.open = false;
        if was_open {
            out.push(CAN);
        }
    }
}

/// Whether `byte` may follow the bytes of a character started by `lead` and `seen` bytes long.
/// The second byte has narrower ranges after some leads, which excludes overlong forms (a
/// control spelled with extra bytes), surrogates and values above U+10FFFF.
fn is_continuation(byte: u8, lead: Option<u8>, seen: usize) -> bool {
    let range = match (lead, seen) {
        (Some(0xe0), 1) => 0xa0..=0xbf,
        (Some(0xed), 1) => 0x80..=0x9f,
        (Some(0xf0), 1) => 0x90..=0xbf,
        (Some(0xf4), 1) => 0x80..=0x8f,
        _ => 0x80..=0xbf,
    };
    range.contains(&byte)
}

/// A byte in the ground state.
fn ground(byte: u8, out: &mut Vec<u8>) {
    match byte {
        ENQ | DEL => {}
        _ => out.push(byte),
    }
}

/// A C0 control that arrives inside an escape sequence. The terminal runs it at once and carries on
/// with the sequence, and so does the filter.
fn ground_control(byte: u8, out: &mut Vec<u8>) {
    match byte {
        ENQ | DEL => {}
        0x00..=0x1f => out.push(byte),
        _ => {}
    }
}

/// Whether a complete CSI (as bytes, `ESC [` first) is `CSI 20 t` or `CSI 21 t`.
fn is_title_report(sequence: &[u8]) -> bool {
    let body = &sequence[2..];
    let Some((&last, params)) = body.split_last() else {
        return false;
    };
    // Plain parameters only: a private marker (`? > < =`) or an intermediate makes it another
    // sequence.
    if last != b't'
        || !params
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b';' || *b == b':')
    {
        return false;
    }
    let first: Vec<u8> = params
        .iter()
        .copied()
        .take_while(|b| *b != b';' && *b != b':')
        .collect();
    let number = first.iter().fold(0u32, |n, d| {
        n.saturating_mul(10).saturating_add(u32::from(d - b'0'))
    });
    matches!(number, 20 | 21)
}

/// Whether a complete DCS header (`ESC P` first) is one the filter lets through: sixel graphics
/// (final `q`, no intermediate) or synchronized output (`= 1 s` or `= 2 s`).
fn is_allowed_dcs(header: &[u8]) -> bool {
    let body = &header[2..];
    let Some((&last, before)) = body.split_last() else {
        return false;
    };
    let plain_parameters = |bytes: &[u8]| bytes.iter().all(|b| b.is_ascii_digit() || *b == b';');
    match last {
        b'q' => plain_parameters(before),
        b's' => before
            .strip_prefix(b"=")
            .is_some_and(|rest| rest == b"1" || rest == b"2"),
        _ => false,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OscVerdict {
    Drop,
    Pass,
    /// Passes, and is a write to the clipboard.
    PassClipboard,
    Undecided,
}

/// The OSC numbers that pass (see the module documentation). 52 passes only as a write.
const ALLOWED_OSC: [u32; 17] = [
    0, 1, 2, 4, 7, 8, 9, 10, 11, 12, 99, 104, 110, 111, 112, 133, 777,
];

/// Decides what to do with an OSC from the start of its body (after `ESC ]`).
fn decide_osc(body: &[u8]) -> OscVerdict {
    let number_len = body.iter().take_while(|b| b.is_ascii_digit()).count();
    if number_len > MAX_OSC_NUMBER {
        return OscVerdict::Drop;
    }
    let Some(&next) = body.get(number_len) else {
        return OscVerdict::Undecided;
    };
    if number_len == 0 || next != b';' {
        // Not a number followed by a separator. Terminals read these differently.
        return OscVerdict::Drop;
    }
    let value = body[..number_len].iter().fold(0u32, |n, d| {
        n.saturating_mul(10).saturating_add(u32::from(d - b'0'))
    });
    if value == 52 {
        return decide_clipboard(&body[number_len + 1..]);
    }
    if ALLOWED_OSC.contains(&value) {
        OscVerdict::Pass
    } else {
        OscVerdict::Drop
    }
}

/// `OSC 52 ; Pc ; Pd`: a `?` as the data asks for the clipboard back.
fn decide_clipboard(rest: &[u8]) -> OscVerdict {
    let Some(separator) = rest.iter().position(|b| *b == b';') else {
        return if rest.len() > MAX_OSC_PREFIX {
            OscVerdict::Drop
        } else {
            OscVerdict::Undecided
        };
    };
    match rest.get(separator + 1) {
        None => OscVerdict::Undecided,
        Some(b'?') => OscVerdict::Drop,
        Some(_) => OscVerdict::PassClipboard,
    }
}

/// The input-affecting terminal modes, switched off, and a cancel for any sequence left open.
///
/// Mouse reporting, focus events and bracketed paste make the terminal type text into the shell
/// without the user pressing a key, so an agent that ends with one of them on would leave the
/// shell receiving it. The shell turns on the ones it uses (bracketed paste) at its next prompt.
pub const MODE_RESET: &[u8] = b"\x18\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?2004l\x1b[?1l\x1b>\x1b[?25h";

/// Filters a whole input at once, for tests.
#[cfg(test)]
fn run(input: &[u8]) -> Vec<u8> {
    let mut filter = Sanitizer::new();
    let mut out = Vec::new();
    filter.feed(input, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn clean(input: &[u8]) -> Vec<u8> {
        run(input)
    }

    // ---- what is removed ----

    #[test]
    fn a_title_report_request_is_removed_in_every_spelling() {
        for sequence in [
            &b"\x1b[21t"[..],
            b"\x1b[20t",
            b"\x1b[21;1t",
            b"\x1b[0021t",
            b"\x1b[21:5t",
            b"\x1b[020t",
        ] {
            assert_eq!(clean(sequence), b"", "{sequence:?}");
        }
    }

    #[test]
    fn the_surrounding_text_of_a_removed_sequence_stays() {
        assert_eq!(clean(b"before\x1b[21tafter"), b"beforeafter");
    }

    #[test]
    fn other_window_operations_are_left_alone() {
        for sequence in [
            &b"\x1b[18t"[..],
            b"\x1b[19t",
            b"\x1b[22;0t",
            b"\x1b[23;0t",
            b"\x1b[8;24;80t",
            b"\x1b[?21t",
            b"\x1b[>21t",
            b"\x1b[21 t",
        ] {
            assert_eq!(clean(sequence), sequence, "{sequence:?}");
        }
    }

    #[test]
    fn a_removed_string_ends_at_either_terminator_and_not_before() {
        for sequence in [
            &b"\x1bP$qm\x1b\\"[..],
            b"\x1bP$q\"p\x1b\\",
            b"\x1bP+q544e\x1b\\",
            b"\x1bP$qm\x07",
        ] {
            let out = clean(sequence);
            assert!(
                !out.windows(2).any(|w| w == b"$q"),
                "{sequence:?} -> {out:?}"
            );
            assert!(
                !out.windows(2).any(|w| w == b"+q"),
                "{sequence:?} -> {out:?}"
            );
        }
        assert_eq!(clean(b"a\x1bP$qm\x1b\\b"), b"ab");
    }

    #[test]
    fn a_clipboard_read_is_removed_and_a_clipboard_write_is_not() {
        assert_eq!(clean(b"\x1b]52;c;?\x07"), b"");
        assert_eq!(clean(b"\x1b]52;;?\x1b\\"), b"");
        let write = b"\x1b]52;c;aGVsbG8=\x07";
        assert_eq!(clean(write), write);
    }

    #[test]
    fn only_the_osc_numbers_agents_use_pass_and_the_rest_are_removed() {
        for number in [
            0, 1, 2, 4, 7, 8, 9, 10, 11, 12, 99, 104, 110, 111, 112, 133, 777,
        ] {
            let sequence = format!("\x1b]{number};x\x07");
            assert_eq!(
                clean(sequence.as_bytes()),
                sequence.as_bytes(),
                "OSC {number}"
            );
        }
        // Font query (xterm), kitty colour control (CVE-2026-54057) and clipboard protocol,
        // iTerm2's own requests, and numbers nobody has a reason to send.
        for number in [3, 5, 6, 13, 21, 50, 66, 5113, 5522, 1337, 9999, 12345678] {
            let sequence = format!("\x1b]{number};x\x07");
            assert_eq!(clean(sequence.as_bytes()), b"", "OSC {number}");
        }
        assert_eq!(clean(b"\x1b]1337;ReportCellSize\x07"), b"");
        assert_eq!(clean(b"\x1b]1337;RequestUpload=format=tgz\x07"), b"");
    }

    #[test]
    fn an_osc_that_is_not_a_number_and_a_separator_is_removed() {
        for sequence in [
            &b"\x1b]x\x07"[..],
            b"\x1b];\x07",
            b"\x1b]0x\x07",
            b"\x1b]\x07",
            b"\x1b]00000000000;x\x07",
        ] {
            let out = clean(sequence);
            assert!(out.is_empty(), "{sequence:?} -> {out:?}");
        }
    }

    #[test]
    fn dcs_apc_pm_and_sos_are_removed_except_sixel_and_synchronized_output() {
        // kitty's DCS handlers (CVE-2026-72913), tmux control mode, DECRQSS, XTGETTCAP, DECUDK.
        for sequence in [
            &b"\x1bP@kitty-cmd{\"cmd\":\"ls\"}\x1b\\"[..],
            b"\x1bP1000p\x1b\\",
            b"\x1bP$qm\x1b\\",
            b"\x1bP+q544e\x1b\\",
            b"\x1bP0;0|17/68656c6c6f\x1b\\",
            b"\x1b_Gi=31,a=q;\x1b\\",
            b"\x1b^private\x1b\\",
            b"\x1bXtext\x1b\\",
        ] {
            assert_eq!(clean(sequence), b"", "{sequence:?}");
        }
        for sequence in [
            &b"\x1bPq#0~\x1b\\"[..],
            b"\x1bP0;1;0q#0~\x1b\\",
            b"\x1bP=2s\x1b\\",
        ] {
            assert_eq!(clean(sequence), sequence, "{sequence:?}");
        }
        assert_eq!(clean(b"\x1bP=3s\x1b\\"), b"");
    }

    #[test]
    fn answerback_pm_sos_and_every_c1_control_are_removed() {
        assert_eq!(clean(b"a\x05b"), b"ab");
        assert_eq!(clean(b"a\x1b^secret\x07b"), b"ab");
        assert_eq!(clean(b"a\x1bXsecret\x07b"), b"ab");
        // 0x9B is CSI, 0x9D is OSC, 0x9C is ST, 0x90 is DCS, as single bytes and as UTF-8.
        assert_eq!(clean(b"a\x9b21tb"), b"a21tb");
        assert_eq!(clean(b"a\xc2\x9b21tb"), b"a21tb");
        assert_eq!(clean(b"a\x9d0;x\x9cb"), b"a0;xb");
        assert_eq!(clean(b"a\x90$qm\x9cb"), b"a$qmb");
    }

    #[test]
    fn bytes_that_are_not_utf8_and_that_a_terminal_might_read_as_controls_are_removed() {
        assert_eq!(clean(b"a\xc0\x9bb"), b"ab");
        assert_eq!(clean(b"a\xc1\x9bb"), b"ab");
        assert_eq!(clean(b"a\xff\xfeb"), b"ab");
    }

    // ---- what passes ----

    #[test]
    fn ordinary_output_passes_byte_for_byte() {
        let samples: [&[u8]; 9] = [
            b"plain text\r\nwith lines\ttabs",
            "unicode: h\u{e9}llo \u{4e16}\u{754c} \u{1f600} \u{a0}\u{ad}".as_bytes(),
            b"\x1b[31mred\x1b[0m \x1b[1;38;2;1;2;3mx\x1b[m",
            b"\x1b[2J\x1b[H\x1b[10;20H\x1b[?25l\x1b[?1049h\x1b[?1049l",
            b"\x1b]0;a title\x07\x1b]2;another\x1b\\",
            b"\x1b]8;;https://example.com\x1b\\link\x1b]8;;\x1b\\",
            b"\x1b]11;?\x07\x1b[c\x1b[6n\x1b[>c\x1b[?2026$p",
            b"\x1b]52;c;aGVsbG8=\x07\x1b(B\x1b=\x1b>",
            b"\x1bP0;1;0q\"1;1;4;4#0;2;0;0;0#0~~~~\x1b\\\x1bP=1s\x1b\\",
        ];
        for sample in samples {
            assert_eq!(clean(sample), sample, "{}", String::from_utf8_lossy(sample));
        }
    }

    #[test]
    fn the_queries_terminal_programs_need_are_not_touched() {
        for query in [
            &b"\x1b[c"[..],
            b"\x1b[>c",
            b"\x1b[>q",
            b"\x1b[6n",
            b"\x1b[?6n",
            b"\x1b[?u",
            b"\x1b]10;?\x07",
            b"\x1b]11;?\x1b\\",
            b"\x1b]4;1;?\x07",
            b"\x1b[?2004$p",
            b"\x1b[18t",
        ] {
            assert_eq!(clean(query), query, "{query:?}");
        }
    }

    // ---- clipboard writes are counted ----

    fn writes(input: &[u8]) -> usize {
        let mut filter = Sanitizer::new();
        let mut out = Vec::new();
        filter.feed(input, &mut out);
        filter.clipboard_writes()
    }

    #[test]
    fn each_clipboard_write_that_passes_is_counted_once() {
        assert_eq!(writes(b""), 0);
        assert_eq!(writes(b"\x1b]52;c;aGk=\x07"), 1);
        assert_eq!(writes(b"\x1b]52;c;aGk=\x07text\x1b]52;p;aGk=\x1b\\"), 2);
        // A split sequence is still one write, wherever it is cut.
        let whole = b"x\x1b]52;c;aGVsbG8=\x07y";
        for cut in 0..=whole.len() {
            let mut filter = Sanitizer::new();
            let mut out = Vec::new();
            filter.feed(&whole[..cut], &mut out);
            filter.feed(&whole[cut..], &mut out);
            assert_eq!(filter.clipboard_writes(), 1, "cut at {cut}");
        }
    }

    #[test]
    fn what_the_filter_removes_is_not_counted_as_a_write() {
        assert_eq!(writes(b"\x1b]52;c;?\x07"), 0, "a read");
        assert_eq!(writes(b"\x1b]0;a title\x07\x1b]8;;http://x\x1b\\"), 0);
        assert_eq!(writes(b"\x1b]5522;x\x07"), 0);
        assert_eq!(writes(b"\x1b]52;c\x07"), 0, "no data");
    }

    // ---- the clipboard policy ----

    fn denying(input: &[u8]) -> (Vec<u8>, ClipboardUse) {
        let mut filter = Sanitizer::with_clipboard(ClipboardPolicy::Deny);
        let mut out = Vec::new();
        filter.feed(input, &mut out);
        (out, filter.clipboard_use())
    }

    #[test]
    fn with_writes_denied_the_osc_never_reaches_the_terminal_and_the_attempt_is_counted() {
        let (out, used) = denying(b"a\x1b]52;c;aGk=\x07b\x1b]52;p;aGk=\x1b\\c");
        assert_eq!(out, b"abc");
        assert_eq!(
            used,
            ClipboardUse {
                allowed: 0,
                blocked: 2
            }
        );
    }

    #[test]
    fn a_clipboard_read_is_removed_in_either_policy_and_is_not_counted_as_a_write() {
        let (out, used) = denying(b"x\x1b]52;c;?\x07y");
        assert_eq!(out, b"xy");
        assert_eq!(used, ClipboardUse::default());
    }

    #[test]
    fn denying_writes_changes_nothing_else() {
        let (out, used) = denying(b"\x1b]0;title\x07\x1b[31mred\x1b[0m\x1b]8;;u\x1b\\");
        assert_eq!(out, b"\x1b]0;title\x07\x1b[31mred\x1b[0m\x1b]8;;u\x1b\\");
        assert_eq!(used, ClipboardUse::default());
    }

    #[test]
    fn the_default_policy_allows_and_counts_allowed_writes() {
        let mut filter = Sanitizer::new();
        let mut out = Vec::new();
        filter.feed(b"\x1b]52;c;aGk=\x07", &mut out);
        assert_eq!(out, b"\x1b]52;c;aGk=\x07");
        assert_eq!(
            filter.clipboard_use(),
            ClipboardUse {
                allowed: 1,
                blocked: 0
            }
        );
    }

    // ---- ending and aborting sequences ----

    #[test]
    fn an_escape_inside_a_string_ends_it_and_starts_a_new_sequence_as_the_terminal_does() {
        // The title is cut off by the ESC that begins the report request, which is then removed.
        // The filter closes the title with its own terminator, so the terminal is never left to
        // decide what a string cut off by a new sequence means.
        assert_eq!(
            clean(b"\x1b]0;title\x1b[21tafter"),
            b"\x1b]0;title\x1b\\after"
        );
    }

    #[test]
    fn two_escapes_in_a_row_inside_a_string_still_end_it_with_a_terminator() {
        assert_eq!(clean(b"\x1bPq\x1b\x1b0"), b"\x1bPq\x1b\\\x1b0");
        assert_eq!(clean(b"\x1b]0;t\x1b\x1b[21tz"), b"\x1b]0;t\x1b\\z");
        assert_eq!(clean(b"\x1bPq\x1b\x1b\\"), b"\x1bPq\x1b\\");
    }

    #[test]
    fn a_sequence_cut_off_by_cancel_is_dropped() {
        assert_eq!(clean(b"\x1b[21\x18t"), b"\x18t");
        assert_eq!(clean(b"\x1b]52;c;?\x18x"), b"\x18x");
    }

    #[test]
    fn a_half_finished_sequence_is_never_sent_on() {
        let mut filter = Sanitizer::new();
        let mut out = Vec::new();
        filter.feed(b"text\x1b[2", &mut out);
        assert_eq!(out, b"text");
        filter.finish(&mut out);
        assert_eq!(out, b"text");
    }

    #[test]
    fn a_string_left_open_at_the_end_is_cancelled() {
        let mut filter = Sanitizer::new();
        let mut out = Vec::new();
        filter.feed(b"\x1b]0;a title that never ends", &mut out);
        assert!(filter.is_open());
        filter.finish(&mut out);
        assert_eq!(out.last(), Some(&CAN));
        assert!(!filter.is_open());
    }

    #[test]
    fn oversized_sequences_are_dropped_whole() {
        let mut long = b"\x1b[".to_vec();
        long.extend(std::iter::repeat_n(b'1', 200));
        long.extend_from_slice(b"mafter");
        assert_eq!(clean(&long), b"after");
        let mut dcs = b"\x1bP".to_vec();
        dcs.extend(std::iter::repeat_n(b'1', 200));
        dcs.extend_from_slice(b"q\x1b\\z");
        let out = clean(&dcs);
        assert!(out.ends_with(b"z"));
        assert!(out.len() < 20, "{out:?}");
    }

    // ---- strict UTF-8 ----

    #[test]
    fn overlong_surrogate_and_out_of_range_utf8_is_dropped_and_valid_text_is_not() {
        // C0 80 and E0 80 80 are overlong NUL; ED A0 80 is a surrogate; F4 90 80 80 is above U+10FFFF;
        // F0 80 80 80 is an overlong form. A lenient decoder reads some of these as controls.
        for bad in [
            &b"a\xe0\x80\x9bb"[..],
            b"a\xe0\x9f\xbfb",
            b"a\xed\xa0\x80b",
            b"a\xf4\x90\x80\x80b",
            b"a\xf0\x80\x80\x9bb",
            b"a\xf0\x8f\xbf\xbfb",
        ] {
            let out = clean(bad);
            assert!(
                out.starts_with(b"a") && out.ends_with(b"b"),
                "{bad:?} -> {out:?}"
            );
            assert!(out.len() <= 2 + 1, "{bad:?} passed bytes through: {out:?}");
        }
        // The same ranges at their edges are valid and pass.
        for good in [
            "\u{800}",
            "\u{d7ff}",
            "\u{e000}",
            "\u{10000}",
            "\u{10ffff}",
            "\u{a0}",
            "\u{7ff}",
        ] {
            assert_eq!(clean(good.as_bytes()), good.as_bytes(), "{good:?}");
        }
    }

    #[test]
    fn text_inside_a_title_that_passes_is_not_changed() {
        let title = "\u{1b}]0;h\u{e9}llo \u{4e16}\u{754c} \u{1f600}\u{7}";
        assert_eq!(clean(title.as_bytes()), title.as_bytes());
    }

    // ---- controls inside sequences ----

    #[test]
    fn a_control_character_inside_a_sequence_runs_at_once_and_the_sequence_carries_on() {
        assert_eq!(clean(b"\x1b[3\n1m"), b"\n\x1b[31m");
        assert_eq!(clean(b"\x1b(\tB"), b"\t\x1b(B");
        assert_eq!(clean(b"\x1b\rM"), b"\r\x1bM");
        // DEL is ignored inside a sequence, and so is ENQ.
        assert_eq!(clean(b"\x1b[3\x7f1m"), b"\x1b[31m");
        assert_eq!(clean(b"\x1b[3\x051m"), b"\x1b[31m");
        // A space is not a control.
        assert_eq!(clean(b"\x1b[1 q"), b"\x1b[1 q");
    }

    #[test]
    fn a_control_in_the_middle_of_an_osc_number_removes_the_osc() {
        assert_eq!(clean(b"\x1b]5\x012;c;x\x07z"), b"z");
        assert_eq!(clean(b"\x1b]0\x7f;t\x07z"), b"z");
    }

    #[test]
    fn other_controls_inside_a_passed_string_are_not_sent_on_either() {
        assert_eq!(clean(b"\x1b]0;a\nb\x01c\x07"), b"\x1b]0;abc\x07");
        assert_eq!(clean(b"\x1bPq#0\r~\x1b\\"), b"\x1bPq#0~\x1b\\");
    }

    #[test]
    fn delete_inside_a_passed_string_is_not_sent_on() {
        assert_eq!(clean(b"\x1b]0;a\x7fb\x07"), b"\x1b]0;ab\x07");
        assert_eq!(clean(b"\x1bPq#\x7f0\x1b\\"), b"\x1bPq#0\x1b\\");
    }

    // ---- bounds ----

    /// A sequence of `start`, then `count` copies of `filler`, then `end`.
    fn spelled(start: &[u8], filler: u8, count: usize, end: &[u8]) -> Vec<u8> {
        let mut bytes = start.to_vec();
        bytes.extend(std::iter::repeat_n(filler, count));
        bytes.extend_from_slice(end);
        bytes
    }

    #[test]
    fn a_sequence_longer_than_the_hold_limit_is_swallowed_whole_and_one_at_the_limit_is_judged_on_its_own()
     {
        // ESC with intermediates: up to 63 (ESC and 63 is 64 bytes) pass, one more is swallowed.
        let at_limit = spelled(b"\x1b", b'(', 63, b"B");
        assert_eq!(clean(&at_limit), at_limit);
        let over = spelled(b"\x1b", b'(', 64, b"Bafter");
        assert_eq!(clean(&over), b"after");
        // CSI: ESC [ and 62 parameter bytes pass; 63 are swallowed.
        let csi = spelled(b"\x1b[", b'1', 62, b"m");
        assert_eq!(clean(&csi), csi);
        let csi_over = spelled(b"\x1b[", b'1', 63, b"mafter");
        assert_eq!(clean(&csi_over), b"after");
        // DCS header: sixel with 62 parameter bytes passes; 63 is swallowed with its body.
        let sixel = spelled(b"\x1bP", b'1', 62, b"q#0~\x1b\\");
        assert_eq!(clean(&sixel), sixel);
        let sixel_over = spelled(b"\x1bP", b'1', 63, b"q#0~\x1b\\z");
        assert_eq!(clean(&sixel_over), b"z");
        // Several intermediates within the limit are one sequence.
        assert_eq!(clean(b"\x1b(!B"), b"\x1b(!B");
    }

    #[test]
    fn an_osc_that_does_not_name_itself_within_the_limit_is_dropped() {
        // OSC 52 whose first field never ends: 32 characters is the most it waits for.
        let fits = spelled(b"\x1b]52;", b'c', 32, b";aGk=\x07");
        assert_eq!(clean(&fits), fits);
        let too_long = spelled(b"\x1b]52;", b'c', 33, b";aGk=\x07z");
        assert_eq!(clean(&too_long), b"z");
        // The same with a first field that fits is a write and passes.
        assert_eq!(clean(b"\x1b]52;cp;aGk=\x07"), b"\x1b]52;cp;aGk=\x07");
        // Eight digits is a number (leading zeros) and nine is too many.
        assert_eq!(
            clean(b"\x1b]00000052;c;aGk=\x07"),
            b"\x1b]00000052;c;aGk=\x07"
        );
        assert_eq!(clean(b"\x1b]000000052;c;aGk=\x07"), b"");
        assert_eq!(clean(b"\x1b]00000052;c;?\x07"), b"");
    }

    // ---- split input ----

    #[test]
    fn a_sequence_split_between_reads_is_still_removed() {
        let whole = b"x\x1b[21ty\x1b]52;c;?\x07z\xc2\x9bw";
        for split in 0..=whole.len() {
            let mut filter = Sanitizer::new();
            let mut out = Vec::new();
            filter.feed(&whole[..split], &mut out);
            filter.feed(&whole[split..], &mut out);
            assert_eq!(out, b"xyzw", "split at {split}");
        }
    }

    // ---- properties ----

    fn any_bytes() -> impl Strategy<Value = Vec<u8>> {
        // Weighted toward the bytes that matter.
        prop::collection::vec(
            prop_oneof![
                4 => any::<u8>(),
                3 => prop::sample::select(vec![0x1b_u8, b'[', b']', b'P', b'_', b'\\', 0x07, 0x18, 0x1a, 0x9b, 0x9d, 0x9c, 0xc2]),
                3 => prop::sample::select(b"0123456789;:?$+qt".to_vec()),
            ],
            0..120,
        )
    }

    proptest! {
        #[test]
        fn the_result_does_not_depend_on_how_the_input_is_split(
            input in any_bytes(),
            cuts in prop::collection::vec(0usize..120, 0..6),
        ) {
            let whole = clean(&input);
            let mut points: Vec<usize> = cuts.into_iter().map(|c| c.min(input.len())).collect();
            points.sort_unstable();
            let mut filter = Sanitizer::new();
            let mut out = Vec::new();
            let mut start = 0;
            for point in points {
                filter.feed(&input[start..point], &mut out);
                start = point;
            }
            filter.feed(&input[start..], &mut out);
            prop_assert_eq!(out, whole);
        }

        #[test]
        fn filtering_twice_changes_nothing(input in any_bytes()) {
            let once = clean(&input);
            prop_assert_eq!(clean(&once), once);
        }

        #[test]
        fn no_removed_sequence_survives(input in any_bytes()) {
            let out = clean(&input);
            // The filter's own output, read by a second filter, loses nothing: it holds no
            // sequence the filter removes. (Idempotence says the same; this reads it back as text.)
            let text = String::from_utf8_lossy(&out);
            for bad in ["\u{1b}[21t", "\u{1b}[20t", "\u{1b}P$q", "\u{1b}P+q", "\u{1b}]52;c;?", "\u{1b}]50;", "\u{1b}]5522;"] {
                prop_assert!(!text.contains(bad), "{bad:?} in {text:?}");
            }
        }

        #[test]
        fn every_string_the_terminal_is_sent_is_of_an_allowed_kind(input in any_bytes()) {
            let out = clean(&input);
            let mut index = 0;
            while let Some(offset) = out[index..].iter().position(|b| *b == ESC) {
                let at = index + offset;
                let after = &out[at + 1..];
                match after.first() {
                    Some(b']') => {
                        let body = &after[1..];
                        let digits = body.iter().take_while(|b| b.is_ascii_digit()).count();
                        // Its number is complete only if the filter let the whole start through.
                        if body.get(digits) == Some(&b';') && digits > 0 {
                            let number: u32 = std::str::from_utf8(&body[..digits])
                                .ok()
                                .and_then(|t| t.parse().ok())
                                .unwrap_or(u32::MAX);
                            prop_assert!(
                                number == 52 || ALLOWED_OSC.contains(&number),
                                "OSC {number} in {out:?}"
                            );
                            if number == 52 {
                                let data = body[digits + 1..].split(|b| *b == b';').nth(1);
                                prop_assert!(data.is_none_or(|d| d.first() != Some(&b'?')), "{out:?}");
                            }
                        } else {
                            prop_assert!(false, "an OSC with no number in {out:?}");
                        }
                    }
                    Some(b'_' | b'^' | b'X') => prop_assert!(false, "APC, PM or SOS in {out:?}"),
                    Some(b'P') => {
                        let header: Vec<u8> = std::iter::once(ESC)
                            .chain(after.iter().copied().take(20))
                            .collect();
                        let end = header.iter().position(|b| (0x40..=0x7e).contains(b) && *b != b'P');
                        prop_assert!(end.is_some(), "an unfinished DCS header in {out:?}");
                        let header = &header[..=end.unwrap_or(0)];
                        prop_assert!(is_allowed_dcs(header), "DCS {header:?} in {out:?}");
                    }
                    _ => {}
                }
                index = at + 1;
            }
        }

        #[test]
        fn no_c1_control_or_answerback_reaches_the_terminal(input in any_bytes()) {
            let out = clean(&input);
            prop_assert!(!out.contains(&ENQ));
            // Whatever the output is, a decoder that reads it as UTF-8 finds no U+0080..U+009F and
            // no stray byte that is one on its own.
            let mut index = 0;
            while index < out.len() {
                let byte = out[index];
                if byte < 0x80 {
                    index += 1;
                    continue;
                }
                let width = match byte {
                    0xc2..=0xdf => 2,
                    0xe0..=0xef => 3,
                    0xf0..=0xf4 => 4,
                    _ => {
                        prop_assert!(false, "a byte that is not text: {byte:#x} in {out:?}");
                        1
                    }
                };
                if width == 2 && byte == 0xc2 {
                    prop_assert!(out.get(index + 1).is_some_and(|b| *b >= 0xa0), "C1 in {out:?}");
                }
                index += width;
            }
        }

        #[test]
        fn text_without_controls_passes_unchanged(text in "[ -~\u{a0}-\u{2fff}]{0,80}") {
            prop_assert_eq!(clean(text.as_bytes()), text.as_bytes());
        }

        #[test]
        fn it_never_holds_more_than_it_is_allowed_to(input in any_bytes()) {
            let mut filter = Sanitizer::new();
            let mut out = Vec::new();
            for byte in input {
                filter.feed(&[byte], &mut out);
                prop_assert!(filter.held.len() <= MAX_OSC_PREFIX + 4);
            }
        }
    }
}
