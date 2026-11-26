// ABOUTME: InputEncoder: turns the owner's key, paste and mouse events into the bytes an agent's terminal expects, honoring the modes it switched on.
// ABOUTME: Pure functions with no terminal access; the Ctrl-g mode switch lives above this, so everything that reaches here goes to the agent.
//! Input encoding.
//!
//! What a terminal sends for a key depends on modes the program running in it set: application
//! cursor keys, bracketed paste, a mouse protocol. [`InputModes`] carries those from the
//! emulator, and each function here returns the bytes for one event, or `None` when the agent
//! should hear nothing (a key release, a mouse event it did not ask for).
//!
//! The encoding follows xterm: `CSI` forms with a modifier parameter for arrows, Home, End and
//! function keys; `ESC` prefix for Alt; control codes for Ctrl with a letter; SGR, UTF-8 or
//! legacy X10 mouse reports as the agent selected. Keys with no xterm form return `None`.

use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use vt100::{MouseProtocolEncoding, MouseProtocolMode};

use super::terminal::InputModes;

const ESC: u8 = 0x1b;
/// Sent before and after pasted text when the agent asked for bracketed paste.
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

/// xterm's modifier parameter: 1 plus shift (1), alt (2), ctrl (4), meta/super (8).
fn modifier_param(modifiers: KeyModifiers) -> u8 {
    let mut bits = 0;
    if modifiers.contains(KeyModifiers::SHIFT) {
        bits |= 1;
    }
    if modifiers.contains(KeyModifiers::ALT) {
        bits |= 2;
    }
    if modifiers.contains(KeyModifiers::CONTROL) {
        bits |= 4;
    }
    if modifiers.intersects(KeyModifiers::SUPER | KeyModifiers::META | KeyModifiers::HYPER) {
        bits |= 8;
    }
    bits + 1
}

/// A final-letter key: `ESC [ x`, or `ESC O x` in application mode, or `ESC [ 1 ; m x` with a
/// modifier (modifiers always use the `CSI` form).
fn letter_key(letter: u8, modifiers: KeyModifiers, application: bool) -> Vec<u8> {
    let param = modifier_param(modifiers);
    if param > 1 {
        format!("\x1b[1;{param}{}", letter as char).into_bytes()
    } else if application {
        vec![ESC, b'O', letter]
    } else {
        vec![ESC, b'[', letter]
    }
}

/// A `CSI n ~` key, with `; m` for a modifier.
fn tilde_key(number: u8, modifiers: KeyModifiers) -> Vec<u8> {
    let param = modifier_param(modifiers);
    if param > 1 {
        format!("\x1b[{number};{param}~").into_bytes()
    } else {
        format!("\x1b[{number}~").into_bytes()
    }
}

/// F1 to F4 use `SS3` (`ESC O P` to `S`), or `CSI 1 ; m P` with a modifier; F5 and up use
/// `CSI n ~` with xterm's gapped numbers.
fn function_key(n: u8, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    let tilde = match n {
        1..=4 => {
            let letter = b"PQRS"[usize::from(n) - 1];
            let param = modifier_param(modifiers);
            return Some(if param > 1 {
                format!("\x1b[1;{param}{}", letter as char).into_bytes()
            } else {
                vec![ESC, b'O', letter]
            });
        }
        5 => 15,
        6 => 17,
        7 => 18,
        8 => 19,
        9 => 20,
        10 => 21,
        11 => 23,
        12 => 24,
        13 => 25,
        14 => 26,
        15 => 28,
        16 => 29,
        17 => 31,
        18 => 32,
        19 => 33,
        20 => 34,
        _ => return None,
    };
    Some(tilde_key(tilde, modifiers))
}

/// The control character for Ctrl plus `c`, as a terminal sends it.
fn control_char(c: char) -> Option<u8> {
    match c {
        'a'..='z' => Some(c as u8 - b'a' + 1),
        'A'..='Z' => Some(c as u8 - b'A' + 1),
        '@' | ' ' | '2' => Some(0),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '7' | '/' => Some(0x1f),
        '8' | '?' => Some(0x7f),
        _ => None,
    }
}

/// The bytes for one key event, or `None` for a release or a key with no terminal form.
///
/// A repeat is sent as a press: a held key repeats in the agent too.
#[must_use]
pub fn encode_key(event: KeyEvent, modes: InputModes) -> Option<Vec<u8>> {
    if event.kind == KeyEventKind::Release {
        return None;
    }
    let mods = event.modifiers;
    let alt = mods.contains(KeyModifiers::ALT);
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let app = modes.application_cursor;
    let bytes = match event.code {
        KeyCode::Char(c) if ctrl => {
            let code = control_char(c)?;
            let mut out = Vec::new();
            if alt {
                out.push(ESC);
            }
            out.push(code);
            out
        }
        KeyCode::Char(c) => {
            let mut out = Vec::new();
            if alt {
                out.push(ESC);
            }
            let mut buffer = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            out
        }
        KeyCode::Enter => with_alt(alt, vec![b'\r']),
        KeyCode::Tab => with_alt(alt, vec![b'\t']),
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Backspace => with_alt(alt, vec![if ctrl { 0x08 } else { 0x7f }]),
        KeyCode::Esc => with_alt(alt, vec![ESC]),
        KeyCode::Up => letter_key(b'A', mods, app),
        KeyCode::Down => letter_key(b'B', mods, app),
        KeyCode::Right => letter_key(b'C', mods, app),
        KeyCode::Left => letter_key(b'D', mods, app),
        KeyCode::Home => letter_key(b'H', mods, app),
        KeyCode::End => letter_key(b'F', mods, app),
        KeyCode::Insert => tilde_key(2, mods),
        KeyCode::Delete => tilde_key(3, mods),
        KeyCode::PageUp => tilde_key(5, mods),
        KeyCode::PageDown => tilde_key(6, mods),
        KeyCode::F(n) => function_key(n, mods)?,
        KeyCode::Null => vec![0],
        _ => return None,
    };
    Some(bytes)
}

fn with_alt(alt: bool, mut bytes: Vec<u8>) -> Vec<u8> {
    if alt {
        bytes.insert(0, ESC);
    }
    bytes
}

/// The bytes for pasted text: wrapped in the bracketed-paste markers when the agent asked for
/// them, else the text as it is.
///
/// With markers on, an end marker inside the text is removed first, so pasted text cannot end
/// the paste early and have the rest read as typed commands.
#[must_use]
pub fn encode_paste(text: &str, modes: InputModes) -> Vec<u8> {
    if !modes.bracketed_paste {
        return text.as_bytes().to_vec();
    }
    let mut out = PASTE_START.to_vec();
    let end = std::str::from_utf8(PASTE_END).unwrap_or_default();
    // Removed until none is left: taking one out of "\x1b[2\x1b[201~01~" would join the rest.
    let mut body = text.to_owned();
    while body.contains(end) {
        body = body.replace(end, "");
    }
    out.extend_from_slice(body.as_bytes());
    out.extend_from_slice(PASTE_END);
    out
}

/// Whether the agent asked for this kind of mouse event.
fn wanted(kind: MouseEventKind, mode: MouseProtocolMode) -> bool {
    match (mode, kind) {
        (MouseProtocolMode::None, _) => false,
        (MouseProtocolMode::Press, MouseEventKind::Down(_)) => true,
        (MouseProtocolMode::Press, _) => false,
        (
            MouseProtocolMode::PressRelease,
            MouseEventKind::Down(_)
            | MouseEventKind::Up(_)
            | MouseEventKind::ScrollUp
            | MouseEventKind::ScrollDown,
        ) => true,
        (MouseProtocolMode::PressRelease, _) => false,
        (MouseProtocolMode::ButtonMotion, MouseEventKind::Moved) => false,
        (MouseProtocolMode::ButtonMotion, _) => true,
        (MouseProtocolMode::AnyMotion, _) => true,
    }
}

/// xterm's button code for an event: 0 left, 1 middle, 2 right, 3 release (legacy), 64 and up
/// for the wheel, plus 32 for motion, plus 4, 8, 16 for shift, alt, ctrl.
fn mouse_code(event: &MouseEvent, sgr: bool) -> Option<u8> {
    let button = |b: MouseButton| match b {
        MouseButton::Left => 0,
        MouseButton::Middle => 1,
        MouseButton::Right => 2,
    };
    let mut code = match event.kind {
        MouseEventKind::Down(b) => button(b),
        MouseEventKind::Up(b) => {
            if sgr {
                button(b)
            } else {
                3
            }
        }
        MouseEventKind::Drag(b) => button(b) + 32,
        MouseEventKind::Moved => 3 + 32,
        MouseEventKind::ScrollUp => 64,
        MouseEventKind::ScrollDown => 65,
        MouseEventKind::ScrollLeft => 66,
        MouseEventKind::ScrollRight => 67,
    };
    if event.modifiers.contains(KeyModifiers::SHIFT) {
        code += 4;
    }
    if event.modifiers.contains(KeyModifiers::ALT) {
        code += 8;
    }
    if event.modifiers.contains(KeyModifiers::CONTROL) {
        code += 16;
    }
    Some(code)
}

/// The bytes for a mouse event at `column`, `row` (0-based, relative to the agent's pane), or
/// `None` when the agent did not ask for it or the position cannot be written in its encoding.
#[must_use]
pub fn encode_mouse(
    event: MouseEvent,
    column: u16,
    row: u16,
    modes: InputModes,
) -> Option<Vec<u8>> {
    if !wanted(event.kind, modes.mouse) {
        return None;
    }
    let sgr = modes.mouse_encoding == MouseProtocolEncoding::Sgr;
    let code = mouse_code(&event, sgr)?;
    let (x, y) = (u32::from(column) + 1, u32::from(row) + 1);
    match modes.mouse_encoding {
        MouseProtocolEncoding::Sgr => {
            let end = if matches!(event.kind, MouseEventKind::Up(_)) {
                'm'
            } else {
                'M'
            };
            Some(format!("\x1b[<{code};{x};{y}{end}").into_bytes())
        }
        MouseProtocolEncoding::Utf8 => {
            let mut out = b"\x1b[M".to_vec();
            for value in [u32::from(code) + 32, x + 32, y + 32] {
                let c = char::from_u32(value)?;
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
            Some(out)
        }
        MouseProtocolEncoding::Default => {
            // One byte each, so positions past 222 cannot be written.
            let bytes = [
                u8::try_from(u32::from(code) + 32).ok()?,
                u8::try_from(x + 32).ok()?,
                u8::try_from(y + 32).ok()?,
            ];
            let mut out = b"\x1b[M".to_vec();
            out.extend_from_slice(&bytes);
            Some(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_none, assert_some};
    use crossterm::event::KeyEventState;
    use pretty_assertions::assert_eq;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn plain() -> InputModes {
        InputModes::default()
    }

    fn application() -> InputModes {
        InputModes {
            application_cursor: true,
            ..InputModes::default()
        }
    }

    fn sent(code: KeyCode, modifiers: KeyModifiers, modes: InputModes) -> Vec<u8> {
        assert_some!(encode_key(key(code, modifiers), modes))
    }

    #[test]
    fn printable_characters_are_utf8_and_alt_adds_an_escape_prefix() {
        let none = KeyModifiers::NONE;
        assert_eq!(sent(KeyCode::Char('a'), none, plain()), b"a");
        assert_eq!(sent(KeyCode::Char('é'), none, plain()), "é".as_bytes());
        assert_eq!(sent(KeyCode::Char('世'), none, plain()), "世".as_bytes());
        assert_eq!(sent(KeyCode::Char('A'), KeyModifiers::SHIFT, plain()), b"A");
        assert_eq!(
            sent(KeyCode::Char('b'), KeyModifiers::ALT, plain()),
            b"\x1bb"
        );
    }

    #[test]
    fn control_combinations_give_the_control_codes() {
        let ctrl = KeyModifiers::CONTROL;
        assert_eq!(sent(KeyCode::Char('c'), ctrl, plain()), [3]);
        assert_eq!(sent(KeyCode::Char('d'), ctrl, plain()), [4]);
        assert_eq!(sent(KeyCode::Char('z'), ctrl, plain()), [26]);
        assert_eq!(sent(KeyCode::Char('A'), ctrl, plain()), [1]);
        assert_eq!(sent(KeyCode::Char('['), ctrl, plain()), [0x1b]);
        assert_eq!(sent(KeyCode::Char('\\'), ctrl, plain()), [0x1c]);
        assert_eq!(sent(KeyCode::Char(' '), ctrl, plain()), [0]);
        assert_eq!(sent(KeyCode::Char('g'), ctrl, plain()), [7]);
        assert_eq!(
            sent(KeyCode::Char('f'), ctrl | KeyModifiers::ALT, plain()),
            [0x1b, 6]
        );
        assert_none!(encode_key(key(KeyCode::Char('ç'), ctrl), plain()));
    }

    #[test]
    fn editing_and_whitespace_keys() {
        let none = KeyModifiers::NONE;
        assert_eq!(sent(KeyCode::Enter, none, plain()), b"\r");
        assert_eq!(sent(KeyCode::Tab, none, plain()), b"\t");
        assert_eq!(
            sent(KeyCode::BackTab, KeyModifiers::SHIFT, plain()),
            b"\x1b[Z"
        );
        assert_eq!(sent(KeyCode::Backspace, none, plain()), [0x7f]);
        assert_eq!(
            sent(KeyCode::Backspace, KeyModifiers::ALT, plain()),
            [0x1b, 0x7f]
        );
        assert_eq!(sent(KeyCode::Esc, none, plain()), [0x1b]);
        assert_eq!(sent(KeyCode::Delete, none, plain()), b"\x1b[3~");
        assert_eq!(sent(KeyCode::Insert, none, plain()), b"\x1b[2~");
        assert_eq!(sent(KeyCode::PageUp, none, plain()), b"\x1b[5~");
        assert_eq!(sent(KeyCode::PageDown, none, plain()), b"\x1b[6~");
    }

    #[test]
    fn arrows_home_and_end_follow_the_application_cursor_mode() {
        let none = KeyModifiers::NONE;
        for (code, letter) in [
            (KeyCode::Up, 'A'),
            (KeyCode::Down, 'B'),
            (KeyCode::Right, 'C'),
            (KeyCode::Left, 'D'),
            (KeyCode::Home, 'H'),
            (KeyCode::End, 'F'),
        ] {
            assert_eq!(
                sent(code, none, plain()),
                format!("\x1b[{letter}").into_bytes(),
                "{code:?}"
            );
            assert_eq!(
                sent(code, none, application()),
                format!("\x1bO{letter}").into_bytes(),
                "{code:?}"
            );
        }
    }

    #[test]
    fn modified_arrows_always_use_the_csi_form_with_xterms_parameter() {
        let cases = [
            (KeyModifiers::SHIFT, "2"),
            (KeyModifiers::ALT, "3"),
            (KeyModifiers::SHIFT | KeyModifiers::ALT, "4"),
            (KeyModifiers::CONTROL, "5"),
            (KeyModifiers::CONTROL | KeyModifiers::SHIFT, "6"),
            (KeyModifiers::CONTROL | KeyModifiers::ALT, "7"),
        ];
        for (mods, param) in cases {
            for modes in [plain(), application()] {
                assert_eq!(
                    sent(KeyCode::Right, mods, modes),
                    format!("\x1b[1;{param}C").into_bytes(),
                    "{mods:?} {modes:?}"
                );
            }
        }
        assert_eq!(
            sent(KeyCode::Delete, KeyModifiers::CONTROL, plain()),
            b"\x1b[3;5~"
        );
    }

    #[test]
    fn function_keys_use_xterms_sequences() {
        let none = KeyModifiers::NONE;
        let expected: [(u8, &[u8]); 12] = [
            (1, b"\x1bOP"),
            (2, b"\x1bOQ"),
            (3, b"\x1bOR"),
            (4, b"\x1bOS"),
            (5, b"\x1b[15~"),
            (6, b"\x1b[17~"),
            (7, b"\x1b[18~"),
            (8, b"\x1b[19~"),
            (9, b"\x1b[20~"),
            (10, b"\x1b[21~"),
            (11, b"\x1b[23~"),
            (12, b"\x1b[24~"),
        ];
        for (n, bytes) in expected {
            assert_eq!(sent(KeyCode::F(n), none, plain()), bytes, "F{n}");
        }
        assert_eq!(
            sent(KeyCode::F(1), KeyModifiers::SHIFT, plain()),
            b"\x1b[1;2P"
        );
        assert_eq!(
            sent(KeyCode::F(5), KeyModifiers::CONTROL, plain()),
            b"\x1b[15;5~"
        );
        assert_none!(encode_key(key(KeyCode::F(0), none), plain()));
        assert_none!(encode_key(key(KeyCode::F(21), none), plain()));
    }

    #[test]
    fn a_release_sends_nothing_and_a_repeat_is_a_press() {
        let mut release = key(KeyCode::Char('a'), KeyModifiers::NONE);
        release.kind = KeyEventKind::Release;
        assert_none!(encode_key(release, plain()));
        let mut repeat = key(KeyCode::Char('a'), KeyModifiers::NONE);
        repeat.kind = KeyEventKind::Repeat;
        assert_eq!(assert_some!(encode_key(repeat, plain())), b"a");
        assert_none!(encode_key(
            key(KeyCode::CapsLock, KeyModifiers::NONE),
            plain()
        ));
    }

    #[test]
    fn a_paste_is_wrapped_only_when_the_agent_asked_and_cannot_end_the_wrap_early() {
        assert_eq!(encode_paste("ls -la\n", plain()), b"ls -la\n");
        let bracketed = InputModes {
            bracketed_paste: true,
            ..InputModes::default()
        };
        assert_eq!(
            encode_paste("hello\nworld", bracketed),
            b"\x1b[200~hello\nworld\x1b[201~"
        );
        // Text that holds the end marker must not be able to leave the paste.
        let hostile = encode_paste("a\x1b[201~rm -rf ~\n", bracketed);
        assert_eq!(hostile, b"\x1b[200~arm -rf ~\n\x1b[201~");
        assert_eq!(
            hostile.windows(6).filter(|w| *w == PASTE_END).count(),
            1,
            "only the closing marker may remain"
        );
        // Removing one marker must not join the pieces around it into a new one.
        let nested = encode_paste("\x1b[2\x1b[201~01~x", bracketed);
        assert_eq!(
            nested.windows(6).filter(|w| *w == PASTE_END).count(),
            1,
            "{nested:?}"
        );
    }

    fn mouse(kind: MouseEventKind) -> MouseEvent {
        MouseEvent {
            kind,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn mouse_modes(mode: MouseProtocolMode, encoding: MouseProtocolEncoding) -> InputModes {
        InputModes {
            mouse: mode,
            mouse_encoding: encoding,
            ..InputModes::default()
        }
    }

    #[test]
    fn the_mouse_is_silent_unless_the_agent_asked_for_that_kind_of_event() {
        let down = mouse(MouseEventKind::Down(MouseButton::Left));
        let up = mouse(MouseEventKind::Up(MouseButton::Left));
        let moved = mouse(MouseEventKind::Moved);
        let drag = mouse(MouseEventKind::Drag(MouseButton::Left));
        let enc = MouseProtocolEncoding::Sgr;
        assert_none!(encode_mouse(
            down,
            5,
            5,
            mouse_modes(MouseProtocolMode::None, enc)
        ));
        let press = mouse_modes(MouseProtocolMode::Press, enc);
        assert_some!(encode_mouse(down, 5, 5, press));
        assert_none!(encode_mouse(up, 5, 5, press));
        let both = mouse_modes(MouseProtocolMode::PressRelease, enc);
        assert_some!(encode_mouse(up, 5, 5, both));
        assert_none!(encode_mouse(drag, 5, 5, both));
        let motion = mouse_modes(MouseProtocolMode::ButtonMotion, enc);
        assert_some!(encode_mouse(drag, 5, 5, motion));
        assert_none!(encode_mouse(moved, 5, 5, motion));
        let any = mouse_modes(MouseProtocolMode::AnyMotion, enc);
        assert_some!(encode_mouse(moved, 5, 5, any));
    }

    #[test]
    fn sgr_reports_use_one_based_positions_and_m_for_a_release() {
        let modes = mouse_modes(MouseProtocolMode::PressRelease, MouseProtocolEncoding::Sgr);
        let down = mouse(MouseEventKind::Down(MouseButton::Left));
        let up = mouse(MouseEventKind::Up(MouseButton::Right));
        assert_eq!(
            assert_some!(encode_mouse(down, 0, 0, modes)),
            b"\x1b[<0;1;1M"
        );
        assert_eq!(
            assert_some!(encode_mouse(up, 9, 19, modes)),
            b"\x1b[<2;10;20m"
        );
        let wheel = mouse(MouseEventKind::ScrollUp);
        assert_eq!(
            assert_some!(encode_mouse(wheel, 3, 4, modes)),
            b"\x1b[<64;4;5M"
        );
        let mut shifted = down;
        shifted.modifiers = KeyModifiers::SHIFT | KeyModifiers::CONTROL;
        assert_eq!(
            assert_some!(encode_mouse(shifted, 0, 0, modes)),
            b"\x1b[<20;1;1M"
        );
    }

    #[test]
    fn legacy_and_utf8_reports_are_offset_by_32_and_the_legacy_form_has_a_limit() {
        let down = mouse(MouseEventKind::Down(MouseButton::Left));
        let legacy = mouse_modes(MouseProtocolMode::Press, MouseProtocolEncoding::Default);
        assert_eq!(
            assert_some!(encode_mouse(down, 0, 0, legacy)),
            [0x1b, b'[', b'M', 32, 33, 33]
        );
        // Column 223 would need a byte over 255; the legacy form cannot say it.
        assert_none!(encode_mouse(down, 223, 0, legacy));
        let utf8 = mouse_modes(MouseProtocolMode::Press, MouseProtocolEncoding::Utf8);
        let wide = assert_some!(encode_mouse(down, 300, 0, utf8));
        assert!(wide.starts_with(b"\x1b[M"));
        assert_eq!(
            std::str::from_utf8(&wide[3..]).map(|s| s.chars().count()),
            Ok(3)
        );
        let up = mouse(MouseEventKind::Up(MouseButton::Left));
        let both = mouse_modes(
            MouseProtocolMode::PressRelease,
            MouseProtocolEncoding::Default,
        );
        assert_eq!(
            assert_some!(encode_mouse(up, 0, 0, both)),
            [0x1b, b'[', b'M', 35, 33, 33]
        );
    }
}
