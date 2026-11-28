// ABOUTME: SessionScreen: one agent's emulated terminal (vt100 0.16), with every side effect the agent asks for recorded, never performed.
// ABOUTME: Only the parsed screen is ever rendered, so OSC 52, titles, bells and queries cannot reach the owner's real terminal.
//! One session's terminal.
//!
//! Bytes from the agent's PTY go into [`SessionScreen::process`], in order, whole or split at
//! any point. They are parsed into a screen and nothing else: the parser's callbacks do not
//! write anywhere, they only count what the agent asked for ([`Suppressed`]), so the view can
//! say `clipboard blocked` and the owner's terminal never sees the request.
//!
//! The view draws the screen with `tui_term::widget::PseudoTerminal`; this module only owns
//! the state. The vt100 crate is used behind this type so a later release can replace it
//! without touching callers.

use vt100::{Callbacks, MouseProtocolEncoding, MouseProtocolMode, Parser, Screen};

/// Most lines of history kept for scrolling back, however narrow the screen.
pub const SCROLLBACK_LINES: usize = 10_000;
/// The memory one screen's history is sized for, about. Lines are capped by this, not only by count:
/// 10,000 lines of 250 columns took 91 MiB, and a supervisor holds up to 32 screens (hb-807 review
/// B, MEDIUM 2).
///
/// This is a size chosen when the screen is made, not a ceiling that holds for ever. The emulator
/// fixes its history length at creation and cannot be told a new one, so a window that is widened
/// afterwards keeps the line count it was made with and its history grows in proportion to the new
/// width. That width is the owner's own terminal: the agent cannot change it (its resize requests are
/// only counted), so what an agent prints can never push a screen past the size it was made for.
pub const SCROLLBACK_BYTES: usize = 8 * 1024 * 1024;
/// A 32-byte vt100 cell plus room for row and allocation overhead.
/// Fresh-process RSS probes at 80, 250 and 400 columns verify this sizing allowance.
const BYTES_PER_CELL: usize = 40;
/// History is sized for at least this many columns, so widening the window later does not take
/// much more than the budget.
const HISTORY_COLS: usize = 200;

/// How many lines of history a screen of `cols` columns keeps.
///
/// Sized from the width at creation and no narrower than 200 columns; a screen widened afterwards
/// keeps this count (see [`SCROLLBACK_BYTES`]). Never fewer than [`MIN_HISTORY`] lines.
#[must_use]
pub fn scrollback_lines(cols: u16) -> usize {
    let width = usize::from(cols).max(HISTORY_COLS);
    (SCROLLBACK_BYTES / (width * BYTES_PER_CELL)).clamp(MIN_HISTORY, SCROLLBACK_LINES)
}

/// The fewest lines of history a screen keeps. Small enough that even the widest possible window
/// (65,535 columns) stays near the budget; a real terminal is never that wide.
pub const MIN_HISTORY: usize = 10;
/// The smallest size an emulator is given; a hidden pane keeps its last valid size instead.
pub const MIN_ROWS: u16 = 1;
/// See [`MIN_ROWS`].
pub const MIN_COLS: u16 = 1;

/// What the agent asked the terminal to do that was not done.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Suppressed {
    /// Clipboard writes (OSC 52).
    pub clipboard_writes: u64,
    /// Clipboard reads (OSC 52 with `?`), which would send the owner's clipboard to the agent.
    pub clipboard_reads: u64,
    /// Window or icon title changes.
    pub title_changes: u64,
    /// Bells, audible or visual.
    pub bells: u64,
    /// Requests to resize the window.
    pub resize_requests: u64,
}

/// The parser's callbacks: they count, and do nothing else.
#[derive(Debug, Default)]
struct Recorder {
    suppressed: Suppressed,
}

impl Callbacks for Recorder {
    fn audible_bell(&mut self, _: &mut Screen) {
        self.suppressed.bells += 1;
    }

    fn visual_bell(&mut self, _: &mut Screen) {
        self.suppressed.bells += 1;
    }

    fn resize(&mut self, _: &mut Screen, _request: (u16, u16)) {
        self.suppressed.resize_requests += 1;
    }

    fn set_window_icon_name(&mut self, _: &mut Screen, _icon_name: &[u8]) {
        self.suppressed.title_changes += 1;
    }

    fn set_window_title(&mut self, _: &mut Screen, _title: &[u8]) {
        self.suppressed.title_changes += 1;
    }

    fn copy_to_clipboard(&mut self, _: &mut Screen, _ty: &[u8], _data: &[u8]) {
        self.suppressed.clipboard_writes += 1;
    }

    fn paste_from_clipboard(&mut self, _: &mut Screen, _ty: &[u8]) {
        self.suppressed.clipboard_reads += 1;
    }
}

/// The most bytes of one OSC string (title, clipboard, hyperlink) the emulator is given. The
/// emulator's parser keeps the whole string until it ends, so without this cap an agent could
/// send `ESC ] 52 ;` and then bytes without end and make the supervisor use all memory.
/// Everything this supervisor does with an OSC string is to count it, so a cut one loses nothing.
pub const MAX_OSC_BYTES: usize = 4096;

/// The most bytes the session's reader gives the emulator in one call.
/// The local vte patch also bounds ESC-search work within each call.
pub const READ_SIZE: usize = 8192;

/// Where the filter thinks the emulator's parser is. Only the entry to and exit from an OSC
/// string matter, and both are the same from every other state, so the rest is one `Other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OscState {
    Other,
    Escape,
    Osc { kept: usize },
}

/// Drops the bytes of an OSC string beyond [`MAX_OSC_BYTES`], and nothing else.
///
/// It follows the parser's own rules (the `vte` crate's `advance_esc` and `advance_osc_string`):
/// `ESC ]` starts a string; BEL, CAN, SUB and ESC end it; CAN and SUB return to ground, ESC to
/// the escape state. Bytes it forwards are exactly those the parser would have been given, so a
/// string under the cap parses the same, and the terminator that ends a long one always arrives.
#[derive(Debug, Clone, Copy)]
struct OscCap {
    state: OscState,
}

impl OscCap {
    const fn new() -> Self {
        Self {
            state: OscState::Other,
        }
    }

    /// Whether `byte` is passed on. Updates the state.
    fn keeps(&mut self, byte: u8) -> bool {
        match self.state {
            OscState::Other => {
                if byte == 0x1b {
                    self.state = OscState::Escape;
                }
                true
            }
            OscState::Escape => {
                self.state = match byte {
                    0x5d => OscState::Osc { kept: 0 },
                    0x1b | 0x00..=0x17 | 0x19 | 0x1c..=0x1f | 0x7f..=0xff => OscState::Escape,
                    _ => OscState::Other,
                };
                true
            }
            OscState::Osc { kept } => match byte {
                0x07 | 0x18 | 0x1a => {
                    self.state = OscState::Other;
                    true
                }
                0x1b => {
                    self.state = OscState::Escape;
                    true
                }
                _ if kept < MAX_OSC_BYTES => {
                    self.state = OscState::Osc { kept: kept + 1 };
                    true
                }
                _ => false,
            },
        }
    }

    /// `bytes` without what the cap drops. Borrows when nothing is dropped.
    fn filter<'a>(&mut self, bytes: &'a [u8]) -> std::borrow::Cow<'a, [u8]> {
        // Most reads hold no escape at all and are not inside a string.
        if self.state == OscState::Other && !bytes.contains(&0x1b) {
            return std::borrow::Cow::Borrowed(bytes);
        }
        let mut kept = Vec::new();
        let mut dropped = false;
        for (i, &byte) in bytes.iter().enumerate() {
            if self.keeps(byte) {
                if dropped {
                    kept.push(byte);
                }
            } else if !dropped {
                dropped = true;
                kept.extend_from_slice(&bytes[..i]);
            }
        }
        if dropped {
            std::borrow::Cow::Owned(kept)
        } else {
            std::borrow::Cow::Borrowed(bytes)
        }
    }
}

/// One agent's emulated terminal.
pub struct SessionScreen {
    parser: Parser<Recorder>,
    osc: OscCap,
    /// Bytes given to the parser, so a test can see that the cap is applied here.
    #[cfg(test)]
    fed: usize,
}

impl std::fmt::Debug for SessionScreen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionScreen")
            .field("size", &self.parser.screen().size())
            .field("suppressed", &self.parser.callbacks().suppressed)
            .finish()
    }
}

impl SessionScreen {
    /// A blank terminal of `rows` by `cols`, raised to at least 1 by 1.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Self {
        Self {
            parser: Parser::new_with_callbacks(
                rows.max(MIN_ROWS),
                cols.max(MIN_COLS),
                scrollback_lines(cols),
                Recorder::default(),
            ),
            osc: OscCap::new(),
            #[cfg(test)]
            fed: 0,
        }
    }

    /// Feeds bytes from the agent, in the order they were read.
    pub fn process(&mut self, bytes: &[u8]) {
        let bytes = self.osc.filter(bytes);
        #[cfg(test)]
        {
            self.fed += bytes.len();
        }
        self.parser.process(&bytes);
    }

    /// Resizes the emulator. A zero size (a hidden pane) is ignored, so the session keeps its
    /// last valid size. Returns whether the size changed.
    pub fn resize(&mut self, rows: u16, cols: u16) -> bool {
        if rows < MIN_ROWS || cols < MIN_COLS || self.parser.screen().size() == (rows, cols) {
            return false;
        }
        self.parser.screen_mut().set_size(rows, cols);
        true
    }

    /// The size, as `(rows, cols)`.
    #[must_use]
    pub fn size(&self) -> (u16, u16) {
        self.parser.screen().size()
    }

    /// The parsed screen, for drawing and for the input modes.
    #[must_use]
    pub fn screen(&self) -> &Screen {
        self.parser.screen()
    }

    /// What the agent asked for that was not done.
    #[must_use]
    pub fn suppressed(&self) -> Suppressed {
        self.parser.callbacks().suppressed
    }

    /// The visible text, one line per row, without styling. For tests and the log.
    #[must_use]
    pub fn text(&self) -> String {
        self.parser.screen().contents()
    }

    /// Scrolls the view back `lines` lines from the bottom; clamped to the history held.
    pub fn scroll_to(&mut self, lines: usize) {
        self.parser.screen_mut().set_scrollback(lines);
    }

    /// How far back the view is scrolled; 0 is the live screen.
    #[must_use]
    pub fn scrolled(&self) -> usize {
        self.parser.screen().scrollback()
    }

    /// The input modes the agent has switched on, which decide how keys and the mouse are sent.
    #[must_use]
    pub fn modes(&self) -> InputModes {
        let screen = self.parser.screen();
        InputModes {
            application_cursor: screen.application_cursor(),
            application_keypad: screen.application_keypad(),
            bracketed_paste: screen.bracketed_paste(),
            mouse: screen.mouse_protocol_mode(),
            mouse_encoding: screen.mouse_protocol_encoding(),
        }
    }
}

/// The modes that change what bytes the agent wants for a key, a paste or the mouse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputModes {
    /// Arrow keys send `ESC O x` instead of `ESC [ x`.
    pub application_cursor: bool,
    /// The keypad sends application sequences.
    pub application_keypad: bool,
    /// A paste is wrapped in `ESC [ 200 ~` and `ESC [ 201 ~`.
    pub bracketed_paste: bool,
    /// Which mouse events the agent wants.
    pub mouse: MouseProtocolMode,
    /// How mouse events are written.
    pub mouse_encoding: MouseProtocolEncoding,
}

impl Default for InputModes {
    fn default() -> Self {
        Self {
            application_cursor: false,
            application_keypad: false,
            bracketed_paste: false,
            mouse: MouseProtocolMode::None,
            mouse_encoding: MouseProtocolEncoding::Default,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_some;
    use pretty_assertions::assert_eq;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use tui_term::widget::{Cursor, PseudoTerminal};

    /// The screen drawn by the real widget into a test backend, as text.
    fn drawn(screen: &SessionScreen) -> String {
        let (rows, cols) = screen.size();
        let mut terminal = Terminal::new(TestBackend::new(cols, rows)).unwrap_or_else(|_| {
            // TestBackend cannot fail to build; keep clippy's unwrap lint satisfied.
            std::process::abort()
        });
        let _ = terminal.draw(|frame| {
            let mut cursor = Cursor::default();
            cursor.hide();
            frame.render_widget(
                PseudoTerminal::new(screen.screen()).cursor(cursor),
                frame.area(),
            );
        });
        let buffer = terminal.backend().buffer().clone();
        (0..rows)
            .map(|y| {
                (0..cols)
                    .map(|x| buffer[(x, y)].symbol().to_owned())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The drawn screen with each cell's style, so a snapshot shows colors and attributes too.
    fn styled(screen: &SessionScreen) -> String {
        let (rows, cols) = screen.size();
        let mut terminal =
            Terminal::new(TestBackend::new(cols, rows)).unwrap_or_else(|_| std::process::abort());
        let _ = terminal.draw(|frame| {
            let mut cursor = Cursor::default();
            cursor.hide();
            frame.render_widget(
                PseudoTerminal::new(screen.screen()).cursor(cursor),
                frame.area(),
            );
        });
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..rows {
            let mut line = String::new();
            for x in 0..cols {
                let cell = &buffer[(x, y)];
                let style = cell.style();
                let mark = format!("{:?}/{:?}/{:?}", style.fg, style.bg, style.add_modifier);
                if cell.symbol() != " " {
                    line.push_str(&format!("{}[{mark}]", cell.symbol()));
                }
            }
            out.push_str(&line);
            out.push('\n');
        }
        out
    }

    #[test]
    fn snapshot_colors_and_attributes() {
        let screen = fed(
            3,
            20,
            b"\x1b[31mred\x1b[0m \x1b[1;4;32mbu\x1b[0m \x1b[38;5;208mo\x1b[48;2;1;2;3mt\x1b[7mi",
        );
        insta::assert_snapshot!(styled(&screen));
    }

    #[test]
    fn snapshot_alternate_screen_with_wide_characters() {
        let mut screen = fed(4, 12, b"main");
        screen.process("\x1b[?1049h\x1b[2J\x1b[1;1H世界 ok\x1b[2;1H\x1b[44mbar\x1b[K".as_bytes());
        insta::assert_snapshot!(styled(&screen));
    }

    fn fed(rows: u16, cols: u16, bytes: &[u8]) -> SessionScreen {
        let mut screen = SessionScreen::new(rows, cols);
        screen.process(bytes);
        screen
    }

    #[test]
    fn text_colors_and_cursor_movement_render_as_a_terminal_would() {
        let screen = fed(
            4,
            20,
            b"\x1b[31mred\x1b[0m plain\r\n\x1b[2;5Hmoved\x1b[1;1H\x1b[1mB\x1b[0m",
        );
        assert_eq!(drawn(&screen), "Bed plain\n    moved\n\n");
        let cell = assert_some!(screen.screen().cell(0, 1));
        assert_eq!(cell.fgcolor(), vt100::Color::Idx(1));
        let bold = assert_some!(screen.screen().cell(0, 0));
        assert!(bold.bold());
    }

    #[test]
    fn the_alternate_screen_hides_the_main_screen_and_gives_it_back() {
        let mut screen = fed(3, 20, b"main text");
        screen.process(b"\x1b[?1049h\x1b[2Jfull screen app");
        assert!(screen.screen().alternate_screen());
        assert_eq!(drawn(&screen), "full screen app\n\n");
        screen.process(b"\x1b[?1049l");
        assert!(!screen.screen().alternate_screen());
        assert_eq!(drawn(&screen), "main text\n\n");
    }

    #[test]
    fn wide_and_combining_characters_take_their_columns() {
        let screen = fed(2, 10, "a世界e\u{301}b".as_bytes());
        let first = assert_some!(screen.screen().cell(0, 1));
        assert!(first.is_wide());
        let tail = assert_some!(screen.screen().cell(0, 2));
        assert!(tail.is_wide_continuation());
        assert_eq!(screen.text(), "a世界e\u{301}b");
    }

    #[test]
    fn a_sequence_split_across_reads_renders_exactly_as_it_does_whole() {
        let stream =
            "\x1b[1;32mgreen\x1b[0m \x1b[2;3Hhi 世界 \x1b]0;a title\x07\x1b[?2004hdone".as_bytes();
        let whole = fed(5, 40, stream);
        for cut in 0..=stream.len() {
            let mut split = SessionScreen::new(5, 40);
            split.process(&stream[..cut]);
            split.process(&stream[cut..]);
            assert_eq!(drawn(&split), drawn(&whole), "cut at {cut}");
            assert_eq!(split.modes(), whole.modes(), "cut at {cut}");
            assert_eq!(split.suppressed(), whole.suppressed(), "cut at {cut}");
        }
        // One byte at a time, the worst case a PTY read can produce.
        let mut bytewise = SessionScreen::new(5, 40);
        for byte in stream {
            bytewise.process(&[*byte]);
        }
        assert_eq!(drawn(&bytewise), drawn(&whole));
    }

    #[test]
    fn clipboard_title_bell_and_resize_requests_are_counted_and_never_drawn() {
        let screen = fed(
            3,
            40,
            b"before\x1b]52;c;aGVsbG8=\x07\x1b]52;c;?\x07\x1b]2;owned\x07\x1b]1;icon\x07\x07\x1b[8;40;120tafter",
        );
        assert_eq!(screen.text(), "beforeafter");
        let seen = screen.suppressed();
        assert_eq!(seen.clipboard_writes, 1, "{seen:?}");
        assert_eq!(seen.clipboard_reads, 1, "{seen:?}");
        assert_eq!(seen.title_changes, 2, "{seen:?}");
        assert_eq!(seen.bells, 1, "{seen:?}");
        assert_eq!(seen.resize_requests, 1, "{seen:?}");
        // The request did not resize the emulator: only the supervisor decides the size.
        assert_eq!(screen.size(), (3, 40));
    }

    #[test]
    fn a_terminal_query_gets_no_reply_from_the_emulator() {
        // A reply would have to be written back to the agent; this type has no way to do that,
        // and the query text itself must not appear on the screen.
        let screen = fed(2, 30, b"\x1b[6n\x1b[c\x1b[>c\x1b]10;?\x07ok");
        assert_eq!(screen.text(), "ok");
    }

    #[test]
    fn input_modes_follow_what_the_agent_switches_on() {
        let mut screen = fed(2, 20, b"");
        assert_eq!(screen.modes(), InputModes::default());
        screen.process(b"\x1b[?1h\x1b[?2004h\x1b[?1000h\x1b[?1006h");
        let modes = screen.modes();
        assert!(modes.application_cursor);
        assert!(modes.bracketed_paste);
        assert_eq!(modes.mouse, MouseProtocolMode::PressRelease);
        assert_eq!(modes.mouse_encoding, MouseProtocolEncoding::Sgr);
        screen.process(b"\x1b[?1l\x1b[?2004l\x1b[?1000l");
        assert_eq!(screen.modes().mouse, MouseProtocolMode::None);
        assert!(!screen.modes().application_cursor);
    }

    #[test]
    fn a_zero_size_is_ignored_and_a_real_one_resizes_the_emulator() {
        let mut screen = fed(10, 40, b"x");
        assert!(!screen.resize(0, 40));
        assert!(!screen.resize(10, 0));
        assert_eq!(screen.size(), (10, 40));
        assert!(!screen.resize(10, 40));
        assert!(screen.resize(20, 60));
        assert_eq!(screen.size(), (20, 60));
        assert_eq!(SessionScreen::new(0, 0).size(), (1, 1));
    }

    #[test]
    fn scrollback_is_bounded_and_the_view_can_move_back_and_return() {
        let mut screen = SessionScreen::new(3, 10);
        let cap = scrollback_lines(10);
        for n in 0..(cap + 50) {
            screen.process(format!("line {n}\r\n").as_bytes());
        }
        screen.scroll_to(usize::MAX);
        assert_eq!(screen.scrolled(), cap, "history is capped");
        screen.scroll_to(0);
        assert_eq!(screen.scrolled(), 0);
    }

    #[test]
    fn history_is_sized_by_memory_not_only_by_line_count() {
        // Narrow screens keep the line cap; wide ones keep fewer lines, so the bytes stay bounded.
        assert_eq!(scrollback_lines(80), scrollback_lines(200));
        assert!(scrollback_lines(80) <= SCROLLBACK_LINES);
        assert!(scrollback_lines(250) < scrollback_lines(200));
        for cols in [1_u16, 80, 100, 200, 250, 400, 1000] {
            let lines = scrollback_lines(cols);
            assert!(
                (MIN_HISTORY..=SCROLLBACK_LINES).contains(&lines),
                "{cols}: {lines}"
            );
            let bytes = lines * usize::from(cols).max(HISTORY_COLS) * BYTES_PER_CELL;
            assert!(
                bytes <= SCROLLBACK_BYTES || lines == MIN_HISTORY,
                "{cols} columns: {bytes} bytes of history"
            );
        }
        // Even the widest window the protocol allows stays within a small multiple of the budget.
        let widest = scrollback_lines(u16::MAX) * usize::from(u16::MAX) * BYTES_PER_CELL;
        assert!(
            widest < 12 * SCROLLBACK_BYTES,
            "{widest} bytes at 65,535 columns"
        );
        for cols in [1_u16, 80, 250, u16::MAX] {
            assert!(scrollback_lines(cols) >= MIN_HISTORY);
        }
    }

    #[test]
    fn a_wide_screen_keeps_fewer_lines_of_history_than_a_narrow_one_and_never_more_than_its_cap() {
        // The history that is actually kept, which is what the budget limits. Process memory was
        // measured once when this was written (87 to 95 MiB for 10,000 lines of 250 columns before,
        // 26 MiB after) but is too noisy under load to assert on.
        for cols in [80_u16, 250, 400] {
            let mut screen = SessionScreen::new(30, cols);
            let line = format!("{}\r\n", "x".repeat(usize::from(cols) - 1));
            let cap = scrollback_lines(cols);
            for _ in 0..(cap + 500) {
                screen.process(line.as_bytes());
            }
            screen.scroll_to(usize::MAX);
            assert_eq!(screen.scrolled(), cap, "{cols} columns");
        }
        assert!(scrollback_lines(250) < scrollback_lines(80));
        assert!(scrollback_lines(400) < scrollback_lines(250));
    }

    #[test]
    fn a_screen_widened_after_it_was_made_keeps_the_line_count_it_was_made_with() {
        // The documented limit, pinned: the emulator cannot change its history length, so widening
        // changes how much memory the same number of lines takes, never the number of lines.
        let made_for = scrollback_lines(80);
        let mut screen = SessionScreen::new(24, 80);
        assert!(screen.resize(24, 400));
        let line = format!("{}\r\n", "x".repeat(399));
        for _ in 0..(made_for + 500) {
            screen.process(line.as_bytes());
        }
        screen.scroll_to(usize::MAX);
        assert_eq!(screen.scrolled(), made_for);
    }

    #[test]
    fn a_flood_of_output_does_not_grow_the_screen_without_bound() {
        let mut screen = SessionScreen::new(24, 80);
        let chunk = "x".repeat(4096);
        for _ in 0..2_000 {
            screen.process(chunk.as_bytes());
        }
        assert_eq!(screen.size(), (24, 80));
        screen.scroll_to(usize::MAX);
        assert!(screen.scrolled() <= SCROLLBACK_LINES);
    }
    // ========================================================================
    // OSC cap: an unfinished string cannot grow without bound
    // ========================================================================

    fn rss_free_len(filter: &mut OscCap, bytes: &[u8]) -> usize {
        filter.filter(bytes).len()
    }

    #[test]
    fn a_long_unterminated_osc_string_is_cut_at_the_cap_whatever_the_chunking() {
        for chunk in [1usize, 7, 4096, 100_000] {
            let mut filter = OscCap::new();
            let mut forwarded = rss_free_len(&mut filter, b"\x1b]52;c;");
            let payload = vec![b'a'; 1_000_000];
            for part in payload.chunks(chunk) {
                forwarded += rss_free_len(&mut filter, part);
            }
            // The introducer is 2 bytes; the cap counts bytes after it.
            assert_eq!(forwarded, 2 + MAX_OSC_BYTES, "chunk {chunk}");
        }
    }

    #[test]
    fn ignored_bytes_after_escape_cannot_bypass_the_osc_cap() {
        for ignored in [0x7f, 0x80, 0xff] {
            let prefix = [0x1b, ignored, b']', b'5', b'2', b';', b'c', b';'];
            for split in 0..=prefix.len() {
                let mut screen = SessionScreen::new(2, 20);
                screen.process(&prefix[..split]);
                screen.process(&prefix[split..]);
                screen.process(&vec![b'a'; MAX_OSC_BYTES * 2]);
                assert!(
                    screen.fed <= 3 + MAX_OSC_BYTES,
                    "OSC cap bypass: ignored={ignored:#x} split={split} fed={}",
                    screen.fed
                );
            }
        }
    }

    #[test]
    fn hostile_utf8_read_in_pty_sized_pieces_is_parsed_in_linear_time() {
        // The unpatched parser repeatedly searched each invalid UTF-8 suffix for ESC.
        // The local vte patch caches that position without splitting reads or changing callbacks.
        // Keep the original debug/release limits and PTY-sized input as a performance regression.
        let limit = if cfg!(debug_assertions) { 20 } else { 2 };
        for hostile in [&b"\xff"[..], b"\xe2\x82", b"\xc3\x28"] {
            let mut screen = SessionScreen::new(24, 80);
            let mut megabyte = Vec::new();
            while megabyte.len() < (1 << 20) {
                megabyte.extend_from_slice(hostile);
            }
            let started = std::time::Instant::now();
            for read in megabyte.chunks(READ_SIZE) {
                screen.process(read);
            }
            assert!(
                started.elapsed() < std::time::Duration::from_secs(limit),
                "{hostile:?} took {:?}",
                started.elapsed()
            );
        }
    }

    #[test]
    fn the_screen_never_gives_its_parser_more_than_the_cap_of_one_unfinished_string() {
        let mut screen = SessionScreen::new(5, 40);
        screen.process(b"\x1b]52;c;");
        for _ in 0..64 {
            screen.process(&vec![b'a'; 1 << 16]);
        }
        assert_eq!(screen.fed, 2 + MAX_OSC_BYTES);
        // The string still ends and the screen still works.
        screen.process(b"\x07ok");
        assert!(screen.text().contains("ok"));
    }

    #[test]
    fn after_a_cut_string_each_terminator_ends_it_and_the_next_text_is_shown() {
        for terminator in [&b"\x07"[..], b"\x1b\\", b"\x18", b"\x1a"] {
            let mut screen = SessionScreen::new(5, 40);
            let mut bytes = b"\x1b]52;c;".to_vec();
            bytes.extend(std::iter::repeat_n(b'a', MAX_OSC_BYTES * 3));
            bytes.extend_from_slice(terminator);
            bytes.extend_from_slice(b"shown");
            screen.process(&bytes);
            let text = screen.text();
            assert!(text.contains("shown"), "{terminator:?}: {text}");
            assert!(!text.contains("aaaa"), "{terminator:?}: {text}");
        }
    }

    #[test]
    fn a_title_or_clipboard_request_still_counts_as_suppressed_even_when_its_payload_was_cut() {
        let mut screen = SessionScreen::new(5, 40);
        let mut bytes = b"\x1b]0;".to_vec();
        bytes.extend(std::iter::repeat_n(b't', MAX_OSC_BYTES * 2));
        bytes.push(0x07);
        bytes.extend_from_slice(b"\x1b]52;c;aGk=\x07");
        screen.process(&bytes);
        let seen = screen.suppressed();
        // OSC 0 sets the icon name and the title, so it counts twice (as in the test above).
        assert_eq!((seen.title_changes, seen.clipboard_writes), (2, 1));
    }

    #[test]
    fn the_escape_forms_that_enter_a_string_are_recognized_like_the_parser_does() {
        // A control byte between ESC and `]` does not stop the string from starting.
        for entry in [&b"\x1b]"[..], b"\x1b\x00]", b"\x1b\x1b]", b"\x1b\x07]"] {
            let mut filter = OscCap::new();
            let mut sent = entry.to_vec();
            sent.extend(std::iter::repeat_n(b'x', MAX_OSC_BYTES * 2));
            let forwarded = rss_free_len(&mut filter, &sent);
            assert_eq!(forwarded, entry.len() + MAX_OSC_BYTES, "{entry:?}");
        }
    }

    #[test]
    fn a_complete_c1_sequence_does_not_consume_the_following_space() {
        let mut screen = SessionScreen::new(6, 30);
        // Extra parser boundaries enter vte's partial decoder, which can swallow the space.
        screen.process(&[0, 0, 0, 0, 0, 194, 128, 32, 128]);
        screen.process(b"\x18\x1b[0mEND");
        assert_eq!(screen.text(), " END");
        assert_eq!(screen.screen().cursor_position(), (0, 4));
    }

    #[test]
    fn the_cap_changes_nothing_the_emulator_would_have_shown_for_strings_under_it() {
        use proptest::prelude::*;
        // Short strings of every kind of byte that matters to the parser, in any order.
        let alphabet = prop::sample::select(vec![
            0x1b_u8, b']', b'\\', 0x07, 0x18, 0x1a, b';', b'0', b'5', b'2', b'a', b'[', b'm',
            b'\n', 0x00, 0xe2, 0x82, 0xac,
        ]);
        let mut runner = proptest::test_runner::TestRunner::default();
        runner
            .run(&prop::collection::vec(alphabet, 0..300), |bytes| {
                let mut plain = Parser::new_with_callbacks(6, 30, 0, Recorder::default());
                plain.process(&bytes);
                let mut filtered = SessionScreen::new(6, 30);
                filtered.process(&bytes);
                prop_assert_eq!(plain.screen().contents(), filtered.screen().contents());
                prop_assert_eq!(plain.callbacks().suppressed, filtered.suppressed());
                Ok(())
            })
            .unwrap_or_else(|e| unreachable!("{e}"));
    }
}
