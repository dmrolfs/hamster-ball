// ABOUTME: The supervisor's screens: layout rule from the terminal's size, and a pure draw of the App into a ratatui frame.
// ABOUTME: Draws only; it reads App and each session's emulated screen and does no I/O. States are words first, color only reinforces.
//! The supervisor's layout rule and screens (epic hb-b6q).

use std::sync::Arc;

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, Tabs, Wrap,
};
use tui_term::widget::{Cursor, PseudoTerminal};

use super::app::{App, Field, Mode, Panel, Pending, Phase, Session, SessionId, Tab};
use super::session::Shared;
use crate::session::supervised::Cleanup;

/// Columns below which only one panel is shown at a time.
pub const WIDE_COLS: u16 = 100;
/// Rows below which only one panel is shown at a time.
pub const WIDE_ROWS: u16 = 24;
/// Columns below which the terminal pane cannot be shown at all.
pub const MIN_COLS: u16 = 60;
/// Rows below which the terminal pane cannot be shown at all.
pub const MIN_ROWS: u16 = 15;

/// How much of the screen the terminal allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Sessions, terminal and the lower tabs at once.
    Wide,
    /// One panel at a time, with the selected session's name in the header.
    Narrow,
    /// Only the session list and a request for a larger terminal.
    Tiny,
}

impl Layout {
    /// The layout for a terminal of `cols` by `rows`.
    #[must_use]
    pub fn for_size(cols: u16, rows: u16) -> Self {
        if cols < MIN_COLS || rows < MIN_ROWS {
            Self::Tiny
        } else if cols < WIDE_COLS || rows < WIDE_ROWS {
            Self::Narrow
        } else {
            Self::Wide
        }
    }
}

/// Whether to use color. Words and symbols carry the meaning either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Look {
    /// Color is allowed.
    pub color: bool,
}

impl Look {
    /// From the value of the `NO_COLOR` variable: set and not empty turns color off
    /// (<https://no-color.org>).
    #[must_use]
    pub fn from_no_color(value: Option<&std::ffi::OsStr>) -> Self {
        Self {
            color: value.is_none_or(std::ffi::OsStr::is_empty),
        }
    }

    fn fg(self, color: Color) -> Style {
        if self.color {
            Style::new().fg(color)
        } else {
            Style::new()
        }
    }
}

/// Where each part goes on a terminal of a given size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Areas {
    /// The one-line status bar.
    pub status: Rect,
    /// The alert or notice line. Always reserved, so the agent's terminal does not change size
    /// every time an alert comes or goes.
    pub alert: Rect,
    /// The session list, if shown.
    pub sessions: Option<Rect>,
    /// The terminal pane including its border, if shown.
    pub terminal: Option<Rect>,
    /// The Denials and Proxy tabs, if shown.
    pub lower: Option<Rect>,
    /// The whole area above the status bar, for modals.
    pub body: Rect,
}

/// Rows the lower tabs take when they share the screen.
const LOWER_ROWS: u16 = 10;
/// Columns the session list takes beside the terminal.
const LIST_COLS: u16 = 28;

/// Splits `area` for the layout and the panel the owner is on.
#[must_use]
pub fn areas(area: Rect, panel: Panel) -> Areas {
    let layout = Layout::for_size(area.width, area.height);
    let [body, alert, status] = ratatui::layout::Layout::vertical([
        Constraint::Min(1),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let mut out = Areas {
        status,
        alert,
        sessions: None,
        terminal: None,
        lower: None,
        body,
    };
    match layout {
        Layout::Tiny => out.sessions = Some(body),
        Layout::Narrow => match panel {
            Panel::Sessions => out.sessions = Some(body),
            Panel::Terminal => out.terminal = Some(body),
            Panel::Denials | Panel::Proxy => out.lower = Some(body),
        },
        Layout::Wide => {
            let [top, lower] = ratatui::layout::Layout::vertical([
                Constraint::Min(5),
                Constraint::Length(LOWER_ROWS),
            ])
            .areas(body);
            let [list, terminal] = ratatui::layout::Layout::horizontal([
                Constraint::Length(LIST_COLS),
                Constraint::Min(20),
            ])
            .areas(top);
            out.sessions = Some(list);
            out.terminal = Some(terminal);
            out.lower = Some(lower);
        }
    }
    out
}

/// The size, as `(rows, cols)`, the selected agent's terminal gets on a screen of `area`, or
/// `None` when the pane is not shown. The loop resizes the session to this.
#[must_use]
pub fn terminal_size(area: Rect) -> Option<(u16, u16)> {
    let pane = areas(area, Panel::Terminal).terminal?;
    let inner = Block::bordered().inner(pane);
    Some((inner.height, inner.width))
}

fn alert_text(app: &App) -> Option<String> {
    if let Some(notice) = &app.notice {
        return Some(notice.clone());
    }
    let alert = app.alerts().last()?;
    let name = app
        .sessions()
        .iter()
        .find(|s| s.id == alert.session)
        .map_or_else(|| "?".to_owned(), session_name);
    Some(format!("{name}: {}", alert.text))
}

/// The project's name for display. It is the agent's to choose, so it is escaped by the same rule
/// as every other untrusted text in the product (control, escape and direction characters become
/// visible `\u{..}` forms) and never trusted to look like anything the supervisor says.
fn session_name(session: &Session) -> String {
    let raw = session.spec.project.file_name().map_or_else(
        || session.spec.project.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    crate::text::EscapedBounded::new(&raw, SHOWN_CHARS).to_string()
}

/// The part of a row that is the supervisor's: the state words, and the unread count after them.
fn row_tail(session: &Session) -> String {
    let mut tail = state_words(session);
    if session.unread_denials > 0 {
        tail.push_str(&format!(" ({})", session.unread_denials));
    }
    tail
}

/// One row of the list in `width` columns: the number and the name on the left, cut with `~` if it
/// does not fit, and the state on the right where a name cannot reach it. The name is the
/// agent's; the state is the supervisor's, so the state is the one that always stays.
fn row_text(index: usize, session: &Session, width: usize) -> (String, String) {
    let tail = row_tail(session);
    let head = format!("{} {}", index + 1, session_name(session));
    // One space between the name and the state, and the tail never shrinks.
    let room = width.saturating_sub(Span::raw(&tail).width() + 1);
    let shown: String = if Span::raw(&head).width() > room {
        let mut left = room.saturating_sub(1);
        let span = Span::raw(&head);
        let mut cut = String::new();
        for grapheme in span.styled_graphemes(Style::default()) {
            let cells = Span::raw(grapheme.symbol).width();
            if cells > left {
                break;
            }
            cut.push_str(grapheme.symbol);
            left -= cells;
        }
        if room > 0 {
            cut.push('~');
        }
        cut
    } else {
        head
    };
    (format!("{shown} "), tail)
}

/// The words a row shows for a phase.
fn state_words(session: &Session) -> String {
    match (&session.phase, &session.exit) {
        (Phase::Exited, Some(exit)) => match (exit.code, exit.signal) {
            (Some(code), _) => format!("Exited {code}"),
            (None, Some(signal)) => format!("Exited signal {signal}"),
            (None, None) => "Exited".to_owned(),
        },
        (Phase::Starting, _) => "Starting".to_owned(),
        (Phase::Approve, _) => "Approve".to_owned(),
        (Phase::Running, _) => "Running".to_owned(),
        (Phase::Stopping, _) => "Stopping".to_owned(),
        (Phase::Exited, None) => "Exited".to_owned(),
        (Phase::Failed, _) => "Failed".to_owned(),
        (Phase::Lost, _) => "Lost".to_owned(),
    }
}

fn state_style(look: Look, session: &Session) -> Style {
    let unclean = session
        .exit
        .as_ref()
        .is_some_and(|e| matches!(e.cleanup, Cleanup::Failed { .. }));
    match session.phase {
        Phase::Running => look.fg(Color::Green),
        Phase::Approve => look.fg(Color::Yellow),
        Phase::Failed | Phase::Lost => look.fg(Color::Red),
        _ if unclean => look.fg(Color::Red),
        _ => Style::new(),
    }
}

/// Where a session's screen is, for drawing. The loop gives it from the runtime.
pub type Screens<'a> = &'a dyn Fn(SessionId) -> Option<Arc<Shared>>;

/// Draws the whole supervisor.
pub fn draw(frame: &mut Frame<'_>, app: &App, screens: Screens<'_>, look: Look) {
    let areas = areas(frame.area(), app.panel);
    if let Some(rect) = areas.sessions {
        draw_sessions(frame, rect, app, look);
    }
    if let Some(rect) = areas.terminal {
        draw_terminal(frame, rect, app, screens, look);
    }
    if let Some(rect) = areas.lower {
        draw_lower(frame, rect, app, look);
    }
    if Layout::for_size(frame.area().width, frame.area().height) == Layout::Tiny {
        draw_too_small(frame, areas.body);
    }
    if let Some(text) = alert_text(app) {
        frame.render_widget(
            Paragraph::new(text).style(look.fg(Color::Yellow)),
            areas.alert,
        );
    }
    let status = status_line(app);
    let short = match app.mode {
        Mode::Overview => " OVERVIEW Enter interact | n new | Tab panels | ? | q quit",
        Mode::Interact => " INTERACT Ctrl-g leaves | Ctrl-g x2 sends Ctrl-g",
        Mode::Launch => " LAUNCH Enter starts | Tab field | Space toggle | Esc cancel",
        Mode::Confirm => " CONFIRM y confirms | other key cancels",
        Mode::Help => " HELP Esc or ? closes",
    };
    let status = if Span::raw(&status).width() > usize::from(areas.status.width) {
        short
    } else {
        &status
    };
    frame.render_widget(Paragraph::new(status), areas.status);
    draw_modal(frame, areas.body, app);
    if !look.color {
        for cell in &mut frame.buffer_mut().content {
            let modifiers = cell.modifier;
            cell.set_style(Style::reset().add_modifier(modifiers));
        }
    }
}

fn draw_sessions(frame: &mut Frame<'_>, rect: Rect, app: &App, look: Look) {
    let rows: Vec<ListItem<'_>> = app
        .sessions()
        .iter()
        .enumerate()
        .map(|(i, session)| {
            // The block's border and the highlight symbol take 4 columns of the list's width.
            let (head, tail) = row_text(i, session, usize::from(rect.width).saturating_sub(4));
            let words = state_words(session);
            let count = tail
                .strip_prefix(words.as_str())
                .unwrap_or_default()
                .to_owned();
            let mut spans = vec![
                Span::raw(head),
                Span::styled(words, state_style(look, session)),
            ];
            if !count.is_empty() {
                spans.push(Span::raw(count));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut state = ListState::default().with_selected(Some(app.selected_index()));
    if app.sessions().is_empty() {
        state = ListState::default();
    }
    let list = List::new(rows)
        .block(Block::bordered().title(" Sessions "))
        .highlight_symbol("> ")
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    if app.sessions().is_empty() {
        let text = Paragraph::new("No sessions yet.\nPress n to start one.")
            .block(Block::bordered().title(" Sessions "));
        frame.render_widget(text, rect);
    } else {
        frame.render_stateful_widget(list, rect, &mut state);
    }
}

fn draw_too_small(frame: &mut Frame<'_>, body: Rect) {
    let rows = body.height.min(3);
    let rect = Rect::new(body.x, body.y + body.height - rows, body.width, rows);
    frame.render_widget(
        Paragraph::new("Make the terminal larger to see the agent's terminal.")
            .wrap(Wrap { trim: true }),
        rect,
    );
}

/// The most characters of an agent-chosen path or command shown in a title or dialog.
const SHOWN_CHARS: usize = 60;

/// A path as the owner sees it: control, escape and direction characters are visible `\u{..}`
/// forms, and a long one is cut. A path is the agent's to choose, so it is never shown raw
/// (hb-807 review B, LOW 4).
fn shown_path(path: &std::path::Path) -> String {
    crate::text::EscapedBounded::new(&path.to_string_lossy(), SHOWN_CHARS).to_string()
}

fn fit(text: &str, cells: usize) -> String {
    let span = Span::raw(text);
    if span.width() <= cells {
        return text.to_owned();
    }
    let mut left = cells.saturating_sub(1);
    let mut out = String::new();
    for g in span.styled_graphemes(Style::default()) {
        let width = Span::raw(g.symbol).width();
        if width > left {
            break;
        }
        left -= width;
        out.push_str(g.symbol);
    }
    if cells > 0 {
        out.push('~');
    }
    out
}

fn terminal_title(app: &App, session: &Session, blocked: bool) -> String {
    let command = session.spec.command.first().map_or("", String::as_str);
    format!(
        " keys: {} | {}{} | {} | {} | {} ",
        if app.mode == Mode::Interact {
            "agent"
        } else {
            "supervisor"
        },
        state_words(session),
        if blocked { " | clipboard blocked" } else { "" },
        session_name(session),
        crate::text::EscapedBounded::new(command, SHOWN_CHARS),
        shown_path(&session.spec.project),
    )
}

fn draw_terminal(frame: &mut Frame<'_>, rect: Rect, app: &App, screens: Screens<'_>, look: Look) {
    let Some(session) = app.selected() else {
        frame.render_widget(
            Paragraph::new("No session selected.").block(Block::bordered().title(" Terminal ")),
            rect,
        );
        return;
    };
    let shared = screens(session.id);
    let blocked = shared.as_ref().is_some_and(|s| {
        s.screen
            .lock()
            .is_ok_and(|screen| screen.suppressed().clipboard_writes > 0)
    });
    let border = if app.mode == Mode::Interact {
        look.fg(Color::Cyan)
    } else {
        Style::new()
    };
    let block = Block::bordered()
        .border_style(border)
        .title(terminal_title(app, session, blocked));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    match (&session.phase, shared) {
        (Phase::Approve, _) => frame.render_widget(
            Paragraph::new("This session needs approval before it can run.\nPress a to review it.")
                .wrap(Wrap { trim: true }),
            inner,
        ),
        (Phase::Failed, None) => frame.render_widget(
            Paragraph::new(session.failure.clone().unwrap_or_default()).wrap(Wrap { trim: true }),
            inner,
        ),
        (_, Some(shared)) => draw_agent(frame, inner, &shared, app.mode == Mode::Interact),
        (_, None) => {}
    }
}

fn draw_agent(frame: &mut Frame<'_>, inner: Rect, shared: &Shared, show_cursor: bool) {
    let Ok(screen) = shared.screen.lock() else {
        return;
    };
    let mut cursor = Cursor::default();
    if !show_cursor {
        cursor.hide();
    }
    frame.render_widget(PseudoTerminal::new(screen.screen()).cursor(cursor), inner);
    defuse_cells(frame.buffer_mut(), inner);
}

/// What replaces a character that can hide or reorder text.
const DEFUSED: &str = "\u{fffd}";

/// Replaces, in the pane's cells, every character that the product's own text rule escapes
/// (direction overrides, zero-width and other invisible format characters). The emulator keeps
/// them in a cell and they would reach the real terminal as written, where one can reorder the
/// supervisor's words beside the pane or make the agent's text read differently from what it is
/// (hb-807 review B, LOW 3). Control characters never get into a cell, so only these are left.
fn defuse_cells(buffer: &mut ratatui::buffer::Buffer, area: Rect) {
    for y in area.top()..area.bottom() {
        for x in area.left()..area.right() {
            let cell = &mut buffer[(x, y)];
            if cell.symbol().chars().any(crate::text::needs_escaping) {
                cell.set_symbol(DEFUSED);
            }
        }
    }
}

fn draw_lower(frame: &mut Frame<'_>, rect: Rect, app: &App, look: Look) {
    let Some(session) = app.selected() else {
        frame.render_widget(Block::bordered().title(" Denials | Proxy "), rect);
        return;
    };
    let dropped = |n: u64| {
        if n > 0 {
            format!(" ({n} dropped)")
        } else {
            String::new()
        }
    };
    let titles = [
        format!(
            "Denials ({}){}",
            session.denials.len() as u64 + session.denials.evicted,
            dropped(session.dropped_denials)
        ),
        format!(
            "Proxy ({}){}",
            session.proxy.len() as u64 + session.proxy.evicted,
            dropped(session.dropped_proxy)
        ),
    ];
    let selected = usize::from(app.tab == Tab::Proxy);
    let tabs = Tabs::new(titles)
        .select(selected)
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD))
        .block(Block::bordered().title(format!(" {} ", session_name(session))));
    let [bar, content] =
        ratatui::layout::Layout::vertical([Constraint::Length(3), Constraint::Min(0)]).areas(rect);
    frame.render_widget(tabs, bar);
    let block = Block::new().borders(Borders::LEFT | Borders::RIGHT | Borders::BOTTOM);
    let inner = block.inner(content);
    frame.render_widget(block, content);
    match app.tab {
        Tab::Denials => draw_denials(frame, inner, session),
        Tab::Proxy => draw_proxy(frame, inner, session, look),
    }
}

/// The last `rows` entries, oldest first, so the newest is at the bottom.
fn newest<'a, T>(items: impl Iterator<Item = &'a T>, rows: u16) -> Vec<&'a T> {
    let mut all: Vec<&T> = items.collect();
    let keep = usize::from(rows);
    all.drain(..all.len().saturating_sub(keep));
    all
}

fn draw_denials(frame: &mut Frame<'_>, rect: Rect, session: &Session) {
    if !session.spec.logging.denials {
        frame.render_widget(
            Paragraph::new("Denial logging is off for this session."),
            rect,
        );
        return;
    }
    if session.denials.is_empty() {
        frame.render_widget(Paragraph::new("No denials."), rect);
        return;
    }
    let lines: Vec<Line<'_>> = newest(session.denials.iter(), rect.height)
        .into_iter()
        .map(|d| Line::from(d.as_str()))
        .collect();
    frame.render_widget(Paragraph::new(lines), rect);
}

fn draw_proxy(frame: &mut Frame<'_>, rect: Rect, session: &Session, look: Look) {
    if !session.spec.logging.proxy {
        frame.render_widget(
            Paragraph::new("Proxy logging is off for this session."),
            rect,
        );
        return;
    }
    if session.proxy.is_empty() {
        frame.render_widget(Paragraph::new("No proxy connections."), rect);
        return;
    }
    let rows: Vec<Row<'_>> = newest(session.proxy.iter(), rect.height.saturating_sub(1))
        .into_iter()
        .map(|r| {
            let verdict = if r.verdict.starts_with("refused") {
                look.fg(Color::Red)
            } else {
                Style::new()
            };
            Row::new([
                Cell::from(r.target.clone()),
                Cell::from(r.verdict.clone()).style(verdict),
                Cell::from(format!("{} up", r.up)),
                Cell::from(format!("{} down", r.down)),
            ])
        })
        .collect();
    let widths = [
        Constraint::Min(20),
        Constraint::Length(12),
        Constraint::Length(12),
        Constraint::Length(12),
    ];
    let table = Table::new(rows, widths).header(
        Row::new(["Target", "Verdict", "Sent", "Received"])
            .style(Style::new().add_modifier(Modifier::BOLD)),
    );
    frame.render_widget(table, rect);
}

/// The status bar: the mode in capitals, then the keys that do something now.
fn status_line(app: &App) -> String {
    match app.mode {
        Mode::Overview => " OVERVIEW  Enter interact \u{b7} n new \u{b7} s stop \u{b7} r restart \u{b7} a approve \u{b7} Tab switch \u{b7} ? help \u{b7} q quit".to_owned(),
        Mode::Interact => format!(
            " INTERACT Ctrl-g leaves | Ctrl-g Ctrl-g sends Ctrl-g | keys to {}",
            app.selected().map_or_else(String::new, session_name)
        ),
        Mode::Help => " HELP  Esc or ? closes".to_owned(),
        Mode::Confirm => " CONFIRM  y confirms \u{b7} any other key cancels".to_owned(),
        Mode::Launch => " LAUNCH  Enter starts \u{b7} Tab next field \u{b7} Up/Down recent \u{b7} Esc cancels".to_owned(),
    }
}

fn centered(body: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(body.width);
    let height = height.min(body.height);
    Rect::new(
        body.x + (body.width - width) / 2,
        body.y + (body.height - height) / 2,
        width,
        height,
    )
}

/// Whether the confirmation can name every affected row with its instructions.
#[must_use]
pub fn confirm_fits(app: &App, area: Rect) -> bool {
    let body = areas(area, app.panel).body;
    confirm_text(app).lines().count() <= usize::from(body.height.saturating_sub(2))
        && area.width >= MIN_COLS
        && area.height >= MIN_ROWS
}

fn draw_modal(frame: &mut Frame<'_>, body: Rect, app: &App) {
    let (title, text) = match app.mode {
        Mode::Help => (" Help ", help_text()),
        Mode::Confirm => (" Confirm ", confirm_text(app)),
        Mode::Launch => (
            " Launch a session ",
            launch_text(app, usize::from(body.width.min(70).saturating_sub(2))),
        ),
        Mode::Overview | Mode::Interact => return,
    };
    let width = body.width.min(70).saturating_sub(2) as usize;
    let mut lines: Vec<String> = text.lines().map(|line| fit(line, width)).collect();
    let available = body.height.saturating_sub(2) as usize;
    if lines.len() > available && available > 0 {
        lines.truncate(available);
        if app.mode == Mode::Confirm {
            lines[available - 1] = fit("Names hidden; enlarge. Any key cancels", width);
        }
    }
    let height = (lines.len() as u16).saturating_add(2);
    let rect = centered(body, 70, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(lines.join("\n")).block(Block::bordered().title(title)),
        rect,
    );
}

fn help_text() -> String {
    [
        "Overview keys",
        "  j/k or arrows: select     1-8: jump",
        "  Enter: interact          n: new session",
        "  s: stop (confirm)        r: restart (confirm)",
        "  a: review approval       Tab: switch panel",
        "  ?: help                  q: quit (confirm)",
        "",
        "Interact: every key goes to the selected agent.",
        "Ctrl-g leaves. Ctrl-g twice sends one Ctrl-g.",
        "Denials are information, never permission grants.",
    ]
    .join("\n")
}

fn confirm_text(app: &App) -> String {
    let named = |id: SessionId| {
        app.sessions().iter().find(|s| s.id == id).map_or_else(
            || "this session".to_owned(),
            |s| {
                format!(
                    "{}: {} ({})",
                    s.id.0,
                    session_name(s),
                    shown_path(&s.spec.project),
                )
            },
        )
    };
    let question = match &app.pending {
        Some(Pending::Stop(id)) => format!("Stop {}?", named(*id)),
        Some(Pending::Restart(id)) => format!("Restart {} as a new run?", named(*id)),
        Some(Pending::Quit) => {
            let mut question = "End these sessions and quit?".to_owned();
            for session in app
                .sessions()
                .iter()
                .filter(|s| s.phase.is_live() || s.phase == Phase::Lost)
            {
                question.push_str(&format!(
                    "\n{}{}",
                    named(session.id),
                    if session.phase == Phase::Lost {
                        " [Lost; stopping]"
                    } else {
                        ""
                    }
                ));
            }
            question
        }
        None => "Continue?".to_owned(),
    };
    format!("{question}\n\ny = yes, any other key = cancel")
}

fn field_tail(text: &str, cells: usize) -> String {
    let escaped = crate::text::Escaped(text).to_string();
    if Span::raw(&escaped).width() <= cells {
        return escaped;
    }
    let span = Span::raw(&escaped);
    let graphemes: Vec<_> = span.styled_graphemes(Style::default()).collect();
    let mut width = 1;
    let mut start = graphemes.len();
    while start > 0 {
        let next = Span::raw(graphemes[start - 1].symbol).width();
        if width + next > cells {
            break;
        }
        width += next;
        start -= 1;
    }
    format!(
        "~{}",
        graphemes[start..]
            .iter()
            .map(|g| g.symbol)
            .collect::<String>()
    )
}

fn launch_text(app: &App, width: usize) -> String {
    let mark = |field: Field| if app.form.field == field { ">" } else { " " };
    let cursor = |field: Field| if app.form.field == field { "_" } else { "" };
    let mut lines = vec![
        format!(
            "{} Project: {}{}",
            mark(Field::Project),
            field_tail(&app.form.project, width.saturating_sub(12)),
            cursor(Field::Project)
        ),
        format!(
            "{} Command: {}{}",
            mark(Field::Command),
            field_tail(&app.form.command, width.saturating_sub(12)),
            cursor(Field::Command)
        ),
        format!(
            "{} [{}] Log denials",
            mark(Field::Denials),
            if app.form.logging.denials { "x" } else { " " }
        ),
        format!(
            "{} [{}] Log proxy",
            mark(Field::Proxy),
            if app.form.logging.proxy { "x" } else { " " }
        ),
        String::new(),
    ];
    let recent = app.recent_projects();
    if !recent.is_empty() {
        lines.push("Recent projects (Up/Down):".to_owned());
        for (i, project) in recent.iter().take(5).enumerate() {
            let at = if app.form.recent == Some(i) { "*" } else { " " };
            lines.push(format!("  {at} {}", shown_path(project)));
        }
    }
    lines.join("\n")
}
#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_three_test_sizes_and_the_edges_pick_the_layouts_the_design_names() {
        assert_eq!(Layout::for_size(120, 40), Layout::Wide);
        assert_eq!(Layout::for_size(80, 24), Layout::Narrow);
        assert_eq!(Layout::for_size(60, 15), Layout::Narrow);
        assert_eq!(Layout::for_size(59, 40), Layout::Tiny);
        assert_eq!(Layout::for_size(120, 14), Layout::Tiny);
        assert_eq!(Layout::for_size(100, 24), Layout::Wide);
        assert_eq!(Layout::for_size(99, 24), Layout::Narrow);
        assert_eq!(Layout::for_size(100, 23), Layout::Narrow);
    }
    // ========================================================================
    // Screens: insta snapshots (text, then one style line per row that has styling)
    // ========================================================================

    use crate::session::supervised::{Cleanup, Event, Verdict};
    use crate::supervise::app::{LaunchSpec, Msg};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::style::Modifier;
    use std::collections::HashMap;
    use std::path::PathBuf;

    struct Scene {
        app: App,
        screens: HashMap<SessionId, Arc<Shared>>,
    }

    fn launch(app: &mut App, name: &str, command: &str) {
        app.update(Msg::Launch(LaunchSpec {
            logging: Default::default(),
            project: PathBuf::from(format!("/work/{name}")),
            command: vec![command.to_owned()],
        }));
    }

    fn event(app: &mut App, id: u32, seq: u64, event: Event) {
        app.update(Msg::Channel {
            id: SessionId(id),
            generation: 1,
            seq,
            event,
        });
    }

    /// shopfront running (with two denials and three proxy rows), billing waiting for approval,
    /// docs exited 0.
    fn scene() -> Scene {
        let mut app = App::new();
        launch(&mut app, "shopfront", "claude");
        launch(&mut app, "billing", "pi");
        launch(&mut app, "docs", "opencode");
        event(&mut app, 1, 1, Event::Starting {});
        event(&mut app, 1, 2, Event::Running { agent_pid: 11 });
        event(
            &mut app,
            1,
            3,
            Event::Denial {
                text: "file-read ~/.ssh/id_rsa".into(),
            },
        );
        event(
            &mut app,
            1,
            4,
            Event::Denial {
                text: "proxy refused api.other.com:443 not_allowed".into(),
            },
        );
        for (n, (host, ok)) in [
            ("api.example.com", true),
            ("api.other.com", false),
            ("registry.npmjs.org", true),
        ]
        .into_iter()
        .enumerate()
        {
            event(
                &mut app,
                1,
                5 + n as u64,
                Event::Proxy {
                    host: Some(host.into()),
                    port: Some(443),
                    decision: if ok {
                        Verdict::Allowed {}
                    } else {
                        Verdict::Refused {
                            code: "not_allowed".into(),
                            reason: String::new(),
                        }
                    },
                    up: 1200,
                    down: 48_000,
                },
            );
        }
        event(
            &mut app,
            1,
            8,
            Event::Dropped {
                denials: 0,
                proxy: 2,
            },
        );
        event(&mut app, 2, 1, Event::Starting {});
        event(
            &mut app,
            2,
            2,
            Event::ApprovalRequired {
                root: "/work/billing".into(),
            },
        );
        event(&mut app, 3, 1, Event::Starting {});
        event(&mut app, 3, 2, Event::Running { agent_pid: 12 });
        event(&mut app, 3, 3, Event::Stopping {});
        event(
            &mut app,
            3,
            4,
            Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: Cleanup::Complete {},
            },
        );
        app.update(Msg::Select(-2));
        let mut screens = HashMap::new();
        let shared = Shared::new(24, 80);
        if let Ok(mut screen) = shared.screen.lock() {
            screen.process(b"$ claude\r\n\x1b[1mWelcome\x1b[0m to shopfront\r\n> fix the cart total\r\n\x1b[32mdone\x1b[0m");
        }
        screens.insert(SessionId(1), shared);
        screens.insert(SessionId(3), Shared::new(24, 80));
        Scene { app, screens }
    }

    fn code(style: Style) -> char {
        if style.add_modifier.contains(Modifier::REVERSED) {
            'R'
        } else {
            match style.fg {
                Some(Color::Green) => 'g',
                Some(Color::Yellow) => 'y',
                Some(Color::Red) => 'r',
                Some(Color::Cyan) => 'c',
                _ if style.add_modifier.contains(Modifier::BOLD) => 'B',
                _ => ' ',
            }
        }
    }

    fn render(scene: &Scene, cols: u16, rows: u16, look: Look) -> String {
        let mut terminal =
            Terminal::new(TestBackend::new(cols, rows)).unwrap_or_else(|_| std::process::abort());
        if let Some((r, c)) = terminal_size(Rect::new(0, 0, cols, rows))
            && let Some(shared) = scene.app.selected().and_then(|s| scene.screens.get(&s.id))
            && let Ok(mut screen) = shared.screen.lock()
        {
            screen.resize(r, c);
        }
        let lookup = |id: SessionId| scene.screens.get(&id).cloned();
        let _ = terminal.draw(|frame| draw(frame, &scene.app, &lookup, look));
        let buffer = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..rows {
            let line: String = (0..cols)
                .map(|x| buffer[(x, y)].symbol().to_owned())
                .collect();
            let styles: String = (0..cols).map(|x| code(buffer[(x, y)].style())).collect();
            out.push_str(line.trim_end());
            out.push('\n');
            if !styles.trim().is_empty() {
                out.push_str(&format!("  styles: {}\n", styles.trim_end()));
            }
        }
        out
    }

    const COLOR: Look = Look { color: true };
    const PLAIN: Look = Look { color: false };

    /// A scene with one running session in a project at `path` (the agent's to choose).
    fn scene_at(path: &str) -> Scene {
        let mut app = App::new();
        app.update(Msg::Launch(LaunchSpec {
            project: PathBuf::from(path),
            command: vec!["claude".to_owned()],
            logging: Default::default(),
        }));
        event(&mut app, 1, 1, Event::Starting {});
        event(&mut app, 1, 2, Event::Running { agent_pid: 11 });
        let shared = Shared::new(30, 100);
        Scene {
            app,
            screens: HashMap::from([(SessionId(1), shared)]),
        }
    }

    #[test]
    fn invisible_and_reordering_characters_in_the_agents_output_do_not_reach_the_frame() {
        let scene = scene_at("/work/shop");
        let shared = &scene.screens[&SessionId(1)];
        if let Ok(mut screen) = shared.screen.lock() {
            screen.process("safe \u{202e}gnp.exe\u{200b} \u{2066}x\u{2069} tail".as_bytes());
        }
        let text = render(&scene, 100, 24, PLAIN);
        for bad in ['\u{202e}', '\u{200b}', '\u{2066}', '\u{2069}'] {
            assert!(!text.contains(bad), "{bad:?} reached the frame");
        }
        assert!(text.contains("safe"), "ordinary text was lost:\n{text}");
        assert!(text.contains("tail"), "ordinary text was lost:\n{text}");
    }

    /// The pane's row that holds `needle`, with the continuation cells of wide characters dropped,
    /// so what is compared is the text as written.
    fn pane_text(text: &str, needle: &str) -> String {
        let line = text
            .lines()
            .find(|l| l.contains(needle))
            .unwrap_or_default();
        line.chars().filter(|c| *c != ' ').collect()
    }

    /// The column, counted in cells, where `marker` starts in the pane's row. A wide character
    /// takes two cells (the buffer holds the character and then a blank continuation).
    fn marker_column(text: &str, marker: char) -> Option<usize> {
        let line = text.lines().find(|l| l.contains(marker))?;
        line.chars().position(|c| c == marker)
    }

    #[test]
    fn ordinary_wide_text_is_untouched_by_defusing() {
        let scene = scene_at("/work/shop");
        let shared = &scene.screens[&SessionId(1)];
        if let Ok(mut screen) = shared.screen.lock() {
            screen.process("\u{4e2d}\u{6587}|A".as_bytes());
        }
        let text = render(&scene, 100, 24, PLAIN);
        assert!(
            pane_text(&text, "|A").contains("\u{4e2d}\u{6587}|A"),
            "wide text was disturbed:\n{text}"
        );
    }

    #[test]
    fn a_character_with_a_hiding_mark_is_replaced_and_the_cells_after_it_do_not_move() {
        // The same row twice: once clean, once with a joiner after the wide character. The marker
        // after it must sit in the same column in both, so defusing replaced a cell and did not
        // insert or remove one.
        let at = |content: &str| {
            let scene = scene_at("/work/shop");
            let shared = &scene.screens[&SessionId(1)];
            if let Ok(mut screen) = shared.screen.lock() {
                screen.process(content.as_bytes());
            }
            render(&scene, 100, 24, PLAIN)
        };
        let clean = at("\u{4e2d}|B");
        let hostile = at("\u{4e2d}\u{200d}|B");
        assert!(
            !hostile.contains('\u{200d}'),
            "the joiner reached the frame"
        );
        assert_eq!(
            marker_column(&clean, 'B'),
            marker_column(&hostile, 'B'),
            "the cell after the character moved:\nclean:   {clean}\nhostile: {hostile}"
        );
    }

    #[test]
    fn defusing_covers_the_right_edge_of_the_pane_and_leaves_the_border_and_title_alone() {
        let scene = scene_at("/work/shop");
        let shared = &scene.screens[&SessionId(1)];
        let width = terminal_size(Rect::new(0, 0, 100, 24)).map_or(70, |(_, c)| usize::from(c));
        // Fill a row so the last column of the pane holds a direction override.
        let mut row = "a".repeat(width.saturating_sub(1));
        row.push('\u{202e}');
        if let Ok(mut screen) = shared.screen.lock() {
            screen.process(format!("{row}\r\n").as_bytes());
        }
        let text = render(&scene, 100, 24, PLAIN);
        assert!(
            !text.contains('\u{202e}'),
            "the last column was not defused"
        );
        // The trusted title is untouched by the pass over the pane.
        assert!(text.contains("keys: supervisor"), "{text}");
        assert!(
            text.contains('\u{250c}') && text.contains('\u{2510}'),
            "the border was damaged"
        );
    }

    #[test]
    fn defusing_is_repeatable_across_frames() {
        let scene = scene_at("/work/shop");
        let shared = &scene.screens[&SessionId(1)];
        if let Ok(mut screen) = shared.screen.lock() {
            screen.process("x\u{202e}y\u{2066}z".as_bytes());
        }
        let first = render(&scene, 100, 24, PLAIN);
        let second = render(&scene, 100, 24, PLAIN);
        assert_eq!(first, second, "a second frame drew something different");
        assert!(!second.contains('\u{202e}') && !second.contains('\u{2066}'));
    }

    #[test]
    fn a_long_project_path_cannot_push_the_supervisors_words_out_of_the_pane_title() {
        let long = format!("/work/{}", "d".repeat(400));
        let text = render(&scene_at(&long), 100, 24, PLAIN);
        let title = text
            .lines()
            .find(|l| l.contains("keys:"))
            .unwrap_or_default();
        assert!(title.contains("keys: supervisor"), "{title}");
        assert!(title.contains("Running"), "{title}");
        assert!(
            !text.contains(&"d".repeat(100)),
            "the long path was shown whole"
        );
    }

    #[test]
    fn control_and_direction_characters_in_a_project_path_are_shown_as_escapes() {
        let hostile = "/work/a\u{1b}[2J\u{202e}gnp.exe/b";
        let text = render(&scene_at(hostile), 120, 24, PLAIN);
        assert!(
            !text.contains('\u{1b}'),
            "an escape byte reached the screen"
        );
        assert!(
            !text.contains('\u{202e}'),
            "a direction override reached the screen"
        );
        assert!(
            text.contains("\\u{1b}"),
            "the escape was not made visible:\n{text}"
        );
    }

    #[test]
    fn the_confirm_dialog_shows_a_hostile_path_escaped_and_cut() {
        // The long part comes first, so the direction override is past the cut and must not be
        // needed to see the cut: the dialog is checked for each on its own.
        // The dialog clips by its own width, so check what it is given, not what fits on a screen.
        let long = scene_at(&format!("/work/{}", "p".repeat(300)));
        let asked = {
            let mut app = long.app;
            app.update(Msg::AskStop);
            confirm_text(&app)
        };
        assert!(asked.contains("Stop "), "{asked}");
        assert!(asked.contains("..."), "the long path was not cut: {asked}");
        assert!(
            !asked.contains(&"p".repeat(100)),
            "the dialog was given the long path whole"
        );

        let mut hostile = scene_at("/work/a\u{202e}x");
        hostile.app.update(Msg::AskStop);
        let text = render(&hostile, 120, 30, PLAIN);
        assert!(text.contains("Stop "), "{text}");
        assert!(
            !text.contains('\u{202e}'),
            "a direction override reached the dialog"
        );
    }

    #[test]
    fn confirmation_fit_agrees_with_visible_rows_and_instructions() {
        let mut scene = scene();
        scene.app.update(Msg::AskQuit);
        assert!(confirm_fits(&scene.app, Rect::new(0, 0, 80, 24)));
        let shown = render(&scene, 80, 24, PLAIN);
        assert!(shown.contains("1: shopfront") && shown.contains("y = yes"));
        let mut crowded = App::new();
        for _ in 0..super::super::app::MAX_SESSIONS {
            crowded.update(Msg::Launch(LaunchSpec {
                logging: Default::default(),
                project: "/same/project".into(),
                command: vec!["agent".into()],
            }));
        }
        crowded.update(Msg::AskQuit);
        assert!(confirm_fits(&crowded, Rect::new(0, 0, 60, 15)));
        assert!(!confirm_fits(&crowded, Rect::new(0, 0, 60, 14)));
        let question = confirm_text(&crowded);
        for id in 1..=8 {
            assert!(question.contains(&format!("{id}: project")));
        }
        assert!(!confirm_fits(&scene.app, Rect::new(0, 0, 60, 6)));
        // Rows beyond the eight live slots can exist, but are not quit targets.
        assert!(!shown.contains("3: docs"));
    }

    #[test]
    fn compact_screens_keep_escape_fields_and_named_confirmation_visible() {
        let mut scene = scene();
        scene.app.update(Msg::EnterInteract);
        let shown = render(&scene, 60, 15, PLAIN);
        assert!(shown.contains("INTERACT") && shown.contains("Ctrl-g leaves"));
        scene.app.update(Msg::LeaveInteract);
        scene.app.update(Msg::OpenLaunch {
            cwd: PathBuf::from(format!("/{}TAIL", "界".repeat(90))),
        });
        scene.app.form.command = format!("agent {}END", "x".repeat(180));
        let shown = render(&scene, 60, 15, PLAIN);
        for word in [
            "Project:",
            "TAIL",
            "Command:",
            "END_",
            "Log denials",
            "Log proxy",
            "Esc cancel",
        ] {
            assert!(shown.contains(word), "missing {word}: {shown}");
        }
        scene.app.update(Msg::CancelLaunch);
        scene.app.update(Msg::AskQuit);
        let shown = render(&scene, 60, 15, PLAIN);
        assert!(
            shown.contains("shopfront") && !shown.contains("3: docs"),
            "{shown}"
        );
        assert!(shown.contains("y = yes") && shown.contains("CONFIRM"));
    }

    #[test]
    fn no_color_resets_indexed_rgb_and_background_agent_cells() {
        let mut scene = scene();
        scene.app.panel = Panel::Terminal;
        let shared = claims::assert_some!(scene.screens.get(&SessionId(1)));
        claims::assert_ok!(shared.screen.lock())
            .process(b"\x1b[2J\x1b[H\x1b[38;5;196mI\x1b[38;2;1;2;3mR\x1b[41mB");
        for look in [COLOR, PLAIN] {
            let mut terminal = claims::assert_ok!(Terminal::new(TestBackend::new(80, 24)));
            let lookup = |id| scene.screens.get(&id).cloned();
            claims::assert_ok!(terminal.draw(|f| draw(f, &scene.app, &lookup, look)));
            let cells = &terminal.backend().buffer().content;
            if look.color {
                assert!(cells.iter().any(|c| matches!(c.fg, Color::Indexed(_))));
                assert!(cells.iter().any(|c| matches!(c.fg, Color::Rgb(..))));
                assert!(cells.iter().any(|c| c.bg != Color::Reset));
            } else {
                assert!(
                    cells
                        .iter()
                        .all(|c| c.fg == Color::Reset && c.bg == Color::Reset)
                );
            }
        }
    }

    #[test]
    fn snapshot_overview_120x40_color() {
        insta::assert_snapshot!(render(&scene(), 120, 40, COLOR));
    }

    #[test]
    fn snapshot_overview_120x40_no_color() {
        insta::assert_snapshot!(render(&scene(), 120, 40, PLAIN));
    }

    #[test]
    fn snapshot_overview_80x24_color() {
        insta::assert_snapshot!(render(&scene(), 80, 24, COLOR));
    }

    #[test]
    fn snapshot_overview_80x24_no_color() {
        insta::assert_snapshot!(render(&scene(), 80, 24, PLAIN));
    }

    #[test]
    fn snapshot_overview_60x15_color() {
        insta::assert_snapshot!(render(&scene(), 60, 15, COLOR));
    }

    #[test]
    fn snapshot_overview_60x15_no_color() {
        insta::assert_snapshot!(render(&scene(), 60, 15, PLAIN));
    }

    #[test]
    fn snapshot_narrow_terminal_panel_80x24() {
        let mut scene = scene();
        scene.app.update(Msg::NextPanel(true));
        insta::assert_snapshot!(render(&scene, 80, 24, COLOR));
    }

    #[test]
    fn snapshot_narrow_proxy_panel_80x24() {
        let mut scene = scene();
        for _ in 0..3 {
            scene.app.update(Msg::NextPanel(true));
        }
        insta::assert_snapshot!(render(&scene, 80, 24, COLOR));
    }

    #[test]
    fn snapshot_proxy_tab_120x40() {
        let mut scene = scene();
        scene.app.update(Msg::NextTab);
        insta::assert_snapshot!(render(&scene, 120, 40, COLOR));
    }

    #[test]
    fn snapshot_interact_120x40() {
        let mut scene = scene();
        scene.app.update(Msg::EnterInteract);
        insta::assert_snapshot!(render(&scene, 120, 40, COLOR));
    }

    #[test]
    fn snapshot_help_80x24() {
        let mut scene = scene();
        scene.app.update(Msg::ToggleHelp);
        insta::assert_snapshot!(render(&scene, 80, 24, COLOR));
    }

    #[test]
    fn snapshot_confirm_stop_names_the_session_80x24() {
        let mut scene = scene();
        scene.app.update(Msg::AskStop);
        let text = render(&scene, 80, 24, COLOR);
        assert!(
            text.contains("Stop 1: shopfront (/work/shopfront)?"),
            "{text}"
        );
        insta::assert_snapshot!(text);
    }

    #[test]
    fn snapshot_confirm_quit_names_each_session_80x24() {
        let mut scene = scene();
        scene.app.update(Msg::AskQuit);
        insta::assert_snapshot!(render(&scene, 80, 24, COLOR));
    }

    #[test]
    fn snapshot_launch_form_with_recent_projects_80x24() {
        let mut scene = scene();
        scene.app.update(Msg::OpenLaunch {
            cwd: PathBuf::from("/work/shopfront"),
        });
        scene
            .app
            .update(Msg::Form(crate::supervise::app::FormEdit::Recent(true)));
        insta::assert_snapshot!(render(&scene, 80, 24, COLOR));
    }

    #[test]
    fn snapshot_a_terminal_too_small_for_the_agent_shows_only_the_list_50x12() {
        insta::assert_snapshot!(render(&scene(), 50, 12, COLOR));
    }

    #[test]
    fn snapshot_empty_app_120x40() {
        let scene = Scene {
            app: App::new(),
            screens: HashMap::new(),
        };
        insta::assert_snapshot!(render(&scene, 120, 40, COLOR));
    }

    // ========================================================================
    // Rules the snapshots do not show by themselves
    // ========================================================================

    #[test]
    fn no_color_removes_every_color_but_keeps_the_words() {
        let scene_with = |f: fn(&mut App)| {
            let mut scene = scene();
            f(&mut scene.app);
            scene
        };
        // Colors used, by scene: green/yellow in the list, red for a refused connection on the
        // Proxy tab, cyan on the border while interacting.
        let proxy = |app: &mut App| {
            app.update(Msg::NextTab);
        };
        let interact = |app: &mut App| {
            app.update(Msg::EnterInteract);
        };
        let colors_in = |text: &str| -> String {
            text.lines()
                .filter_map(|l| l.strip_prefix("  styles: "))
                .flat_map(str::chars)
                .filter(|c| "gyrc".contains(*c))
                .collect()
        };
        let words = |text: &str| {
            text.lines()
                .filter(|l| !l.starts_with("  styles: "))
                .collect::<Vec<_>>()
                .join(
                    "
",
                )
        };
        for (name, f) in [("proxy", proxy as fn(&mut App)), ("interact", interact)] {
            let color = render(&scene_with(f), 120, 40, COLOR);
            let plain = render(&scene_with(f), 120, 40, PLAIN);
            assert_eq!(colors_in(&plain), "", "{name}");
            assert!(!colors_in(&color).is_empty(), "{name}");
            assert_eq!(words(&color), words(&plain), "{name}");
        }
        let all = colors_in(&render(&scene_with(proxy), 120, 40, COLOR));
        for mark in ['y', 'r'] {
            assert!(all.contains(mark), "{mark}");
        }
        // The selected row is reversed, so green shows on a running session that is not selected.
        let other = |app: &mut App| {
            app.update(Msg::Select(1));
        };
        assert!(colors_in(&render(&scene_with(other), 120, 40, COLOR)).contains('g'));
        assert!(colors_in(&render(&scene_with(interact), 120, 40, COLOR)).contains('c'));
        let plain = render(&scene(), 120, 40, PLAIN);
        for word in ["Running", "Approve", "Exited 0"] {
            assert!(plain.contains(word), "{word}");
        }
    }

    #[test]
    fn the_variable_decides_the_look_and_an_empty_one_does_not_count() {
        use std::ffi::OsStr;
        assert!(Look::from_no_color(None).color);
        assert!(Look::from_no_color(Some(OsStr::new(""))).color);
        assert!(!Look::from_no_color(Some(OsStr::new("1"))).color);
    }

    #[test]
    fn the_agents_terminal_gets_the_size_the_layout_leaves_it() {
        assert_eq!(terminal_size(Rect::new(0, 0, 120, 40)), Some((26, 90)));
        assert_eq!(terminal_size(Rect::new(0, 0, 80, 24)), Some((20, 78)));
        assert_eq!(terminal_size(Rect::new(0, 0, 60, 15)), Some((11, 58)));
        assert_eq!(terminal_size(Rect::new(0, 0, 50, 12)), None);
    }

    #[test]
    fn drawing_never_panics_at_any_size_in_any_mode() {
        for (cols, rows) in [
            (0, 0),
            (1, 1),
            (10, 3),
            (59, 14),
            (60, 15),
            (99, 23),
            (100, 24),
            (200, 60),
        ] {
            for step in 0..6 {
                let mut scene = scene();
                match step {
                    1 => {
                        scene.app.update(Msg::EnterInteract);
                    }
                    2 => {
                        scene.app.update(Msg::ToggleHelp);
                    }
                    3 => {
                        scene.app.update(Msg::AskStop);
                    }
                    4 => {
                        scene.app.update(Msg::OpenLaunch {
                            cwd: PathBuf::from("/x"),
                        });
                    }
                    5 => {
                        scene.app.update(Msg::NextPanel(true));
                    }
                    _ => {}
                }
                let _ = render(&scene, cols, rows, COLOR);
            }
        }
    }

    // ========================================================================
    // A project's name is the agent's to choose; the state words are the supervisor's
    // ========================================================================

    /// The first row of the session list, as the owner sees it at `cols` wide.
    fn first_row(project: &str, cols: u16) -> String {
        let mut app = App::new();
        launch(&mut app, project, "claude");
        event(&mut app, 1, 1, Event::Starting {});
        event(
            &mut app,
            1,
            2,
            Event::ApprovalRequired { root: "/x".into() },
        );
        let scene = Scene {
            app,
            screens: HashMap::new(),
        };
        let text = render(&scene, cols, 24, PLAIN);
        text.lines()
            .find(|l| l.starts_with("│> 1 "))
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn wide_unicode_names_cannot_hide_the_trusted_state() {
        for width in [60, 80, 120] {
            let row = first_row(&format!("{}Running", "界".repeat(30)), width);
            assert!(
                row.contains("Approve"),
                "trusted state hidden at {width}: {row:?}"
            );
        }
    }

    #[test]
    fn row_name_truncation_uses_cells_and_preserves_grapheme_prefixes() {
        for name in ["界".repeat(30), "e\u{301}".repeat(60), "👩‍💻".repeat(30)] {
            let mut app = App::new();
            launch(&mut app, &name, "claude");
            let session = &app.sessions()[0];
            let original = format!("1 {}", session_name(session));
            for width in [0, 1, 8, 9, 10, 11, 24, 25, 56] {
                let (head, tail) = row_text(0, session, width);
                assert_eq!(tail, row_tail(session));
                if width > Span::raw(&tail).width() {
                    assert!(Span::raw(&head).width() + Span::raw(&tail).width() <= width);
                }
                let prefix = head.trim_end_matches(' ').trim_end_matches('~');
                let mut rebuilt = String::new();
                let span = Span::raw(&original);
                for g in span.styled_graphemes(Style::default()) {
                    if rebuilt == prefix {
                        break;
                    }
                    rebuilt.push_str(g.symbol);
                }
                assert_eq!(rebuilt, prefix, "truncated inside a grapheme");
            }
        }
    }

    #[test]
    fn a_long_name_cannot_push_the_real_state_out_of_the_row() {
        let name = format!("{}Running", "x".repeat(60));
        let row = first_row(&name, 80);
        assert!(
            row.contains("Approve"),
            "the real state was pushed off: {row:?}"
        );
    }

    #[test]
    fn a_name_that_says_running_is_not_mistaken_for_the_state() {
        let row = first_row("billing Running", 80);
        // The name is shown as it is, and what the supervisor says comes last and is true.
        assert!(row.contains("billing Running Approve"), "{row:?}");
        // The row's last word before the border is the real state, whatever the name says.
        assert!(
            row.trim_end_matches(['│', ' ']).ends_with("Approve"),
            "{row:?}"
        );
    }

    #[test]
    fn a_name_with_controls_or_format_characters_is_shown_escaped() {
        for hostile in [
            "a\u{1b}[2Jb",
            "a\u{202e}Running",
            "tab\there",
            "nl\nRunning",
        ] {
            let row = first_row(hostile, 80);
            assert!(
                row.trim_end_matches(['│', ' ']).ends_with("Approve"),
                "{hostile:?} -> {row:?}"
            );
            // No raw control or direction character reaches the screen, anywhere on it.
            let mut app = App::new();
            launch(&mut app, hostile, "claude");
            let scene = Scene {
                app,
                screens: HashMap::new(),
            };
            let screen = render(&scene, 80, 24, PLAIN);
            assert!(
                !screen
                    .chars()
                    .any(|c| c == '\u{1b}' || c == '\u{202e}' || (c.is_control() && c != '\n')),
                "{hostile:?} reached the screen: {screen:?}"
            );
        }
    }
}
