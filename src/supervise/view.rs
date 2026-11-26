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

fn session_name(session: &Session) -> String {
    session.spec.project.file_name().map_or_else(
        || session.spec.project.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
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
    frame.render_widget(Paragraph::new(status_line(app)), areas.status);
    draw_modal(frame, areas.body, app);
}

fn draw_sessions(frame: &mut Frame<'_>, rect: Rect, app: &App, look: Look) {
    let rows: Vec<ListItem<'_>> = app
        .sessions()
        .iter()
        .enumerate()
        .map(|(i, session)| {
            let mut spans = vec![
                Span::raw(format!("{} {} ", i + 1, session_name(session))),
                Span::styled(state_words(session), state_style(look, session)),
            ];
            if session.unread_denials > 0 {
                spans.push(Span::raw(format!(" ({})", session.unread_denials)));
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

/// The title of the terminal pane: which agent it is, in which project, and where keys go.
fn terminal_title(app: &App, session: &Session, blocked: bool) -> String {
    let command = session.spec.command.first().map_or("", String::as_str);
    let mut title = format!(
        " {} \u{b7} {} \u{b7} {} \u{b7} {} \u{b7} keys: {} ",
        session_name(session),
        command,
        state_words(session),
        session.spec.project.display(),
        if app.mode == Mode::Interact {
            "to the agent"
        } else {
            "to the supervisor"
        },
    );
    if blocked {
        title.push_str("\u{b7} clipboard blocked ");
    }
    title
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
            " INTERACT -> {}  every key goes to the agent \u{b7} Ctrl-g leaves \u{b7} Ctrl-g Ctrl-g sends Ctrl-g",
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

fn draw_modal(frame: &mut Frame<'_>, body: Rect, app: &App) {
    let (title, text) = match app.mode {
        Mode::Help => (" Help ", help_text()),
        Mode::Confirm => (" Confirm ", confirm_text(app)),
        Mode::Launch => (" Launch a session ", launch_text(app)),
        Mode::Overview | Mode::Interact => return,
    };
    let height = u16::try_from(text.lines().count())
        .unwrap_or(u16::MAX)
        .saturating_add(2);
    let rect = centered(body, 70, height);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(text)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(title)),
        rect,
    );
}

fn help_text() -> String {
    [
        "Overview keys",
        "  j k, arrows   select a session        1-8   jump to a session",
        "  Enter         type to the agent       n     start a session",
        "  s             stop (asks first)       r     restart (asks first)",
        "  a             review approval         Tab   switch Denials / Proxy",
        "  ?             this help               q     quit (asks first)",
        "",
        "While typing to an agent, every key goes to it.",
        "Ctrl-g returns here. Ctrl-g Ctrl-g sends one Ctrl-g to the agent.",
        "Denials are information; there is no allow action here.",
    ]
    .join("\n")
}

fn confirm_text(app: &App) -> String {
    let named = |id: SessionId| {
        app.sessions().iter().find(|s| s.id == id).map_or_else(
            || "this session".to_owned(),
            |s| format!("{} ({})", session_name(s), s.spec.project.display()),
        )
    };
    let question = match &app.pending {
        Some(Pending::Stop(id)) => format!("Stop {}?", named(*id)),
        Some(Pending::Restart(id)) => format!("Restart {} as a new run?", named(*id)),
        Some(Pending::Quit) => format!("Stop {} running session(s) and quit?", app.live_count()),
        None => "Continue?".to_owned(),
    };
    format!("{question}\n\ny = yes, any other key = cancel")
}

fn launch_text(app: &App) -> String {
    let mark = |field: Field| if app.form.field == field { ">" } else { " " };
    let cursor = |field: Field| if app.form.field == field { "_" } else { "" };
    let mut lines = vec![
        format!(
            "{} Project: {}{}",
            mark(Field::Project),
            app.form.project,
            cursor(Field::Project)
        ),
        format!(
            "{} Command: {}{}",
            mark(Field::Command),
            app.form.command,
            cursor(Field::Command)
        ),
        String::new(),
    ];
    let recent = app.recent_projects();
    if !recent.is_empty() {
        lines.push("Recent projects (Up/Down):".to_owned());
        for (i, project) in recent.iter().take(5).enumerate() {
            let at = if app.form.recent == Some(i) { "*" } else { " " };
            lines.push(format!("  {at} {}", project.display()));
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
        assert!(text.contains("Stop shopfront (/work/shopfront)?"), "{text}");
        insta::assert_snapshot!(text);
    }

    #[test]
    fn snapshot_confirm_quit_counts_running_sessions_80x24() {
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
}
