// ABOUTME: The key router: turns one key press into app messages, deciding who receives it (the supervisor or one agent) from the mode alone.
// ABOUTME: Pure. Ctrl-g leaves Interact at once; a second Ctrl-g straight after sends a literal Ctrl-g to that same session and generation.
//! Key routing (epic hb-b6q).
//!
//! In [`Mode::Interact`] every key goes to the agent except `Ctrl-g`. The first `Ctrl-g` leaves
//! at once, so the status bar is truthful between the two presses; a second `Ctrl-g` as the very
//! next press sends a literal `Ctrl-g` (0x07) to the session the owner was typing to, and goes
//! back to Interact. There is no timer. The router remembers which session and generation it
//! left, and checks that again when the second press arrives, because a restart, an exit or a
//! jump in between would make the memory wrong.
//!
//! The router does no I/O: it returns [`Msg`]s, and the loop that owns the keyboard applies them.

use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use super::app::{App, FormEdit, Generation, Mode, Msg, Phase, SessionId};
use super::input::{encode_key, encode_paste};
use super::terminal::InputModes;
use super::view::Layout;

/// What the router needs to know about the screen and the selected agent.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    /// How much of the screen the terminal allows.
    pub layout: Layout,
    /// The selected agent's input modes, which decide how its keys are encoded.
    pub modes: InputModes,
    /// Where the supervisor was started; the launch form's default project.
    pub cwd: &'a Path,
}

/// The Ctrl-g byte, sent to the agent by `Ctrl-g Ctrl-g`.
const BELL: u8 = 0x07;

/// Remembers a `Ctrl-g` that left Interact, so a second one can send the literal.
#[derive(Debug, Default)]
pub struct Router {
    left: Option<(SessionId, Generation)>,
}

/// Whether this is the supervisor's escape key. `Ctrl-Alt-g` is not: it goes to the agent.
fn is_escape(key: &KeyEvent) -> bool {
    matches!(key.code, KeyCode::Char('g' | 'G'))
        && (key.modifiers == KeyModifiers::CONTROL
            || key.modifiers == KeyModifiers::CONTROL | KeyModifiers::SHIFT)
}

impl Router {
    /// A router with nothing remembered.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The messages for one key event.
    pub fn route(&mut self, app: &App, key: KeyEvent, ctx: &Context<'_>) -> Vec<Msg> {
        // A release changes nothing, and must not cancel a pending `Ctrl-g`: terminals that
        // report releases send the first one between the two presses.
        if key.kind == KeyEventKind::Release {
            return Vec::new();
        }
        if is_escape(&key) && key.kind == KeyEventKind::Repeat {
            return Vec::new();
        }
        match app.mode {
            Mode::Interact => self.interact(app, key, ctx),
            mode => {
                let second = self.left.take();
                if mode == Mode::Overview && is_escape(&key) {
                    return Self::second_escape(app, second);
                }
                match mode {
                    Mode::Overview => overview(&key, ctx),
                    Mode::Help => help(&key),
                    Mode::Confirm => confirm(&key),
                    Mode::Launch => launch(&key),
                    Mode::Interact => Vec::new(),
                }
            }
        }
    }

    /// The messages for pasted text.
    pub fn paste(&mut self, app: &App, text: &str, ctx: &Context<'_>) -> Vec<Msg> {
        self.left = None;
        match app.mode {
            Mode::Interact => target(app)
                .map(|(id, generation)| {
                    vec![Msg::Input {
                        id,
                        generation,
                        bytes: encode_paste(text, ctx.modes),
                    }]
                })
                .unwrap_or_default(),
            Mode::Launch => text
                .chars()
                .filter(|c| !c.is_control())
                .map(|c| Msg::Form(FormEdit::Char(c)))
                .collect(),
            Mode::Overview | Mode::Help | Mode::Confirm => Vec::new(),
        }
    }

    fn interact(&mut self, app: &App, key: KeyEvent, ctx: &Context<'_>) -> Vec<Msg> {
        self.left = None;
        let Some((id, generation)) = target(app) else {
            return vec![Msg::LeaveInteract];
        };
        if ctx.layout == Layout::Tiny {
            // The terminal pane is not shown, so keys must not go to an agent unseen.
            return vec![Msg::LeaveInteract, Msg::TooSmall];
        }
        if is_escape(&key) {
            self.left = Some((id, generation));
            return vec![Msg::LeaveInteract];
        }
        encode_key(key, ctx.modes)
            .map(|bytes| {
                vec![Msg::Input {
                    id,
                    generation,
                    bytes,
                }]
            })
            .unwrap_or_default()
    }

    /// `Ctrl-g` in Overview: the second of a pair only if it is about the same running session.
    fn second_escape(app: &App, left: Option<(SessionId, Generation)>) -> Vec<Msg> {
        match (left, target(app)) {
            (Some(left), Some(now)) if left == now => vec![
                Msg::EnterInteract,
                Msg::Input {
                    id: now.0,
                    generation: now.1,
                    bytes: vec![BELL],
                },
            ],
            _ => Vec::new(),
        }
    }
}

/// The session keys would go to: the selected one, if it is running.
fn target(app: &App) -> Option<(SessionId, Generation)> {
    app.selected()
        .filter(|s| s.phase == Phase::Running)
        .map(|s| (s.id, s.generation))
}

fn overview(key: &KeyEvent, ctx: &Context<'_>) -> Vec<Msg> {
    let narrow = ctx.layout != Layout::Wide;
    let msg = match key.code {
        KeyCode::Char('j') | KeyCode::Down => Msg::Select(1),
        KeyCode::Char('k') | KeyCode::Up => Msg::Select(-1),
        KeyCode::Enter if ctx.layout == Layout::Tiny => Msg::TooSmall,
        KeyCode::Enter => Msg::EnterInteract,
        KeyCode::Char('n') => Msg::OpenLaunch {
            cwd: ctx.cwd.to_path_buf(),
        },
        KeyCode::Char('s') => Msg::AskStop,
        KeyCode::Char('r') => Msg::AskRestart,
        KeyCode::Char('a') => Msg::ReviewApproval,
        KeyCode::Tab if narrow => Msg::NextPanel(true),
        KeyCode::BackTab if narrow => Msg::NextPanel(false),
        KeyCode::Tab | KeyCode::BackTab => Msg::NextTab,
        KeyCode::Char('?') => Msg::ToggleHelp,
        KeyCode::Char('q') => Msg::AskQuit,
        KeyCode::Char(c @ '1'..='8') => Msg::Jump(usize::from(c as u8 - b'0')),
        _ => return Vec::new(),
    };
    vec![msg]
}

fn help(key: &KeyEvent) -> Vec<Msg> {
    match key.code {
        KeyCode::Esc | KeyCode::Char('?') => vec![Msg::ToggleHelp],
        _ => Vec::new(),
    }
}

/// `y` confirms; anything else cancels, so a stray key never stops a session.
fn confirm(key: &KeyEvent) -> Vec<Msg> {
    vec![Msg::Answer(matches!(key.code, KeyCode::Char('y')))]
}

fn launch(key: &KeyEvent) -> Vec<Msg> {
    let plain = key.modifiers - KeyModifiers::SHIFT == KeyModifiers::NONE;
    let msg = match key.code {
        KeyCode::Esc => Msg::CancelLaunch,
        KeyCode::Enter => Msg::SubmitLaunch,
        KeyCode::Tab | KeyCode::BackTab => Msg::Form(FormEdit::SwitchField),
        KeyCode::Up => Msg::Form(FormEdit::Recent(true)),
        KeyCode::Down => Msg::Form(FormEdit::Recent(false)),
        KeyCode::Backspace => Msg::Form(FormEdit::Backspace),
        KeyCode::Char(c) if plain => Msg::Form(FormEdit::Char(c)),
        _ => return Vec::new(),
    };
    vec![msg]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::supervised::Event;
    use crate::supervise::app::{Effect, LaunchSpec};
    use pretty_assertions::assert_eq;
    use std::path::PathBuf;

    const CWD: &str = "/work/here";

    fn ctx(layout: Layout) -> Context<'static> {
        Context {
            layout,
            modes: InputModes::default(),
            cwd: Path::new(CWD),
        }
    }

    fn press(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn plain(c: char) -> KeyEvent {
        press(KeyCode::Char(c), KeyModifiers::NONE)
    }

    fn ctrl_g() -> KeyEvent {
        press(KeyCode::Char('g'), KeyModifiers::CONTROL)
    }

    fn kind(mut key: KeyEvent, kind: KeyEventKind) -> KeyEvent {
        key.kind = kind;
        key
    }

    /// An app with one running session in Overview (id 1, generation 1).
    fn running() -> App {
        let mut app = App::new();
        app.update(Msg::Launch(LaunchSpec {
            project: PathBuf::from("/work/shop"),
            command: vec!["claude".to_owned()],
        }));
        for (n, event) in [Event::Starting {}, Event::Running { agent_pid: 7 }]
            .into_iter()
            .enumerate()
        {
            app.update(Msg::Channel {
                id: SessionId(1),
                generation: 1,
                seq: n as u64 + 1,
                event,
            });
        }
        app
    }

    fn interacting() -> App {
        let mut app = running();
        app.update(Msg::EnterInteract);
        assert_eq!(app.mode, Mode::Interact);
        app
    }

    fn input(bytes: &[u8]) -> Msg {
        Msg::Input {
            id: SessionId(1),
            generation: 1,
            bytes: bytes.to_vec(),
        }
    }

    /// Routes one key and applies the messages, as the loop will; returns what was routed and
    /// the bytes the app would write.
    fn feed(router: &mut Router, app: &mut App, key: KeyEvent, c: &Context<'_>) -> Vec<Msg> {
        let msgs = router.route(app, key, c);
        for msg in msgs.clone() {
            app.update(msg);
        }
        msgs
    }

    fn written(app: &mut App, msgs: Vec<Msg>) -> Vec<Vec<u8>> {
        msgs.into_iter()
            .flat_map(|m| app.update(m))
            .filter_map(|e| match e {
                Effect::Write { bytes, .. } => Some(bytes),
                _ => None,
            })
            .collect()
    }

    // ========================================================================
    // Interact: what reaches the agent
    // ========================================================================

    #[test]
    fn every_key_but_ctrl_g_in_interact_goes_to_the_agent_as_the_encoder_makes_it() {
        let c = ctx(Layout::Wide);
        let keys = [
            (plain('q'), b"q".to_vec()),
            (plain('?'), b"?".to_vec()),
            (press(KeyCode::Esc, KeyModifiers::NONE), vec![0x1b]),
            (press(KeyCode::Tab, KeyModifiers::NONE), vec![b'\t']),
            (press(KeyCode::Enter, KeyModifiers::NONE), vec![b'\r']),
            (press(KeyCode::Char('c'), KeyModifiers::CONTROL), vec![3]),
            (press(KeyCode::Up, KeyModifiers::NONE), b"\x1b[A".to_vec()),
            (
                press(KeyCode::Char('g'), KeyModifiers::ALT),
                vec![0x1b, b'g'],
            ),
            // Ctrl-Alt-g is not the escape: the agent gets it.
            (
                press(
                    KeyCode::Char('g'),
                    KeyModifiers::CONTROL | KeyModifiers::ALT,
                ),
                vec![0x1b, 7],
            ),
        ];
        for (key, bytes) in keys {
            let mut router = Router::new();
            let app = interacting();
            assert_eq!(router.route(&app, key, &c), vec![input(&bytes)], "{key:?}");
        }
    }

    #[test]
    fn interact_keys_follow_the_modes_the_agent_switched_on() {
        let mut c = ctx(Layout::Wide);
        c.modes.application_cursor = true;
        let app = interacting();
        assert_eq!(
            Router::new().route(&app, press(KeyCode::Up, KeyModifiers::NONE), &c),
            vec![input(b"\x1bOA")]
        );
        c.modes.bracketed_paste = true;
        assert_eq!(
            Router::new().paste(&app, "hi", &c),
            vec![input(b"\x1b[200~hi\x1b[201~")]
        );
    }

    #[test]
    fn keys_for_a_session_that_is_not_running_are_not_sent() {
        let mut app = interacting();
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: Some(0),
            signal: None,
        });
        // The app left Interact by itself when the session stopped running.
        assert_eq!(app.mode, Mode::Overview);
        // A key that was already in flight, if the router is still asked in Interact:
        let msgs = Router::new().route(&app, plain('x'), &ctx(Layout::Wide));
        assert_eq!(msgs, vec![]);
    }

    #[test]
    fn input_for_an_older_generation_or_a_stopped_session_becomes_no_write() {
        let mut app = interacting();
        assert_eq!(written(&mut app, vec![input(b"x")]), vec![b"x".to_vec()]);
        let old = Msg::Input {
            id: SessionId(1),
            generation: 0,
            bytes: b"x".to_vec(),
        };
        assert_eq!(written(&mut app, vec![old]), Vec::<Vec<u8>>::new());
        app.update(Msg::AskStop);
        // Not in Overview: nothing changed. Stop it directly instead.
        app.update(Msg::LeaveInteract);
        app.update(Msg::AskStop);
        app.update(Msg::Answer(true));
        assert_eq!(written(&mut app, vec![input(b"x")]), Vec::<Vec<u8>>::new());
    }

    // ========================================================================
    // Ctrl-g
    // ========================================================================

    #[test]
    fn ctrl_g_leaves_interact_at_once_and_sends_nothing() {
        let (mut router, mut app) = (Router::new(), interacting());
        let msgs = feed(&mut router, &mut app, ctrl_g(), &ctx(Layout::Wide));
        assert_eq!(msgs, vec![Msg::LeaveInteract]);
        assert_eq!(app.mode, Mode::Overview);
        assert_eq!(written(&mut app, msgs), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn ctrl_g_twice_sends_one_literal_bell_to_the_same_session_and_stays_in_interact() {
        let (mut router, mut app) = (Router::new(), interacting());
        let c = ctx(Layout::Wide);
        feed(&mut router, &mut app, ctrl_g(), &c);
        let msgs = feed(&mut router, &mut app, ctrl_g(), &c);
        assert_eq!(msgs, vec![Msg::EnterInteract, input(&[7])]);
        assert_eq!(app.mode, Mode::Interact);
        assert_eq!(written(&mut app, msgs), vec![vec![7]]);
        // A third press starts the next pair: it leaves again.
        assert_eq!(
            feed(&mut router, &mut app, ctrl_g(), &c),
            vec![Msg::LeaveInteract]
        );
    }

    #[test]
    fn uppercase_and_shifted_ctrl_g_are_the_escape_too() {
        for key in [
            press(KeyCode::Char('G'), KeyModifiers::CONTROL),
            press(
                KeyCode::Char('g'),
                KeyModifiers::CONTROL | KeyModifiers::SHIFT,
            ),
        ] {
            let app = interacting();
            assert_eq!(
                Router::new().route(&app, key, &ctx(Layout::Wide)),
                vec![Msg::LeaveInteract]
            );
        }
    }

    #[test]
    fn a_release_between_the_two_presses_does_not_cancel_the_double() {
        let (mut router, mut app) = (Router::new(), interacting());
        let c = ctx(Layout::Wide);
        feed(&mut router, &mut app, ctrl_g(), &c);
        assert_eq!(
            feed(
                &mut router,
                &mut app,
                kind(ctrl_g(), KeyEventKind::Release),
                &c
            ),
            vec![]
        );
        assert_eq!(
            feed(&mut router, &mut app, ctrl_g(), &c),
            vec![Msg::EnterInteract, input(&[7])]
        );
    }

    #[test]
    fn a_held_ctrl_g_cannot_fire_the_double() {
        let (mut router, mut app) = (Router::new(), interacting());
        let c = ctx(Layout::Wide);
        feed(&mut router, &mut app, ctrl_g(), &c);
        for _ in 0..5 {
            let repeat = kind(ctrl_g(), KeyEventKind::Repeat);
            assert_eq!(feed(&mut router, &mut app, repeat, &c), vec![]);
        }
        assert_eq!(app.mode, Mode::Overview);
        // The memory survives the repeats, so a real second press still works.
        assert_eq!(
            feed(&mut router, &mut app, ctrl_g(), &c),
            vec![Msg::EnterInteract, input(&[7])]
        );
    }

    #[test]
    fn any_other_key_or_a_paste_between_the_presses_cancels_the_double() {
        let c = ctx(Layout::Wide);
        for between in [Some(plain('j')), Some(plain('x')), None] {
            let (mut router, mut app) = (Router::new(), interacting());
            feed(&mut router, &mut app, ctrl_g(), &c);
            match between {
                Some(key) => {
                    feed(&mut router, &mut app, key, &c);
                }
                None => {
                    router.paste(&app, "p", &c);
                }
            }
            // A lone Ctrl-g in Overview does nothing: it is not a way back in.
            assert_eq!(feed(&mut router, &mut app, ctrl_g(), &c), vec![]);
            assert_eq!(app.mode, Mode::Overview);
        }
    }

    #[test]
    fn the_double_is_dropped_if_the_session_was_restarted_or_another_selected_between() {
        let c = ctx(Layout::Wide);
        // Restarted: same id, new generation (and not running yet).
        let (mut router, mut app) = (Router::new(), interacting());
        feed(&mut router, &mut app, ctrl_g(), &c);
        app.update(Msg::AskRestart);
        app.update(Msg::Answer(true));
        assert_eq!(feed(&mut router, &mut app, ctrl_g(), &c), vec![]);
        // Another session selected: it must not get the bell.
        let (mut router, mut app) = (Router::new(), interacting());
        feed(&mut router, &mut app, ctrl_g(), &c);
        app.update(Msg::Launch(LaunchSpec {
            project: PathBuf::from("/work/other"),
            command: vec!["pi".to_owned()],
        }));
        assert_eq!(feed(&mut router, &mut app, ctrl_g(), &c), vec![]);
    }

    #[test]
    fn a_stale_target_in_a_second_session_is_distinguished_by_generation() {
        // Same id and a newer generation that is running again must not take the old double.
        let c = ctx(Layout::Wide);
        let (mut router, mut app) = (Router::new(), interacting());
        feed(&mut router, &mut app, ctrl_g(), &c);
        app.update(Msg::AskRestart);
        app.update(Msg::Answer(true));
        for (n, event) in [Event::Starting {}, Event::Running { agent_pid: 9 }]
            .into_iter()
            .enumerate()
        {
            app.update(Msg::Channel {
                id: SessionId(1),
                generation: 2,
                seq: n as u64 + 1,
                event,
            });
        }
        assert_eq!(
            app.selected().map(|s| s.phase.clone()),
            Some(Phase::Running)
        );
        assert_eq!(feed(&mut router, &mut app, ctrl_g(), &c), vec![]);
    }

    // ========================================================================
    // Small terminals
    // ========================================================================

    #[test]
    fn interact_is_refused_where_the_terminal_pane_is_not_shown() {
        let c = ctx(Layout::Tiny);
        let (mut router, mut app) = (Router::new(), running());
        let msgs = feed(
            &mut router,
            &mut app,
            press(KeyCode::Enter, KeyModifiers::NONE),
            &c,
        );
        assert_eq!(msgs, vec![Msg::TooSmall]);
        assert_eq!(app.mode, Mode::Overview);
        assert_eq!(
            app.notice.as_deref(),
            Some("the terminal is too small to interact; make it larger")
        );
    }

    #[test]
    fn a_terminal_that_becomes_tiny_while_interacting_stops_sending_keys() {
        let (mut router, mut app) = (Router::new(), interacting());
        let msgs = feed(&mut router, &mut app, plain('x'), &ctx(Layout::Tiny));
        assert_eq!(msgs, vec![Msg::LeaveInteract, Msg::TooSmall]);
        assert_eq!(app.mode, Mode::Overview);
    }

    #[test]
    fn tab_switches_panels_when_narrow_and_the_lower_tab_when_wide() {
        let tab = press(KeyCode::Tab, KeyModifiers::NONE);
        let app = running();
        assert_eq!(
            Router::new().route(&app, tab, &ctx(Layout::Narrow)),
            vec![Msg::NextPanel(true)]
        );
        assert_eq!(
            Router::new().route(
                &app,
                press(KeyCode::BackTab, KeyModifiers::SHIFT),
                &ctx(Layout::Narrow)
            ),
            vec![Msg::NextPanel(false)]
        );
        assert_eq!(
            Router::new().route(&app, tab, &ctx(Layout::Wide)),
            vec![Msg::NextTab]
        );
    }

    // ========================================================================
    // Overview, help, confirm, launch
    // ========================================================================

    #[test]
    fn overview_keys_map_to_the_actions_the_design_lists() {
        let app = running();
        let c = ctx(Layout::Wide);
        let cases = [
            ('j', Msg::Select(1)),
            ('k', Msg::Select(-1)),
            (
                'n',
                Msg::OpenLaunch {
                    cwd: PathBuf::from(CWD),
                },
            ),
            ('s', Msg::AskStop),
            ('r', Msg::AskRestart),
            ('a', Msg::ReviewApproval),
            ('?', Msg::ToggleHelp),
            ('q', Msg::AskQuit),
            ('1', Msg::Jump(1)),
            ('8', Msg::Jump(8)),
        ];
        for (key, msg) in cases {
            assert_eq!(
                Router::new().route(&app, plain(key), &c),
                vec![msg],
                "{key}"
            );
        }
        for key in ['9', '0', 'x', 'z'] {
            assert_eq!(Router::new().route(&app, plain(key), &c), vec![], "{key}");
        }
        assert_eq!(
            Router::new().route(&app, press(KeyCode::Enter, KeyModifiers::NONE), &c),
            vec![Msg::EnterInteract]
        );
    }

    #[test]
    fn only_y_confirms_and_every_other_key_cancels() {
        let mut app = running();
        app.update(Msg::AskStop);
        assert_eq!(app.mode, Mode::Confirm);
        let c = ctx(Layout::Wide);
        assert_eq!(
            Router::new().route(&app, plain('y'), &c),
            vec![Msg::Answer(true)]
        );
        for key in [
            plain('n'),
            plain('Y'),
            plain(' '),
            press(KeyCode::Enter, KeyModifiers::NONE),
            press(KeyCode::Esc, KeyModifiers::NONE),
        ] {
            assert_eq!(
                Router::new().route(&app, key, &c),
                vec![Msg::Answer(false)],
                "{key:?}"
            );
        }
    }

    #[test]
    fn help_closes_on_escape_or_question_mark_and_ignores_the_rest() {
        let mut app = running();
        app.update(Msg::ToggleHelp);
        let c = ctx(Layout::Wide);
        for key in [press(KeyCode::Esc, KeyModifiers::NONE), plain('?')] {
            assert_eq!(Router::new().route(&app, key, &c), vec![Msg::ToggleHelp]);
        }
        // A stop key does nothing while help is open.
        assert_eq!(Router::new().route(&app, plain('s'), &c), vec![]);
    }

    #[test]
    fn the_launch_form_takes_text_and_pastes_and_never_acts_on_overview_keys() {
        let mut app = running();
        app.update(Msg::OpenLaunch {
            cwd: PathBuf::from(CWD),
        });
        assert_eq!(app.mode, Mode::Launch);
        let c = ctx(Layout::Wide);
        let mut router = Router::new();
        assert_eq!(
            router.route(&app, plain('q'), &c),
            vec![Msg::Form(FormEdit::Char('q'))]
        );
        assert_eq!(
            router.route(&app, press(KeyCode::Char('Q'), KeyModifiers::SHIFT), &c),
            vec![Msg::Form(FormEdit::Char('Q'))]
        );
        assert_eq!(
            router.route(&app, press(KeyCode::Esc, KeyModifiers::NONE), &c),
            vec![Msg::CancelLaunch]
        );
        assert_eq!(
            router.route(&app, press(KeyCode::Enter, KeyModifiers::NONE), &c),
            vec![Msg::SubmitLaunch]
        );
        assert_eq!(
            router.route(&app, press(KeyCode::Tab, KeyModifiers::NONE), &c),
            vec![Msg::Form(FormEdit::SwitchField)]
        );
        assert_eq!(
            router.route(&app, press(KeyCode::Backspace, KeyModifiers::NONE), &c),
            vec![Msg::Form(FormEdit::Backspace)]
        );
        // Ctrl-letter is not text.
        assert_eq!(
            router.route(&app, press(KeyCode::Char('c'), KeyModifiers::CONTROL), &c),
            vec![]
        );
        // A paste is typed in, minus newlines, which would otherwise submit nothing and confuse.
        assert_eq!(
            router.paste(&app, "ab\ncd", &c),
            ['a', 'b', 'c', 'd']
                .map(|ch| Msg::Form(FormEdit::Char(ch)))
                .to_vec()
        );
    }

    #[test]
    fn a_paste_outside_interact_and_launch_is_ignored() {
        let app = running();
        assert_eq!(
            Router::new().paste(&app, "rm -rf", &ctx(Layout::Wide)),
            vec![]
        );
    }
}
