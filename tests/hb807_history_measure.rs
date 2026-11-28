// ABOUTME: Manual, isolated RSS probe for supervisor history sizing.
// ABOUTME: Run each scenario in a fresh process; not a CI memory assertion.
//! Fresh-process measurement of the history sizing allowance.
#![cfg(feature = "supervise")]
use claims::assert_ok;
use hamster_ball::supervise::terminal::{SessionScreen, scrollback_lines};
fn rss() -> usize {
    let out = assert_ok!(
        std::process::Command::new("/bin/ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
    );
    assert_ok!(String::from_utf8_lossy(&out.stdout).trim().parse())
}
#[test]
#[ignore = "manual RSS measurement, not a timing/memory CI gate"]
fn history_rss() {
    let cols: u16 = assert_ok!(
        std::env::var("HB_MEASURE_COLS")
            .unwrap_or("250".into())
            .parse()
    );
    let before = rss();
    let mut screens = Vec::new();
    for _ in 0..32 {
        let mut screen = SessionScreen::new(60, cols);
        let line = format!("{}\r\n", "x".repeat(usize::from(cols) - 1));
        for _ in 0..scrollback_lines(cols) + 100 {
            screen.process(line.as_bytes());
        }
        screens.push(screen);
    }
    eprintln!(
        "cols={cols} lines={} cell_bytes={} delta_kib={} screens={}",
        scrollback_lines(cols),
        std::mem::size_of::<vt100::Cell>(),
        rss().saturating_sub(before),
        screens.len()
    );
    std::hint::black_box(screens);
}
