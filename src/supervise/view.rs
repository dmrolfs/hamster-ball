// ABOUTME: What fits on the owner's terminal: which panels are shown at once, from its size alone.
// ABOUTME: Shared by the key router (what an action can do here) and the screens (what to draw).
//! The supervisor's layout rule (epic hb-b6q).

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
}
