// ABOUTME: Compares every vte callback and termination offset with the published parser.
// ABOUTME: External read partitions are identical, preserving known partial-decoder behavior.
use proptest::prelude::*;

#[derive(Default)]
struct Trace {
    events: Vec<String>,
    stop: usize,
}

macro_rules! performer {
    ($parser:ident) => {
        impl $parser::Perform for Trace {
            fn print(&mut self, c: char) {
                self.events.push(format!("print {c:?}"));
            }
            fn execute(&mut self, b: u8) {
                self.events.push(format!("execute {b}"));
            }
            fn put(&mut self, b: u8) {
                self.events.push(format!("put {b}"));
            }
            fn unhook(&mut self) {
                self.events.push("unhook".into());
            }
            fn hook(&mut self, p: &$parser::Params, i: &[u8], ignore: bool, c: char) {
                self.events.push(format!("hook {p:?} {i:?} {ignore} {c:?}"));
            }
            fn csi_dispatch(&mut self, p: &$parser::Params, i: &[u8], ignore: bool, c: char) {
                self.events.push(format!("csi {p:?} {i:?} {ignore} {c:?}"));
            }
            fn osc_dispatch(&mut self, p: &[&[u8]], bell: bool) {
                self.events.push(format!("osc {p:?} {bell}"));
            }
            fn esc_dispatch(&mut self, i: &[u8], ignore: bool, b: u8) {
                self.events.push(format!("esc {i:?} {ignore} {b}"));
            }
            fn terminated(&self) -> bool {
                self.events.len() >= self.stop
            }
        }
    };
}
performer!(baseline);
performer!(patched);

fn compare(bytes: &[u8], chunk: usize, stop: usize, partial: bool) {
    let (mut old, mut new) = (baseline::Parser::new(), patched::Parser::new());
    let (mut a, mut b) = (
        Trace {
            stop,
            ..Trace::default()
        },
        Trace {
            stop,
            ..Trace::default()
        },
    );
    for read in bytes
        .chunks(chunk)
        .chain([&b""[..], &b"\x18\x1b[0mEND"[..]])
    {
        if partial {
            let mut offset = 0;
            while offset < read.len() {
                // Also compare the checkpoint that consumes nothing.
                a.stop = a.events.len();
                b.stop = b.events.len();
                let x = old.advance_until_terminated(&mut a, &read[offset..]);
                let y = new.advance_until_terminated(&mut b, &read[offset..]);
                assert_eq!(x, y);
                assert_eq!(a.events, b.events);
                offset += x;
                a.stop = a.events.len() + stop.max(1);
                b.stop = b.events.len() + stop.max(1);
                let x = old.advance_until_terminated(&mut a, &read[offset..]);
                let y = new.advance_until_terminated(&mut b, &read[offset..]);
                assert_eq!(x, y);
                assert_eq!(a.events, b.events);
                assert!(x > 0 || offset == read.len());
                offset += x;
            }
        } else {
            old.advance(&mut a, read);
            new.advance(&mut b, read);
            assert_eq!(a.events, b.events);
        }
    }
}

#[test]
fn known_boundaries_and_termination_checkpoints() {
    for bytes in [
        &b"\0\0\0\0\0\xc2\x80 \x80"[..],
        b"\xe2\x82\xac \xff\xffA\x1b[m",
        b"\x1b]52;c;data\x07\x1bP1;2qabc\x1b\\\x1b[?1049h",
        b"\xff\xffA\x1b[m",
    ] {
        for chunk in 1..=bytes.len() {
            for stop in 0..=8 {
                compare(bytes, chunk, stop, false);
                compare(bytes, chunk, stop, true);
            }
        }
    }
}

proptest! {
    #[test]
    fn escape_and_unicode_rich_reads(
        tokens in prop::collection::vec(prop::sample::select(vec![
            &b"\x1b[31m"[..], b"\x1b[0m", b"\x1b]52;c;hi\x07", b"\x1bPqhi\x1b\\",
            b"\xc2\x80", b"\xe2\x82\xac", b"\xe2", b"\xff", b"\x1b", b"\x9c", b"abc\n",
        ]), 0..256),
        chunk in prop_oneof![1usize..16, 1usize..8193],
        stop in 1usize..16,
        partial in any::<bool>(),
    ) {
        compare(&tokens.concat(), chunk, stop, partial);
    }

    #[test]
    fn identical_external_reads_and_callbacks(
        bytes in prop::collection::vec(any::<u8>(), 0..16384),
        chunk in prop_oneof![1usize..16, 1usize..8193],
        stop in 1usize..32,
        partial in any::<bool>(),
    ) {
        compare(&bytes, chunk, stop, partial);
    }
}
