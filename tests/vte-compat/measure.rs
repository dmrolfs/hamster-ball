// ABOUTME: Opt-in before/after parser measurement using identical input and callbacks.
// ABOUTME: Prints elapsed times without inventing a timing gate or changing application limits.
use std::time::Instant;

#[derive(Default)]
struct Sink(usize);
impl baseline::Perform for Sink {
    fn print(&mut self, _: char) {
        self.0 += 1;
    }
    fn execute(&mut self, _: u8) {
        self.0 += 1;
    }
}
impl patched::Perform for Sink {
    fn print(&mut self, _: char) {
        self.0 += 1;
    }
    fn execute(&mut self, _: u8) {
        self.0 += 1;
    }
}
fn main() {
    for (name, pattern) in [
        ("invalid", &b"\xff"[..]),
        ("ansi", &b"hello\x1b[31mworld\x1b[0m\r\n"[..]),
    ] {
        let bytes = pattern.repeat((1 << 20) / pattern.len());
        for reverse in [false, true] {
            let mut results = [std::time::Duration::ZERO; 2];
            let mut counts = [0; 2];
            for index in if reverse { [1, 0] } else { [0, 1] } {
                let mut sink = Sink::default();
                let now = Instant::now();
                if index == 0 {
                    let mut parser = baseline::Parser::new();
                    for chunk in bytes.chunks(8192) {
                        parser.advance(&mut sink, chunk);
                    }
                } else {
                    let mut parser = patched::Parser::new();
                    for chunk in bytes.chunks(8192) {
                        parser.advance(&mut sink, chunk);
                    }
                }
                results[index] = now.elapsed();
                counts[index] = sink.0;
            }
            assert_eq!(counts[0], counts[1]);
            println!(
                "{name} reverse={reverse}: baseline={:?} patched={:?}",
                results[0], results[1]
            );
        }
    }
}
