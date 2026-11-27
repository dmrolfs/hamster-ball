// ABOUTME: The MCP probe `hb warm` runs inside the ball: start a server, send `initialize`, wait for the answer, end its process group.
// ABOUTME: A perl script (the system perl, which the conformance wrapper already uses in the ball) so no hb binary has to run in the sandbox.
//! The probe (design 10, hb-ghd.7.3).
//!
//! `/usr/bin/perl -e PROBE <seconds> <command> <args>...` starts the command in its own process
//! group with pipes for its streams, writes one MCP `initialize` request, and reads its stdout
//! until the response with `id` 1 arrives, the server ends, or the time is up. It then ends the
//! group (TERM, then KILL). Exit 0 is an answer. Otherwise it exits 1 after printing the server's
//! last 20 stderr lines and why it stopped, so the user sees the server's own words.

use std::ffi::OsString;
use std::time::Duration;

/// The system perl.
pub const PERL: &str = "/usr/bin/perl";

/// The probe script.
pub const PROBE: &str = r#"use strict; use warnings; use IO::Select; use POSIX ();
my ($limit, @cmd) = @ARGV;
pipe(my $in_r, my $in_w) or die "pipe: $!";
pipe(my $out_r, my $out_w) or die "pipe: $!";
pipe(my $err_r, my $err_w) or die "pipe: $!";
my $pid = fork(); die "fork: $!" unless defined $pid;
if (!$pid) {
  POSIX::setpgid(0, 0);
  open(STDIN, "<&", $in_r) or die; open(STDOUT, ">&", $out_w) or die; open(STDERR, ">&", $err_w) or die;
  close($_) for ($in_w, $out_r, $err_r);
  exec @cmd or do { print STDERR "hb: cannot start $cmd[0]: $!\n"; POSIX::_exit(127) };
}
close($_) for ($in_r, $out_w, $err_w);
syswrite($in_w, '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"hb-warm","version":"0"}}}' . "\n");
my $sel = IO::Select->new($out_r, $err_r);
my ($out, $err, $ok) = ("", "", 0);
my $deadline = time + $limit;
while (time < $deadline && $sel->count) {
  for my $fh ($sel->can_read(1)) {
    my $n = sysread($fh, my $buf, 65536);
    if (!$n) { $sel->remove($fh); next }
    if ($fh == $out_r) { $out .= $buf } else { $err .= $buf; $err = substr($err, -20000) if length $err > 20000 }
  }
  if ($out =~ /"id"\s*:\s*1\b/ && $out =~ /"result"/) { $ok = 1; last }
}
my $why = $ok ? "" : (time >= $deadline ? "timed out after ${limit}s" : "exited before answering");
kill 'TERM', -$pid; select(undef, undef, undef, 0.5); kill 'KILL', -$pid; waitpid($pid, 0);
unless ($ok) {
  my @lines = grep { length } split /\n/, $err;
  @lines = @lines[-20 .. -1] if @lines > 20;
  print STDERR "$_\n" for @lines;
  print STDERR "hb: $why\n";
}
exit($ok ? 0 : 1);
"#;

/// The argument list that runs the probe on `command` and `args` for at most `limit`.
#[must_use]
pub fn argv(limit: Duration, command: &str, args: &[String]) -> Vec<OsString> {
    // uv's fixed settings (see `private_python_vars`) are set inside the probe, before it starts
    // the server, so the "cannot start" message still names the server's own program.
    let settings: String = crate::session::offline::private_python_vars()
        .into_iter()
        .map(|(k, v)| format!("$ENV{{{k}}} = '{v}';\n"))
        .collect();
    let mut words: Vec<OsString> = vec![
        PERL.into(),
        "-e".into(),
        format!("{settings}{PROBE}").into(),
        limit.as_secs().to_string().into(),
        command.into(),
    ];
    words.extend(args.iter().map(OsString::from));
    words
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Output};
    use std::time::Duration;

    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    use super::*;

    /// Runs the probe on `/bin/sh -c script`.
    fn probe(limit_secs: u64, script: &str) -> Output {
        let argv = argv(
            Duration::from_secs(limit_secs),
            "/bin/sh",
            &["-c".to_owned(), script.to_owned()],
        );
        assert_ok!(Command::new(&argv[0]).args(&argv[1..]).output())
    }

    fn stderr(out: &Output) -> String {
        String::from_utf8_lossy(&out.stderr).into_owned()
    }

    #[test]
    fn the_argument_list_is_perl_the_script_the_limit_the_command_and_its_arguments() {
        let words = argv(
            Duration::from_secs(90),
            "uvx",
            &["--from".into(), "x".into()],
        );
        let words: Vec<String> = words
            .iter()
            .map(|w| w.to_string_lossy().into_owned())
            .collect();
        assert_eq!(words[0], "/usr/bin/perl");
        assert_eq!(words[1], "-e");
        assert!(
            words[2].ends_with(PROBE),
            "the probe script is unchanged after its settings"
        );
        assert!(words[2].starts_with("$ENV{UV_PYTHON_PREFERENCE} = 'only-managed';"));
        assert_eq!(&words[3..], ["90", "uvx", "--from", "x"]);
    }

    #[test]
    fn the_script_compiles() {
        let out = assert_ok!(
            Command::new("/usr/bin/perl")
                .args([
                    "-c",
                    "-e",
                    &argv(Duration::from_secs(1), "x", &[])[2].to_string_lossy()
                ])
                .output()
        );
        assert!(out.status.success(), "{}", stderr(&out));
    }

    #[test]
    fn a_server_that_answers_initialize_passes_and_prints_nothing() {
        let out = probe(
            20,
            r#"read line; echo '{"jsonrpc":"2.0","id":1,"result":{"capabilities":{}}}'; sleep 30"#,
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        assert_eq!(stderr(&out), "");
    }

    #[test]
    fn output_before_the_answer_and_a_notification_do_not_count_as_one() {
        let out = probe(
            20,
            r#"read line; echo 'starting up'; echo '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'; echo '{"jsonrpc":"2.0","id":1,"result":{}}'; sleep 30"#,
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    }

    #[test]
    fn a_server_that_exits_first_fails_with_its_stderr_and_a_reason() {
        let out = probe(20, "echo boom >&2; exit 3");
        assert_eq!(out.status.code(), Some(1));
        let text = stderr(&out);
        assert!(text.contains("boom"), "{text}");
        assert!(text.contains("hb: exited before answering"), "{text}");
    }

    #[test]
    fn only_the_last_twenty_lines_of_stderr_are_kept() {
        let out = probe(20, "for i in $(seq 1 60); do echo line$i >&2; done; exit 1");
        let text = stderr(&out);
        assert!(text.contains("line60") && text.contains("line41"), "{text}");
        assert!(!text.contains("line40\n"), "{text}");
    }

    #[test]
    fn a_server_that_never_answers_times_out_and_says_so() {
        let out = probe(1, "sleep 60");
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("hb: timed out after 1s"),
            "{}",
            stderr(&out)
        );
    }

    #[test]
    fn a_program_that_cannot_start_is_named() {
        let argv = argv(Duration::from_secs(5), "/nonexistent/hb-server", &[]);
        let out = assert_ok!(Command::new(&argv[0]).args(&argv[1..]).output());
        assert_eq!(out.status.code(), Some(1));
        assert!(
            stderr(&out).contains("cannot start /nonexistent/hb-server"),
            "{}",
            stderr(&out)
        );
    }

    #[test]
    fn the_servers_whole_process_group_is_ended() {
        let marker = "hb-probe-test-sleeper-5151";
        let out = probe(
            20,
            &format!(
                r#"(exec -a {marker} sleep 51) & read line; echo '{{"jsonrpc":"2.0","id":1,"result":{{}}}}'; sleep 51"#
            ),
        );
        assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
        std::thread::sleep(Duration::from_millis(300));
        let alive = assert_ok!(
            Command::new("/usr/bin/pgrep")
                .args(["-f", "sleep 51"])
                .output()
        );
        assert!(
            String::from_utf8_lossy(&alive.stdout).trim().is_empty(),
            "a descendant survived: {}",
            String::from_utf8_lossy(&alive.stdout)
        );
    }
}
