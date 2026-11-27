// ABOUTME: Exercises supervisor job control through a real interactive bash on an expect-owned PTY.
// ABOUTME: Checks terminal restoration before stop, background continuation, foreground redraw, and review cancellation.
//! Job-control behavior on the owner's terminal.
mod common;

use claims::assert_ok;
use common::World;
use std::process::Command;

const SUPERVISE: &str = env!("CARGO_BIN_EXE_hb-supervise");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

fn exercise(review: bool, terminate: Option<&str>) {
    let w = World::new("[fs]\nwrite = [\".\"]\n");
    let pidfile = w.base.join("supervisor.pid");
    let launcher = w.base.join("supervisor.sh");
    common::write(
        &launcher,
        &format!("echo $$ > '{}'\nexec '{}'\n", pidfile.display(), SUPERVISE),
    );
    let script = w.base.join("job.exp");
    let enter_review = if review {
        "send -- \"n\"; expect -ex {LAUNCH}\n\
         send -- \"/usr/bin/true\\r\"; expect -ex {Approve}\n\
         send -- \"a\"; expect -ex {to approve: }\n"
    } else {
        ""
    };
    let suspend = if review {
        "send -- \"\\032\""
    } else {
        "exec /bin/kill -TSTP $supervisor"
    };
    let resume = if review {
        // The review owns cooked input, so a resumed UI would steal its answer.
        r#"expect -ex {/bin/sh}; expect_before; set timeout 1; expect {
            -ex "\033\[?1049h" { puts stderr "UI_ENTERED_DURING_REVIEW"; exit 96 }
            timeout {}
        }
        set timeout 15
        expect_before timeout { puts stderr "JOB TIMEOUT"; exit 90 } eof { exit 91 }
        send -- "\003"; expect -ex "\033\[?1049h""#
    } else {
        r#"expect -ex "\033\[?1049h""#
    };
    let finish = terminate.map_or_else(
        || format!("expect_before timeout {{ exit 90 }} eof {{ exit 91 }}\nsend -- \"fg\\r\"\n{resume}\nsend -- \"q\"\nexpect -ex {{JOB$ }}"),
        |signal| format!("exec /bin/kill -{signal} $supervisor\nsend -- \"wait %1; echo ENDED\\r\"\nexpect -re {{\\r\\nENDED\\r\\n}}\nexpect -ex {{JOB$ }}\nif {{![catch {{exec /bin/kill -0 $supervisor}}]}} {{ exit 99 }}\nif {{[info exists review_pid] && ![catch {{exec /bin/kill -0 $review_pid}}]}} {{ exit 100 }}"),
    );
    // macOS clears PENDIN as input is consumed; compare all stable settings, not that queue flag.
    common::write(
        &script,
        &format!(
            r#"set timeout 15
set env(PS1) {{JOB$ }}
set env(TERM) xterm-256color
set env(HB_SUPERVISE_HB) {{{DRIVE}}}
set env(HB_TD_HOME) {{{home}}}
set env(HB_TD_CWD) {{{project}}}
set env(HB_TD_PATH) {{{path}}}
set env(HB_TD_TMP) {{{tmp}}}
spawn /bin/bash --noprofile --norc -i
set shell [exp_pid]
set f [open {{{shellfile}}} w]; puts $f $shell; close $f
rename exit original_exit
proc exit {{code}} {{
    global shell supervisor
    if {{$code != 0 && [info exists supervisor]}} {{
        # Bash still owns the job: verify that before signalling its process group.
        if {{![catch {{exec /bin/ps -o ppid=,pgid= -p $supervisor}} identity] &&
             [lindex $identity 0] == $shell && [lindex $identity 1] == $supervisor}} {{
            catch {{exec /bin/kill -KILL -- -$supervisor}}
        }}
    }}
    catch {{close}}
    catch {{wait}}
    original_exit $code
}}
set result [catch {{
expect_before timeout {{ puts stderr "JOB TIMEOUT"; exit 90 }} eof {{ puts stderr "UNEXPECTED EOF"; exit 91 }}
expect -ex {{JOB$ }}
send -- {{modes() {{ stty -g | /usr/bin/perl -pe 's/lflag=([0-9a-f]+)/"lflag=".sprintf("%x", hex($1) & ~0x20000000)/e'; }};}}
send -- "\r"
expect -ex {{JOB$ }}
send -- "cd '{project}'; stty rows 30 columns 120; baseline=\$(modes); /bin/sh '{launcher}'\r"
expect -ex {{Sessions}}
{enter_review}
set f [open {{{pidfile}}} r]; set supervisor [string trim [read $f]]; close $f
if {{{review}}} {{
    set rows [exec /bin/ps -o pid=,ppid= -ax]
    foreach row [split $rows \n] {{
        if {{[lindex $row 1] eq $supervisor}} {{ set review_pid [lindex $row 0] }}
    }}
    if {{![info exists review_pid]}} {{ exit 101 }}
}}
{suspend}
expect -ex {{Stopped}}
expect -ex {{JOB$ }}
send -- "test \"\$(modes)\" = \"\$baseline\" && echo MODES_OK || echo MODES_BAD\r"
expect -re {{\r\nMODES_(OK|BAD)\r\n}}
if {{$expect_out(1,string) ne "OK"}} {{ exit 92 }}
expect -ex {{JOB$ }}
send -- "bg\r"
expect_before -ex "\033\[?1049h" {{ puts stderr "UI_ENTERED_IN_BACKGROUND"; exit 98 }} timeout {{ exit 90 }} eof {{ exit 91 }}
expect -ex {{JOB$ }}
for {{set sample 0}} {{$sample < 5}} {{incr sample}} {{
    after 60
    set state [exec /bin/ps -o stat= -p $supervisor]
    if {{[regexp {{[TZ]}} $state]}} {{ puts stderr "SUPERVISOR_NOT_RUNNING: $state"; exit 95 }}
}}
send -- "test \"\$(modes)\" = \"\$baseline\" && echo BACKGROUND_OK || echo BACKGROUND_BAD\r"
expect -re {{\r\nBACKGROUND_(OK|BAD)\r\n}}
if {{$expect_out(1,string) ne "OK"}} {{ exit 93 }}
expect -ex {{JOB$ }}
{finish}
send -- "test \"\$(modes)\" = \"\$baseline\" && echo FINAL_OK || echo FINAL_BAD\r"
expect -re {{\r\nFINAL_(OK|BAD)\r\n}}
if {{$expect_out(1,string) ne "OK"}} {{ exit 94 }}
expect -ex {{JOB$ }}
expect_before
send -- "exit\r"
expect {{ eof {{}} timeout {{ exit 97 }} }}
wait
puts "JOB_PASS"
}} problem]
if {{$result}} {{ puts stderr $problem; exit 102 }}
exit 0
"#,
            home = w.home_dir().display(),
            project = w.project.display(),
            path = w.base.join("bin").display(),
            tmp = w.base.join("tmp").display(),
            launcher = launcher.display(),
            pidfile = pidfile.display(),
            shellfile = w.base.join("shell.pid").display(),
            review = i32::from(review),
        ),
    );
    let transcript = w.base.join("transcript");
    let out = assert_ok!(std::fs::File::create(&transcript));
    let mut child = assert_ok!(
        Command::new("/usr/bin/expect")
            .arg(&script)
            .stdout(assert_ok!(out.try_clone()))
            .stderr(out)
            .spawn()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = assert_ok!(child.try_wait()) {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            // Verify the shell's identity while expect is still our unreaped child.
            if let Ok(shell) = std::fs::read_to_string(w.base.join("shell.pid")) {
                let shell = shell.trim();
                let identity = assert_ok!(
                    Command::new("/bin/ps")
                        .args(["-o", "ppid=", "-p", shell])
                        .output()
                );
                if String::from_utf8_lossy(&identity.stdout).trim() == child.id().to_string() {
                    if let Ok(job) = std::fs::read_to_string(&pidfile) {
                        let job = job.trim();
                        let identity = assert_ok!(
                            Command::new("/bin/ps")
                                .args(["-o", "ppid=,pgid=", "-p", job])
                                .output()
                        );
                        let identity = String::from_utf8_lossy(&identity.stdout);
                        let ids: Vec<_> = identity.split_whitespace().collect();
                        if ids == [shell, job] {
                            let _ = Command::new("/bin/kill")
                                .args(["-KILL", "--", &format!("-{job}")])
                                .status();
                        }
                    }
                    let _ = Command::new("/bin/kill").args(["-KILL", shell]).status();
                }
            }
            assert_ok!(child.kill());
            assert_ok!(child.wait());
            assert_ok!(Err::<(), _>(
                "job-control harness exceeded its outer deadline"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    assert!(
        status.success(),
        "{}",
        assert_ok!(std::fs::read_to_string(transcript)),
    );
}

#[test]
fn a_suspended_ui_restores_modes_and_resumes_only_in_the_foreground() {
    exercise(false, None);
}

#[test]
fn a_suspended_review_can_be_foregrounded_and_cancelled_without_losing_the_ui() {
    if !common::sandbox_available() {
        return;
    }
    exercise(true, None);
}

#[test]
fn a_backgrounded_review_responds_to_termination_without_fg() {
    if !common::sandbox_available() {
        return;
    }
    for signal in ["TERM", "HUP"] {
        exercise(true, Some(signal));
        exercise(false, Some(signal));
    }
}
