// ABOUTME: A throwaway CA and a local TLS server for handshake tests, made with the system openssl only.
// ABOUTME: The server answers on a loopback port picked at run time and is killed when the fixture is dropped.
//! A local TLS server whose certificate a throwaway CA signed.
//!
//! The tests that need it ask for a verdict from a real client under the generated profile, so
//! the CA and the server are created fresh and live in the test's own temporary directory. No
//! keychain or system setting is touched, and nothing here needs network access.

#![allow(dead_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use claims::assert_ok;

/// The openssl that ships with macOS (LibreSSL), so no Homebrew tool is needed.
pub const OPENSSL: &str = "/usr/bin/openssl";

/// A CA, a `localhost` certificate it signed, and a server using that certificate.
pub struct TlsFixture {
    /// The CA certificate, which a client must be given to trust the server.
    pub ca: PathBuf,
    /// The loopback port the server listens on.
    pub port: u16,
    server: Child,
}

/// Whether the system openssl is there.
pub fn openssl_available() -> bool {
    Path::new(OPENSSL).exists()
}

fn openssl(args: &[&str], dir: &Path) {
    let out = assert_ok!(Command::new(OPENSSL).args(args).current_dir(dir).output());
    assert!(
        out.status.success(),
        "openssl {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn free_port() -> u16 {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    assert_ok!(listener.local_addr()).port()
}

impl TlsFixture {
    /// Creates the CA and the server certificate in `dir` and starts the server.
    pub fn start(dir: &Path) -> Self {
        assert_ok!(fs::create_dir_all(dir));
        assert_ok!(fs::write(
            dir.join("ca.cnf"),
            "[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=hb throwaway CA\n\
             [v3]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n",
        ));
        assert_ok!(fs::write(
            dir.join("srv.cnf"),
            "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n",
        ));
        openssl(
            &[
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out",
                "ca.pem", "-days", "2", "-config", "ca.cnf",
            ],
            dir,
        );
        openssl(
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "srv.key",
                "-out",
                "srv.csr",
                "-subj",
                "/CN=localhost",
            ],
            dir,
        );
        openssl(
            &[
                "x509",
                "-req",
                "-in",
                "srv.csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-CAcreateserial",
                "-out",
                "srv.pem",
                "-days",
                "2",
                "-extfile",
                "srv.cnf",
            ],
            dir,
        );
        let port = free_port();
        let server = assert_ok!(
            Command::new(OPENSSL)
                .args(["s_server", "-accept", &port.to_string()])
                .args(["-cert", "srv.pem", "-key", "srv.key", "-www", "-quiet"])
                .current_dir(dir)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        );
        let fixture = Self {
            ca: assert_ok!(fs::canonicalize(dir.join("ca.pem"))),
            port,
            server,
        };
        fixture.wait_until_listening();
        fixture
    }

    fn wait_until_listening(&self) {
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.port));
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut up = false;
        while !up && Instant::now() < deadline {
            up = TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok();
            if !up {
                thread::sleep(Duration::from_millis(50));
            }
        }
        assert!(
            up,
            "the local TLS server did not start on port {}",
            self.port
        );
    }

    /// `https://localhost:<port>/`.
    pub fn url(&self) -> String {
        format!("https://localhost:{}/", self.port)
    }

    /// `localhost:<port>`.
    pub fn host_port(&self) -> String {
        format!("localhost:{}", self.port)
    }
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}
