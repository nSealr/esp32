//! desktop-simulator CLI: replay one named `specs/vectors` file through
//! `nsealr-core` for ad hoc debugging. All logic lives in the library
//! ([`desktop_simulator::run_cli`]) so the CLI and the exhaustive test suite
//! share a single loader + replay code path.

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(desktop_simulator::run_cli(&args) as u8)
}
