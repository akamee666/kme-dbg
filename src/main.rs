mod debugger;
mod logger;

use crate::debugger::{Debugger, DebuggerError};

use std::io;
use std::path::Path;
use std::path::PathBuf;

use clap::{Arg, Command};

use tracing as log;

fn main() {
    let args = Command::new("debugger")
        .about("A simple Linux debugger")
        .arg(
            Arg::new("bin")
                .help("The binary to debug")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::new("verbose")
                .help("Enable verbose output")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue),
        )
        .get_matches();

    logger::init(args.get_flag("verbose"));

    let exe = args
        .get_one::<String>("bin")
        .ok_or_else(|| DebuggerError::NotFound("Binary name required".into()))
        .and_then(|bin| {
            std::fs::canonicalize(Path::new(bin)).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    DebuggerError::NotFound(bin.into())
                } else {
                    e.into()
                }
            })
        })
        .unwrap_or_else(|_| {
            log::error!(
                "The specified binary file does not exist or the provided path is invalid. Check the argument provided and try again"
            );
            std::process::exit(1);
        });

    let result = run(exe);

    match result {
        Err(error) => {
            log::error!("{error}");
            std::process::exit(1);
        }
        Ok(()) => {
            std::process::exit(1);
        }
    }
}

/// Returns `Err(..)` upon fatal errors. Otherwise, will never return (by now).
fn run(exe: PathBuf) -> Result<(), DebuggerError> {
    log::info!("Exe: {:?}", exe);
    let exe_data = std::fs::read(exe.clone())?;
    let elf_bytes = exe_data.as_slice();
    let mut dbg = Debugger::launch(elf_bytes, exe)?;
    dbg.wait_for_signal()?;
    unreachable!();
}
