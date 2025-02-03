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
        Ok(false) => {
            std::process::exit(1);
        }
        Ok(true) => {
            std::process::exit(0);
        }
    }
}

/// From bat's rust code:
/// Returns `Err(..)` upon fatal errors. Otherwise, returns `Ok(true)` on full success and
/// `Ok(false)` if any intermediate errors occurred (were printed).
fn run(exe: PathBuf) -> Result<bool, DebuggerError> {
    log::info!("Exe: {:?}", exe);
    let mut dbg = Debugger::launch(exe)?;
    let _entry_point = dbg.find_entrypoint()?;
    // dbg.set_breakpoint(entry_point as u64)?; // for some reason this does not work.
    dbg.wait_for_signal()?;

    Ok(true)
}
