mod logger;

use clap::Arg;

use tracing::*;

use std::path::{Path, PathBuf};
use std::{os::unix::process::CommandExt, process::*};

use nix::{
    sys::{ptrace, wait::waitpid},
    unistd::{fork, ForkResult, Pid},
};

fn main() {
    let matches = clap::Command::new("debugger")
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
                .action(clap::ArgAction::SetTrue), // Sets the value to `true` if the flag is present
        )
        .get_matches();

    let target_executable = matches
        .get_one::<String>("bin")
        .expect("Binary name is required");

    let verbose = matches.get_flag("verbose");
    logger::init(verbose);

    // Resolve the binary path to an absolute path
    let target_path = Path::new(target_executable);
    let resolved_path = std::fs::canonicalize(target_path).unwrap_or_else(|err| {
        error!("Failed to resolve binary path: {}", err);
        std::process::exit(1);
    });

    info!("Verbose mode: {}", verbose);
    info!("Resolved the target binary path: {:?}", resolved_path);

    // Here we have two ways to start the target process:
    // 1. Command::new -> Get_pid -> ptrace::attach(child_pid);
    // 2. Fork -> Replace the process with the target binary -> ptrace::traceme();
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => trace_child(child),
        Ok(ForkResult::Child) => {
            run_child(resolved_path);
        }
        Err(_) => println!("Fork failed"),
    }
}

fn trace_child(forked_child: Pid) {
    info!("kme_dbg is executing with pid: [{}]", std::process::id());

    let ws = waitpid(forked_child, None).expect("Parent failed waiting for child");
    info!("Child process stopped with status: {:?}", ws);

    ptrace::cont(forked_child, None).expect("cont failed");

    // exited;
    let ws = waitpid(forked_child, None).expect("Parent failed waiting for child");
    info!("Child process stopped with status: {:?}", ws);
}

fn run_child(target_path: PathBuf) {
    info!(
        "Target executable was successfully forked, pid: [{}]",
        std::process::id()
    );

    // Indicates that this process is to be traced by its parent.
    // This is the only ptrace request to be issued by the tracee.
    // I personally dont see any scenario where it can failed
    ptrace::traceme().expect("Failed when asking to be traced");

    Command::new(target_path).exec();

    unreachable!("Failed to execute the target executable");
}
