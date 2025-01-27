mod logger;

use clap::Arg;

use tracing::*;

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use nix::errno::Errno;
use nix::sys::signal::Signal;
use nix::{
    sys::{
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{fork, ForkResult, Pid},
};
use std::path::{Path, PathBuf};
use std::{os::unix::process::CommandExt, process::*};

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
        Err(_) => error!("Fork failed"),
    }
}

fn trace_child(forked_child: Pid) {
    info!("kme_dbg is executing with pid: [{}]", std::process::id());

    // Ok(T where T is the signal)
    // Err(E where E is ?)
    loop {
        match waitpid(forked_child, None) {
            Ok(signal) => {
                if let Err(e) = handle_signal(signal) {
                    error!("Error while handling child signal: {e}");
                };
            }

            Err(e) => {
                // FIX:
                // I am not sure how this can failed and didn't find which error it returns so i'll let
                // it unhandled by now.
                error!("Something failed waiting for a signal: {e}");
            }
        }
    }
}

/// Handles different process statuses received from a child process from the function waitpid().
/// TODO: Handle errors that are recoverable (Not sure which ones are but i guess i'll figure that
/// out in the future).
fn handle_signal(r_signal: WaitStatus) -> Result<(), Errno> {
    match r_signal {
        WaitStatus::Exited(pid, status) => {
            info!("Child process {} exited with status: {}", pid, status);

            Ok(())
        }
        WaitStatus::Signaled(pid, signal, core_dumped) => {
            info!(
                "Child process {} was terminated by signal: {:?} (core dumped: {})",
                pid, signal, core_dumped
            );

            Ok(())
        }
        WaitStatus::Stopped(pid, stopped_signal) => {
            info!(
                "Child process {} was stopped by signal: {:?}",
                pid, stopped_signal
            );

            match stopped_signal {
                Signal::SIGTRAP => {
                    let regs = match ptrace::getregs(pid) {
                        Ok(regs) => regs,
                        Err(e) => {
                            error!("Failed to get registers due to: {}", e);
                            return Err(e);
                        }
                    };

                    print_current_instruction(pid, regs.rip)
                        .unwrap_or_else(|e| error!("Invalid instruction at the SIGTRAP. {e}"));

                    let mut should_continue = String::new();

                    println!("Step into?");
                    std::io::stdin().read_line(&mut should_continue).unwrap();

                    // should_continue.chars().
                }
                _ => {
                    info!(
                        "Stop signal: {:?} is yet to be implemented.",
                        stopped_signal
                    );
                }
            }

            Ok(())
        }
        WaitStatus::PtraceEvent(pid, signal, event) => {
            info!(
                "Child process {} received a ptrace event: {} (signal: {:?})",
                pid, event, signal
            );

            Ok(())
        }
        WaitStatus::PtraceSyscall(pid) => {
            info!("Child process {} entered a syscall", pid);

            Ok(())
        }
        WaitStatus::Continued(pid) => {
            info!("Child process {} continued", pid);

            Ok(())
        }
        WaitStatus::StillAlive => {
            info!("Child process is still alive");

            Ok(())
        }
    }
}

/// Prints the current instruction at the given RIP for a process.
///
/// # Arguments
/// * `pid` - The process ID of the target process.
/// * `rip` - The instruction pointer (RIP) where the instruction is located.
///
/// # Returns
/// Returns `Ok(())` on success, or an `Errno` if an error occurs.
fn print_current_instruction(pid: Pid, rip: u64) -> Result<(), Errno> {
    // In the x86 and x86-64 architectures, the maximum instruction length is 15 bytes. This limit is defined by the architecture itself
    let mut instruction_bytes = [0u8; 16];
    for (i, byte) in instruction_bytes.iter_mut().enumerate() {
        // WARN:
        // Converting rip to usize might lose data if the architecture is 32bit or 16bit, which
        // would make this operation likely to fail.
        let word = ptrace::read(pid, (rip as usize + i) as *mut _)?;

        debug!("byte read: 0x{:x}", word as u8);
        *byte = word as u8;
    }

    // Create decoder for 64-bit code
    let mut decoder = Decoder::with_ip(
        64,                   // 64-bit mode
        &instruction_bytes,   // Code buffer
        rip,                  // RIP
        DecoderOptions::NONE, // No special options needed
    );

    let mut formatter = NasmFormatter::new();

    let mut output = String::new();
    formatter.format(&decoder.decode(), &mut output);

    info!("Current instruction at 0x{:x}: {}", rip, output);

    Ok(())
}

fn run_child(target_path: PathBuf) {
    info!(
        "Target executable was successfully forked! Pid: [{}]",
        std::process::id()
    );

    // Indicates that this process is to be traced by its parent.
    // This is the only ptrace request to be issued by the tracee.
    // I personally dont see any scenario where it can failed
    ptrace::traceme().expect("Failed when asking to be traced");

    Command::new(target_path).exec();

    unreachable!("Failed to execute the target executable");
}

#[allow(dead_code)]
fn set_breakpoint(_addr: u8) {
    // replace address to 0xcc(int 3).
}
