mod logger;

use clap::{Arg, Command};
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{fork, ForkResult, Pid},
};
use std::{collections::HashMap, os::unix::process::CommandExt};
use std::{io::Write, path::Path};
use thiserror::Error;
use tracing::*;

// I need to think more about these errors
// Also, somewhere i need to handle all these ? because if i do not handle it somewhere my debugger
// will just crash for any fucking error
#[derive(Error, Debug)]
pub enum DebuggerError {
    #[error("Failed to attach with the target process")]
    AttachError,
    #[error("Invalid command, Please provide one of the available inputs.")]
    InvalidCommand,
    #[error("Failed to set breakpoint due to invalid address: `{0}`")]
    BkInvalidAddress(u64),
    #[error("Generic Failed to set breakpoint")]
    BkError,
    #[error("Nix error: {0}")]
    NixError(#[from] Errno),
    #[error("Io error: {0}")]
    IoError(#[from] std::io::Error),
}

struct Debugger {
    debugee_pid: Pid,
    // In the x86 and x86-64 architectures, the maximum instruction length is 15 bytes. This limit is defined by the architecture itself
    breakpoints: HashMap<u64, u16>, // Address and the replaced byte.
}

impl Debugger {
    fn new(pid: Pid) -> Self {
        Self {
            debugee_pid: pid,
            breakpoints: HashMap::new(),
        }
    }

    fn set_breakpoint(&mut self, address: u64) -> Result<(), DebuggerError> {
        // Save original byte
        let orig_byte = ptrace::read(self.debugee_pid, address as *mut _)?;
        let data_with_int3 = (orig_byte & 0xff) | 0xcc;

        debug!("Inserting breakpoint at 0x{:x}", address);
        debug!("Original byte and instruction: 0x:{:x}", orig_byte);
        // WARN: This can panic but i dont pretend to keep it here, im just printing for debug
        // reasons.
        print_current_instruction(
            self.debugee_pid,
            ptrace::getregs(self.debugee_pid).unwrap().rip,
        )?;

        debug!(
            "Original byte with int3 at bottom byte: 0x{:x}",
            data_with_int3
        );

        self.breakpoints.insert(address, orig_byte as u16);

        // Write INT3 instruction (0xCC)
        // Does it work?
        ptrace::write(self.debugee_pid, address as *mut _, 0xcc)?;

        debug!("Breakpoint set at address 0x{:x}", address);
        Ok(())
    }

    fn remove_breakpoint(&mut self, address: u64) -> Result<(), DebuggerError> {
        if let Some(orig_byte) = self.breakpoints.remove(&address) {
            ptrace::write(self.debugee_pid, address as *mut _, orig_byte as i64)?;
            debug!("Breakpoint removed from address 0x{:x}", address);
        }
        Ok(())
    }

    fn handle_command(&mut self, cmd: &str) -> Result<bool, DebuggerError> {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        match parts.first().copied() {
            Some("si") | Some("step_into") => {
                debug!("Stepping into next instruction");
                ptrace::step(self.debugee_pid, None)?;
                Ok(false)
            }
            Some("so") | Some("step_over") => {
                debug!("Stepping over next instruction");
                let debugee_regs = ptrace::getregs(self.debugee_pid)?;

                let word = ptrace::read(self.debugee_pid, debugee_regs.rip as *mut _)? as u8;
                debug!("Current instruction byte: 0x{:x}", word);

                let is_call_opcode: bool = matches!(word, 0xE8 | 0xFF | 0x9A);
                if is_call_opcode {
                    // TODO:
                    // set breakpoint next instruction and ptrace::count.
                } else {
                    ptrace::step(self.debugee_pid, None)?;
                    return Ok(false);
                }
                Ok(false)
            }
            Some("cr") | Some("continue_until_return") => {
                // WARN: :D
                // I wrote this while checking the oven for my vegetables so it's probably not
                // working the way it should
                debug!("Running until return");
                let debugee_regs = ptrace::getregs(self.debugee_pid)?;
                let return_opcodes = [0xC3, 0xCB, 0xC2, 0xCA];
                let mut instruction_bytes = [0u8; 16];
                for (i, byte) in instruction_bytes.iter_mut().enumerate() {
                    let word =
                        ptrace::read(self.debugee_pid, (debugee_regs.rip as usize + i) as *mut _)?;

                    debug!("Current instruction byte: 0x{:x}", word);

                    for byte_opcode in return_opcodes.iter() {
                        if word == *byte_opcode {
                            debug!("Return instruction");
                        } else {
                            debug!("Not return");
                        }
                    }
                    *byte = word as u8;
                }

                Ok(false)
            }
            Some("c") | Some("continue") => {
                debug!("Continuing execution");
                ptrace::cont(self.debugee_pid, None)?;
                Ok(false)
            }
            Some("p") | Some("print") => {
                self.print_registers()?;
                Ok(true)
            }
            Some("b") | Some("break") => {
                if let Some(addr_str) = parts.get(1) {
                    if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                        self.set_breakpoint(addr)?;
                    }
                }
                Ok(true)
            }
            Some("rb") | Some("remove_bp") => {
                if let Some(addr_str) = parts.get(1) {
                    if let Ok(addr) = u64::from_str_radix(addr_str.trim_start_matches("0x"), 16) {
                        self.remove_breakpoint(addr)?;
                    }
                }
                Ok(true)
            }
            Some("bt") | Some("backtrace") => {
                self.print_backtrace()?;
                Ok(true)
            }
            Some("q") | Some("quit") => {
                debug!("Exiting debugger");
                std::process::exit(0);
            }
            Some(cmd) => {
                warn!("Invalid command: {}", cmd);
                self.print_help();
                Ok(true)
            }
            None => Ok(true),
        }
    }

    fn print_help(&self) {
        println!("Available commands:");
        println!("  s, step         - Step into next instruction");
        println!("  c, continue     - Continue execution");
        println!("  p, print        - Print registers");
        println!("  b, break <addr> - Set breakpoint at address");
        println!("  rb, removebreak <addr> - Remove breakpoint");
        println!("  bt, backtrace   - Print stack backtrace");
        println!("  q, quit         - Exit debugger");
        println!();
    }

    fn print_registers(&self) -> Result<(), DebuggerError> {
        let regs = ptrace::getregs(self.debugee_pid)?;
        debug!(
            "Registers:\n\
            RAX: 0x{:016x}  RBX: 0x{:016x}  RCX: 0x{:016x}\n\
            RDX: 0x{:016x}  RSI: 0x{:016x}  RDI: 0x{:016x}\n\
            RBP: 0x{:016x}  RSP: 0x{:016x}  RIP: 0x{:016x}\n\
            R8:  0x{:016x}  R9:  0x{:016x}  R10: 0x{:016x}\n\
            R11: 0x{:016x}  R12: 0x{:016x}  R13: 0x{:016x}\n\
            R14: 0x{:016x}  R15: 0x{:016x}  FLAGS: 0x{:016x}",
            regs.rax,
            regs.rbx,
            regs.rcx,
            regs.rdx,
            regs.rsi,
            regs.rdi,
            regs.rbp,
            regs.rsp,
            regs.rip,
            regs.r8,
            regs.r9,
            regs.r10,
            regs.r11,
            regs.r12,
            regs.r13,
            regs.r14,
            regs.r15,
            regs.eflags
        );
        Ok(())
    }

    fn print_backtrace(&self) -> Result<(), DebuggerError> {
        let regs = ptrace::getregs(self.debugee_pid)?;
        let mut current_bp = regs.rbp;
        let mut frame_count = 0;

        while current_bp != 0 && frame_count < 20 {
            let return_addr = ptrace::read(self.debugee_pid, (current_bp + 8) as *mut _)? as u64;
            debug!(
                "Frame #{}: return address = 0x{:x}",
                frame_count, return_addr
            );

            current_bp = ptrace::read(self.debugee_pid, current_bp as *mut _)? as u64;
            frame_count += 1;
        }
        Ok(())
    }

    fn print_current_instruction(&self) -> Result<(), DebuggerError> {
        let regs = ptrace::getregs(self.debugee_pid)?;
        let rip = regs.rip;

        let mut instruction_bytes = [0u8; 16];
        for (i, byte) in instruction_bytes.iter_mut().enumerate() {
            let word = ptrace::read(self.debugee_pid, (rip as usize + i) as *mut _)?;
            *byte = word as u8;
        }

        let mut decoder = Decoder::with_ip(64, &instruction_bytes, rip, DecoderOptions::NONE);
        let mut formatter = NasmFormatter::new();
        let mut output = String::new();
        formatter.format(&decoder.decode(), &mut output);

        debug!("Current instruction at 0x{:x}: {}", rip, output);
        Ok(())
    }
}

fn main() -> Result<(), DebuggerError> {
    let matches = Command::new("debugger")
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

    // Clap handle this one.
    let target_executable = matches
        .get_one::<String>("bin")
        .expect("Binary name is required");

    let verbose = matches.get_flag("verbose");
    logger::init(verbose);

    let resolved_exe_path = std::fs::canonicalize(Path::new(target_executable))?;

    info!("Verbose mode: {}", verbose);
    info!("Resolved the target binary path: {:?}", resolved_exe_path);

    // Here we have two ways to start the target process:
    // 1. Command::new -> Get_pid -> ptrace::attach(child_pid);
    // 2. Fork -> Replace the process with the target binary -> ptrace::traceme();
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child, .. }) => trace_child(child),
        Ok(ForkResult::Child) => {
            debug!(
                "Target executable forked successfully! Pid: [{}]",
                std::process::id()
            );

            // Indicates that this process is to be traced by its parent.
            // This is the only ptrace request to be issued by the tracee.
            // I personally dont see any scenario where it can failed
            ptrace::traceme()?;

            // Replace forked child process with the target executable.
            std::process::Command::new(resolved_exe_path).exec();

            unreachable!("Failed to execute the target executable");
        }
        Err(e) => Err(e.into()),
    }
}

fn trace_child(child_pid: Pid) -> Result<(), DebuggerError> {
    debug!("Debugger is executing with pid: [{}]", std::process::id());
    let mut debugger = Debugger::new(child_pid);

    debugger.print_help();

    loop {
        // Wait until our debugee process change status.
        let status = waitpid(child_pid, None)?;

        // Maybe i should check the type of error here.
        handle_child_status(&mut debugger, status)?;
    }
}

fn handle_child_status(debugger: &mut Debugger, status: WaitStatus) -> Result<(), DebuggerError> {
    match status {
        WaitStatus::Exited(pid, exit_code) => {
            // TODO: Should not finish here and instead let a option to rerun or attach a new
            // binary.
            debug!("Child process {} exited with code: {}", pid, exit_code);
            std::process::exit(0);
        }
        WaitStatus::Signaled(pid, signal, core_dumped) => {
            debug!(
                "Child process {} was killed by signal: {:?} (core dumped: {})",
                pid, signal, core_dumped
            );
            // TODO: Same thing as above, maybe return a specific error and handle it when returned
            // to let the debugger not finish.
        }
        WaitStatus::Stopped(pid, signal) => {
            debug!("Child process {} was stopped by signal: {:?}", pid, signal);
            handle_stopped_process(debugger, pid, signal)?;
        }
        WaitStatus::PtraceEvent(pid, signal, event) => {
            debug!(
                "Child process {} received ptrace event: {} (signal: {:?})",
                pid, event, signal
            );
        }
        WaitStatus::PtraceSyscall(pid) => {
            debug!("Child process {} entered a syscall", pid);
        }
        WaitStatus::Continued(pid) => {
            debug!("Child process {} continued", pid);
        }
        WaitStatus::StillAlive => {
            debug!("Child process is still alive");
        }
    }
    Ok(())
}

fn handle_stopped_process(
    debugger: &mut Debugger,
    _pid: Pid,
    signal: Signal,
) -> Result<(), DebuggerError> {
    if signal == Signal::SIGTRAP {
        debugger.print_current_instruction()?;
        loop {
            print!("(kme-dbg) :: ");

            std::io::stdout().flush()?;
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !debugger.handle_command(input.trim())? {
                break;
            }
        }
    } else {
        debug!("Unhandled stop signal: {:?}", signal);
    }

    Ok(())
}

fn print_current_instruction(pid: Pid, rip: u64) -> Result<(), Errno> {
    // In the x86 and x86-64 architectures, the maximum instruction length is 15 bytes. This limit is defined by the architecture itself
    let mut instruction_bytes = [0u8; 16];
    for (i, byte) in instruction_bytes.iter_mut().enumerate() {
        // WARN:
        // Converting rip to usize might lose data if the architecture is 32bit or 16bit, which
        // would make this operation likely to fail.
        let word = ptrace::read(pid, (rip as usize + i) as *mut _)?;
        *byte = word as u8;
    }

    let mut decoder = Decoder::with_ip(
        64,                   // 64-bit mode
        &instruction_bytes,   // Code buffer
        rip,                  // RIP
        DecoderOptions::NONE, // No special options needed
    );
    let mut formatter = NasmFormatter::new();
    let mut output = String::new();
    formatter.format(&decoder.decode(), &mut output);

    debug!("Current instruction at 0x{:x}: {}", rip, output);
    Ok(())
}
