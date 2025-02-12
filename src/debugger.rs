use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use nix::{sys::ptrace, unistd::Pid};

use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::os::unix::fs::FileExt;
use std::os::unix::process::CommandExt;
use std::{collections::HashMap, fmt::Debug};

use tracing::*;

use tracing as log;

use std::io::Write;
use std::io::{self, Read};
use std::path::PathBuf;

use nix::{
    errno::Errno,
    sys::{
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::{fork, ForkResult},
};

use thiserror::Error;

const INT3: u8 = 0xcc;
const ET_DYN: u16 = 0x03;
const ET_EXEC: u16 = 0x02;
const ELF_TYPE: u64 = 0x10;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum DebuggerError {
    #[error("Internal I/O operation failed due to: {0}")]
    IoError(#[from] io::Error),
    #[error("Failed to attach to target process: {0}")]
    AttachError(String),
    #[error("Provided binary \"{0}\" was not found.")]
    NotFound(String),
    #[error("Invalid command. Use 'help' to see available commands.")]
    InvalidCommand,
    #[error("Breakpoint error: {0}")]
    BreakpointError(#[from] BreakpointError),
    #[error("System error: {0}")]
    SystemError(#[from] Errno),
    #[error("Could not find the Base Address reading \"/proc/<proc>/maps\" due to: {0}")]
    BaseAddressError(String),
}

#[derive(Error, Debug)]
pub enum BreakpointError {
    #[error("Failed to read memory at address 0x{address:x}")]
    MemoryReadFailed { address: u64, source: nix::Error },

    #[error("Failed to write breakpoint at address 0x{address:x}")]
    MemoryWriteFailed { address: u64, source: nix::Error },
}

pub struct Debugger {
    // In the x86 and x86-64 architectures, the maximum instruction length is 15 bytes. This limit is defined by the architecture itself
    breakpoints: HashMap<u64, u16>, // Address and the replaced byte.
    debugee_pid: Pid,
    exe: PathBuf,
}

pub enum Arch {
    B32,
    B64,
    Invalid,
}

pub trait FileArch {
    fn get_arch(&mut self) -> Arch;
}

impl FileArch for File {
    fn get_arch(&mut self) -> Arch {
        let mut header = [0u8; 5]; // First 5 bytes-- magic and arch.

        let _ = self.read_exact(&mut header);

        if header[0..4] != [0x7F, b'E', b'L', b'F'] {
            return Arch::Invalid;
        }

        match header[4] {
            0x01 => Arch::B32,
            0x02 => Arch::B64,
            _ => Arch::Invalid,
        }
    }
}

impl Debugger {
    pub fn launch(exe: PathBuf) -> Result<Self, DebuggerError> {
        let f = unsafe { fork().map_err(DebuggerError::SystemError)? };
        match f {
            ForkResult::Parent { child } => {
                let debugger = Debugger::init(child, exe);
                Ok(debugger)
            }
            ForkResult::Child => {
                debug!("Process forked, Child's PID is [{}].", std::process::id());

                ptrace::traceme().map_err(DebuggerError::SystemError)?;

                let _ = std::process::Command::new(exe).exec();

                // This line will never be reached because `exec` replaces the current process image
                unreachable!("Failed to execute the target executable");
            }
        }
    }

    fn init(p: Pid, exe: PathBuf) -> Self {
        Self {
            breakpoints: HashMap::new(),
            debugee_pid: p,
            exe,
        }
    }

    pub fn set_breakpoint(&mut self, address: u64) -> Result<(), BreakpointError> {
        // Read original instruction
        let orig_byte = match ptrace::read(self.debugee_pid, address as *mut _) {
            Ok(byte) => byte,
            Err(e) => {
                return Err(BreakpointError::MemoryReadFailed { address, source: e });
            }
        };

        let breakpoint_instruction = (orig_byte & !0xff) | INT3 as i64;

        ptrace::write(self.debugee_pid, address as *mut _, breakpoint_instruction)
            .map_err(|source| BreakpointError::MemoryWriteFailed { address, source })?;

        self.breakpoints.insert(address, orig_byte as u16);

        Ok(())
    }
    pub fn remove_breakpoint(&mut self, address: u64) -> Result<(), DebuggerError> {
        if let Some(orig_byte) = self.breakpoints.remove(&address) {
            ptrace::write(self.debugee_pid, address as *mut _, orig_byte as i64)?;
            debug!("Breakpoint removed from address 0x{:x}", address);
        }
        Ok(())
    }

    pub fn wait_for_signal(&mut self) -> Result<(), DebuggerError> {
        debug!("Debugger is executing with pid: [{}]", std::process::id());
        debug!("Started waiting for child's signal.");

        loop {
            // Wait until our debugee process change status.
            let status = waitpid(self.debugee_pid, None)?;

            // Maybe i should check the type of error here.
            self.handle_child_status(status)?;
        }
    }

    /// Sets a breakpoint at the program's entry point.
    ///
    /// This function determines the entry point of the executable using `find_entrypoint`
    /// and sets a breakpoint accordingly. It differentiates between Position Independent
    /// Executables (PIE) and non-PIE executables since to put a breakpoint in PIE we need
    /// to calculate the EP address using offset from the header and the BaseAddress, see:
    /// Runtime EntryPoint = PIE Base Address + EntryPoint Offset
    pub fn break_entrypoint(&mut self) -> Result<(), DebuggerError> {
        let mut fd = File::open(self.exe.clone())?;
        let mut header = [0u8; 2];

        fd.read_exact_at(&mut header, ELF_TYPE)?;

        let ep = self.find_entrypoint(&mut fd)?;

        match u16::from_le_bytes(header) {
            ET_DYN => {
                log::debug!(
                    "PIE enabled, calculating entrypoint address using header address as offset."
                );
                let base_addr = self.get_base_address()?;
                log::info!("Found BaseAddress: 0x{base_addr:x}");
                let ep = base_addr + ep as u64;
                self.set_breakpoint(ep)?;
            }
            ET_EXEC => {
                debug!("PIE not enabled, attempting to set breakpoint using raw header address.");
                self.set_breakpoint(ep as u64)?;
            }

            _ => unimplemented!(),
        }

        log::info!("Breakpoint at EntryPoint was added.");

        Ok(())
    }

    fn get_base_address(&self) -> Result<u64, DebuggerError> {
        let maps_file_path = format!("/proc/{}/maps", self.debugee_pid);
        let maps_file = File::open(maps_file_path)?;
        let reader = BufReader::new(maps_file);

        if let Some(line_result) = reader.lines().next() {
            let line = line_result?;

            let base_addr = line
                .split_whitespace()
                .next()
                .and_then(|first_line| first_line.split('-').next())
                .unwrap();

            return Ok(u64::from_str_radix(base_addr, 16).unwrap());
        }

        Err(DebuggerError::BaseAddressError(
            "Could not read maps from the exe".to_string(),
        ))
    }

    /// This is the memory address or the *offset* of the entry point from where the process starts executing.
    /// This field is either 32 or 64 bits long, depending on the format defined earlier (byte 0x04).
    /// If the file doesn't have an associated entry point, then this holds zero.
    fn find_entrypoint(&self, fd: &mut File) -> Result<usize, DebuggerError> {
        match fd.get_arch() {
            Arch::B32 => {
                log::info!("Provided binary is 32bit.");

                // This field is either 32 or 64 bits long, depending on the architecture.
                let mut header = [0u8; 4];

                fd.read_exact_at(&mut header, 0x18)?;

                let addr = u32::from_le_bytes(header);
                log::info!("EntryPoint at 0x{:x}", addr);
                return Ok(addr as usize);
            }
            Arch::B64 => {
                log::info!("Provided binary is 64bit.");

                // This field is either 32 or 64 bits long, depending on the architecture.
                let mut header = [0u8; 8];

                fd.read_exact_at(&mut header, 0x18)?;

                let addr = u64::from_le_bytes(header);
                log::info!("EntryPoint at 0x{:x}", addr);
                return Ok(addr as usize);
            }
            Arch::Invalid => {
                log::error!("Invalid Binary, Could not read ELF Header.");
            }
        }

        Ok(0)
    }

    fn handle_stopped_process(&mut self, _pid: Pid, signal: Signal) -> Result<(), DebuggerError> {
        // FIX: It only works after the first TRAP is received but if i keep it here it would put a
        // breakpoint every stopped signal.
        self.break_entrypoint()?;

        if signal == Signal::SIGTRAP {
            self.print_current_instruction()?;
            loop {
                print!("(kme-dbg) :: ");

                std::io::stdout().flush()?;
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;

                if !self.handle_command(input.trim())? {
                    break;
                }
            }
        } else {
            debug!("Unhandled stop signal: {:?}", signal);
        }

        Ok(())
    }

    fn handle_child_status(&mut self, status: WaitStatus) -> Result<(), DebuggerError> {
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
                let addr = ptrace::getregs(pid)?.rip;
                debug!("Stopped at address: 0x{addr:x}");

                self.handle_stopped_process(pid, signal)?;
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

    // TODO:
    // TOMORROW ->
    // HANDLE ERRORS INSTEAD OF CRASHING.
    // DEFINE ERRORS FOR PTRACE OPERATIONS.
    pub fn handle_command(&mut self, cmd: &str) -> Result<bool, DebuggerError> {
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
                        debug!("Trying to set breakpoint at: 0x{:x}", addr);
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

    pub fn print_help(&self) {
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

    pub fn print_registers(&self) -> Result<(), DebuggerError> {
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

    pub fn print_backtrace(&self) -> Result<(), DebuggerError> {
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

    pub fn print_current_instruction(&self) -> Result<(), DebuggerError> {
        let regs = ptrace::getregs(self.debugee_pid)?;
        let rip = regs.rip;

        let mut instruction_bytes = [0u8; 16];
        // WARN:
        // Converting rip to usize might lose data if the architecture is 32bit or 16bit, which
        // would make this operation likely to fail.
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
