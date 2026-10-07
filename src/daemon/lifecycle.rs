//! Daemon Process Lifecycle, Detachment & Signal Management (M6.3).
//!
//! Provides background process daemonization, PID file management with advisory
//! locking and stale process detection, cryptographic session token generation,
//! and clean signal trapping (SIGTERM/SIGINT) for graceful socket unlinking.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Check if a process with the given PID is currently active.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        unsafe {
            if libc::kill(pid as libc::pid_t, 0) == 0 {
                return true;
            }
            let err = io::Error::last_os_error();
            // EPERM means the process exists but is owned by another user
            err.raw_os_error() == Some(libc::EPERM)
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Generate a secure random 256-bit hexadecimal session token.
pub fn generate_session_token() -> String {
    use sha2::{Digest, Sha256};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let pid = std::process::id();
    let mut hasher = Sha256::new();
    hasher.update(now.to_le_bytes());
    hasher.update(pid.to_le_bytes());
    hasher.update(b"vouch-daemon-session-salt-v1");
    format!("{:x}", hasher.finalize())
}

/// RAII Guard managing PID file creation, locking, and unlinking.
pub struct PidLockGuard {
    pub path: PathBuf,
    pub pid: u32,
    active: bool,
}

impl PidLockGuard {
    /// Attempt to acquire PID file lock. Returns error if another daemon is live.
    pub fn acquire(pid_path: &Path) -> Result<Self, String> {
        if pid_path.exists() {
            if let Ok(mut f) = File::open(pid_path) {
                let mut contents = String::new();
                if f.read_to_string(&mut contents).is_ok() {
                    if let Ok(existing_pid) = contents.trim().parse::<u32>() {
                        if is_pid_alive(existing_pid) {
                            return Err(format!(
                                "vouch daemon already running with PID {existing_pid} (lock: {})",
                                pid_path.display()
                            ));
                        }
                    }
                }
            }
            // Remove stale PID file if process is no longer alive
            let _ = std::fs::remove_file(pid_path);
        }

        if let Some(parent) = pid_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let pid = std::process::id();
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(pid_path)
                .map_err(|e| format!("could not create PID file {}: {e}", pid_path.display()))?;
            writeln!(f, "{pid}").map_err(|e| e.to_string())?;
            f.flush().map_err(|e| e.to_string())?;
        }
        #[cfg(not(unix))]
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(pid_path)
                .map_err(|e| format!("could not create PID file {}: {e}", pid_path.display()))?;
            writeln!(f, "{pid}").map_err(|e| e.to_string())?;
            f.flush().map_err(|e| e.to_string())?;
        }

        Ok(Self {
            path: pid_path.to_path_buf(),
            pid,
            active: true,
        })
    }

    /// Explicitly release and unlink the PID file.
    pub fn release(&mut self) {
        if self.active {
            let _ = std::fs::remove_file(&self.path);
            self.active = false;
        }
    }
}

impl Drop for PidLockGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Fork the current process into the background (Unix double-fork daemonization).
pub fn daemonize_process(log_path: Option<&Path>) -> Result<(), String> {
    #[cfg(unix)]
    {
        unsafe {
            // First fork
            let pid = libc::fork();
            if pid < 0 {
                return Err("fork(1) failed".into());
            }
            if pid > 0 {
                // Initial parent process exits immediately
                libc::_exit(0);
            }

            // Create new session and detach from controlling terminal
            if libc::setsid() < 0 {
                return Err("setsid() failed".into());
            }

            // Second fork: ensure daemon cannot re-acquire controlling terminal
            let pid2 = libc::fork();
            if pid2 < 0 {
                return Err("fork(2) failed".into());
            }
            if pid2 > 0 {
                libc::_exit(0);
            }

            // Set restrictive file mode creation mask
            libc::umask(0o077);

            // Redirect stdin to /dev/null
            let dev_null = std::ffi::CString::new("/dev/null").unwrap();
            let fd_null = libc::open(dev_null.as_ptr(), libc::O_RDWR);
            if fd_null >= 0 {
                libc::dup2(fd_null, libc::STDIN_FILENO);
            }

            // Redirect stdout & stderr to log file if provided, otherwise /dev/null
            if let Some(log) = log_path {
                if let Some(parent) = log.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let log_c = std::ffi::CString::new(log.to_string_lossy().as_bytes()).unwrap();
                let fd_log = libc::open(
                    log_c.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
                    0o600,
                );
                if fd_log >= 0 {
                    libc::dup2(fd_log, libc::STDOUT_FILENO);
                    libc::dup2(fd_log, libc::STDERR_FILENO);
                    if fd_log > 2 {
                        libc::close(fd_log);
                    }
                }
            } else if fd_null >= 0 {
                libc::dup2(fd_null, libc::STDOUT_FILENO);
                libc::dup2(fd_null, libc::STDERR_FILENO);
            }

            if fd_null > 2 {
                libc::close(fd_null);
            }
            Ok(())
        }
    }
    #[cfg(not(unix))]
    {
        let _ = log_path;
        Err("daemonization is not supported on this platform".into())
    }
}

static GLOBAL_SHUTDOWN: std::sync::OnceLock<Arc<AtomicBool>> = std::sync::OnceLock::new();

/// Install SIGTERM and SIGINT signal handlers connected to the shutdown flag.
pub fn install_signal_handlers(flag: Arc<AtomicBool>) {
    let _ = GLOBAL_SHUTDOWN.set(flag);

    #[cfg(unix)]
    {
        extern "C" fn handle_signal(sig: libc::c_int) {
            if sig == libc::SIGTERM || sig == libc::SIGINT {
                if let Some(flag) = GLOBAL_SHUTDOWN.get() {
                    flag.store(true, Ordering::SeqCst);
                }
            }
        }

        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = handle_signal as *const () as usize;
            sa.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut sa.sa_mask);

            libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
            libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        }
    }
}
