//! Terminal Backend Abstraction for Interactive Vouch TUI.

use std::collections::VecDeque;
use std::io::{self, Read, Write};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyCode {
    Char(char),
    Up,
    Down,
    Left,
    Right,
    Enter,
    Escape,
    Tab,
    Backspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvent {
    Key(KeyCode),
    Resize(u16, u16),
}

pub trait TerminalBackend: Send {
    fn size(&self) -> (u16, u16);
    fn read_event(&mut self) -> io::Result<Option<TerminalEvent>>;
    fn write_str(&mut self, s: &str) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
    fn enter_raw_mode(&mut self) -> io::Result<()>;
    fn exit_raw_mode(&mut self) -> io::Result<()>;
}

/// Headless mock terminal backend for unit testing interactive sessions.
pub struct MockTerminalBackend {
    pub width: u16,
    pub height: u16,
    pub events: VecDeque<TerminalEvent>,
    pub output_buffer: Vec<u8>,
    pub rendered_frames: Vec<String>,
    pub raw_mode: bool,
}

impl MockTerminalBackend {
    pub fn new(width: u16, height: u16, events: Vec<TerminalEvent>) -> Self {
        Self {
            width,
            height,
            events: VecDeque::from(events),
            output_buffer: Vec::new(),
            rendered_frames: Vec::new(),
            raw_mode: false,
        }
    }

    pub fn last_frame(&self) -> Option<&str> {
        self.rendered_frames.last().map(String::as_str)
    }
}

impl TerminalBackend for MockTerminalBackend {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn read_event(&mut self) -> io::Result<Option<TerminalEvent>> {
        Ok(self.events.pop_front())
    }

    fn write_str(&mut self, s: &str) -> io::Result<()> {
        self.output_buffer.extend_from_slice(s.as_bytes());
        Ok(())
    }

    fn flush(&mut self) -> io::Result<()> {
        let frame = String::from_utf8_lossy(&self.output_buffer).to_string();
        self.rendered_frames.push(frame);
        self.output_buffer.clear();
        Ok(())
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        self.raw_mode = true;
        Ok(())
    }

    fn exit_raw_mode(&mut self) -> io::Result<()> {
        self.raw_mode = false;
        Ok(())
    }
}

/// RAII guard managing OS-level raw terminal mode.
/// Guarantees restoration to canonical cooked mode upon drop or thread panic.
pub struct RawModeGuard {
    #[cfg(unix)]
    original_termios: Option<libc::termios>,
    #[cfg(windows)]
    original_mode: Option<u32>,
    active: bool,
}

impl RawModeGuard {
    pub fn acquire() -> io::Result<Self> {
        #[cfg(unix)]
        {
            unsafe {
                if libc::isatty(libc::STDIN_FILENO) != 1 {
                    return Ok(Self {
                        original_termios: None,
                        active: false,
                    });
                }
                let mut original = std::mem::zeroed::<libc::termios>();
                if libc::tcgetattr(libc::STDIN_FILENO, &mut original) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut raw = original;
                // Clear canonical mode, echo, extended input processing, signal chars
                raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG | libc::IEXTEN);
                // Clear flow control and input translations
                raw.c_iflag &= !(libc::IXON | libc::ICRNL | libc::BRKINT | libc::INPCK | libc::ISTRIP);
                // Set non-blocking with 0.1s read timeout for single keystroke dispatch
                raw.c_cc[libc::VMIN] = 0;
                raw.c_cc[libc::VTIME] = 1;

                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &raw) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Self {
                    original_termios: Some(original),
                    active: true,
                })
            }
        }
        #[cfg(windows)]
        {
            Ok(Self {
                original_mode: None,
                active: false,
            })
        }
        #[cfg(not(any(unix, windows)))]
        {
            Ok(Self { active: false })
        }
    }

    pub fn restore(&mut self) {
        if !self.active {
            return;
        }
        #[cfg(unix)]
        {
            if let Some(ref original) = self.original_termios {
                unsafe {
                    let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, original);
                }
            }
        }
        self.active = false;
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Pure decoder turning a raw byte slice into a TerminalEvent and byte count consumed.
pub fn decode_key_bytes(buf: &[u8]) -> Option<(TerminalEvent, usize)> {
    if buf.is_empty() {
        return None;
    }
    if buf[0] == 0x1b {
        if buf.len() >= 3 && buf[1] == b'[' {
            match buf[2] {
                b'A' => return Some((TerminalEvent::Key(KeyCode::Up), 3)),
                b'B' => return Some((TerminalEvent::Key(KeyCode::Down), 3)),
                b'C' => return Some((TerminalEvent::Key(KeyCode::Right), 3)),
                b'D' => return Some((TerminalEvent::Key(KeyCode::Left), 3)),
                _ => {}
            }
        }
        return Some((TerminalEvent::Key(KeyCode::Escape), 1));
    }
    match buf[0] {
        b'\r' | b'\n' => Some((TerminalEvent::Key(KeyCode::Enter), 1)),
        b'\t' => Some((TerminalEvent::Key(KeyCode::Tab), 1)),
        0x7f | 0x08 => Some((TerminalEvent::Key(KeyCode::Backspace), 1)),
        b => {
            if let Ok(s) = std::str::from_utf8(buf) {
                if let Some(ch) = s.chars().next() {
                    return Some((TerminalEvent::Key(KeyCode::Char(ch)), ch.len_utf8()));
                }
            }
            Some((TerminalEvent::Key(KeyCode::Char(b as char)), 1))
        }
    }
}

/// Standard console backend using ANSI escape sequences and unbuffered OS raw mode.
pub struct ConsoleBackend {
    width: u16,
    height: u16,
    raw_guard: Option<RawModeGuard>,
}

impl ConsoleBackend {
    pub fn stdout() -> Self {
        Self {
            width: 80,
            height: 24,
            raw_guard: None,
        }
    }
}

impl TerminalBackend for ConsoleBackend {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn read_event(&mut self) -> io::Result<Option<TerminalEvent>> {
        let mut buf = [0u8; 16];
        let n = io::stdin().read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if let Some((event, _)) = decode_key_bytes(&buf[..n]) {
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    fn write_str(&mut self, s: &str) -> io::Result<()> {
        io::stdout().write_all(s.as_bytes())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        if self.raw_guard.is_none() {
            self.raw_guard = Some(RawModeGuard::acquire()?);
        }
        // Hide cursor
        self.write_str("\x1b[?25l")?;
        self.flush()
    }

    fn exit_raw_mode(&mut self) -> io::Result<()> {
        // Show cursor
        let _ = self.write_str("\x1b[?25h");
        let _ = self.flush();
        if let Some(mut guard) = self.raw_guard.take() {
            guard.restore();
        }
        Ok(())
    }
}
