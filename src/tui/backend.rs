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

/// Standard console backend using ANSI escape sequences.
pub struct ConsoleBackend {
    width: u16,
    height: u16,
}

impl ConsoleBackend {
    pub fn stdout() -> Self {
        Self {
            width: 80,
            height: 24,
        }
    }
}

impl TerminalBackend for ConsoleBackend {
    fn size(&self) -> (u16, u16) {
        (self.width, self.height)
    }

    fn read_event(&mut self) -> io::Result<Option<TerminalEvent>> {
        let mut buf = [0u8; 4];
        let n = io::stdin().read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        if buf[0] == 0x1b {
            if n >= 3 && buf[1] == b'[' {
                match buf[2] {
                    b'A' => return Ok(Some(TerminalEvent::Key(KeyCode::Up))),
                    b'B' => return Ok(Some(TerminalEvent::Key(KeyCode::Down))),
                    b'C' => return Ok(Some(TerminalEvent::Key(KeyCode::Right))),
                    b'D' => return Ok(Some(TerminalEvent::Key(KeyCode::Left))),
                    _ => {}
                }
            }
            return Ok(Some(TerminalEvent::Key(KeyCode::Escape)));
        }
        match buf[0] {
            b'\r' | b'\n' => Ok(Some(TerminalEvent::Key(KeyCode::Enter))),
            b'\t' => Ok(Some(TerminalEvent::Key(KeyCode::Tab))),
            0x7f | 0x08 => Ok(Some(TerminalEvent::Key(KeyCode::Backspace))),
            b => Ok(Some(TerminalEvent::Key(KeyCode::Char(b as char)))),
        }
    }

    fn write_str(&mut self, s: &str) -> io::Result<()> {
        io::stdout().write_all(s.as_bytes())
    }

    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }

    fn enter_raw_mode(&mut self) -> io::Result<()> {
        // Hide cursor
        self.write_str("\x1b[?25l")?;
        self.flush()
    }

    fn exit_raw_mode(&mut self) -> io::Result<()> {
        // Show cursor
        self.write_str("\x1b[?25h")?;
        self.flush()
    }
}
