//! A small leveled logger: `HH:MM:SS LEVEL  message`, with ANSI colors
//! when standard output is a terminal and `NO_COLOR` is unset.
//!
//! No dependency: the runtime is one atomic for the level and one for the
//! resolved color choice. Messages below the configured level are dropped.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::now;

/// Log levels, ordered least to most severe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Routine detail, hidden by default.
    Debug,
    /// Normal operation.
    Info,
    /// Something unexpected that the node handled.
    Warn,
    /// A failure worth attention.
    Error,
}

impl Level {
    /// The fixed-width tag shown in a log line.
    fn tag(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO ",
            Self::Warn => "WARN ",
            Self::Error => "ERROR",
        }
    }

    /// The ANSI color for the tag.
    fn color(self) -> &'static str {
        match self {
            Self::Debug => "\x1b[36m",
            Self::Info => "\x1b[32m",
            Self::Warn => "\x1b[33m",
            Self::Error => "\x1b[1;31m",
        }
    }
}

impl core::str::FromStr for Level {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warn" => Ok(Self::Warn),
            "error" => Ok(Self::Error),
            other => Err(format!(
                "unknown log level {other}, expected debug|info|warn|error"
            )),
        }
    }
}

/// The minimum level printed. Defaults to [`Level::Info`].
static MIN_LEVEL: AtomicU8 = AtomicU8::new(Level::Info as u8);
/// Resolved color choice: 0 = undecided, 1 = on, 2 = off.
static COLOR: AtomicU8 = AtomicU8::new(0);

/// Sets the minimum level printed.
pub fn set_level(level: Level) {
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

fn enabled(level: Level) -> bool {
    level as u8 >= MIN_LEVEL.load(Ordering::Relaxed)
}

/// Whether to color output: a terminal with `NO_COLOR` unset. Decided once.
fn colored() -> bool {
    match COLOR.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let on = std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal();
            COLOR.store(if on { 1 } else { 2 }, Ordering::Relaxed);
            on
        }
    }
}

/// The wall-clock time as `HH:MM:SS` in UTC.
fn clock() -> String {
    let secs = now() % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Renders one line. Separated from I/O so it can be tested.
fn line(level: Level, time: &str, message: &str, color: bool) -> String {
    if color {
        format!(
            "\x1b[2m{time}\x1b[0m {}{}\x1b[0m  {message}",
            level.color(),
            level.tag()
        )
    } else {
        format!("{time} {}  {message}", level.tag())
    }
}

fn emit(level: Level, message: &str) {
    if enabled(level) {
        println!("{}", line(level, &clock(), message, colored()));
    }
}

/// Logs at [`Level::Debug`].
pub fn debug(message: &str) {
    emit(Level::Debug, message);
}

/// Logs at [`Level::Info`].
pub fn info(message: &str) {
    emit(Level::Info, message);
}

/// Logs at [`Level::Warn`].
pub fn warn(message: &str) {
    emit(Level::Warn, message);
}

/// Logs at [`Level::Error`].
pub fn error(message: &str) {
    emit(Level::Error, message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_parse_and_order() {
        assert_eq!("warn".parse::<Level>().unwrap(), Level::Warn);
        assert!("shout".parse::<Level>().is_err());
        assert!(
            Level::Debug < Level::Info && Level::Info < Level::Warn && Level::Warn < Level::Error
        );
    }

    #[test]
    fn plain_lines_have_the_level_tag_and_no_escapes() {
        let plain = line(Level::Warn, "12:00:00", "careful", false);
        assert_eq!(plain, "12:00:00 WARN   careful");
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn colored_lines_wrap_the_tag_in_ansi() {
        let colored = line(Level::Error, "12:00:00", "boom", true);
        assert!(colored.contains("\x1b[1;31mERROR\x1b[0m"));
        assert!(colored.contains("boom"));
    }

    #[test]
    fn the_level_filter_gates_by_severity() {
        set_level(Level::Warn);
        assert!(!enabled(Level::Info) && !enabled(Level::Debug));
        assert!(enabled(Level::Warn) && enabled(Level::Error));
        set_level(Level::Info);
        assert!(enabled(Level::Info) && !enabled(Level::Debug));
    }
}
