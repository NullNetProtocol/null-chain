//! A small leveled logger: `HH:MM:SS LEVEL  message`, with ANSI colors
//! when standard output is a terminal and `NO_COLOR` is unset. Optionally
//! every line is also appended to a file as `YYYY-MM-DD HH:MM:SS LEVEL
//! message` (UTC, never colored), for nodes run without a terminal.
//!
//! No dependency: the runtime is one atomic for the level, one for the
//! resolved color choice and a mutex around the optional file. Messages
//! below the configured level are dropped.

use std::fs::File;
use std::io::{IsTerminal, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Mutex, PoisonError};

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
/// The log file, if one is set. Logging is synchronous, so a `std` mutex
/// held for one write is enough.
static FILE: Mutex<Option<File>> = Mutex::new(None);

/// Sets the minimum level printed.
pub fn set_level(level: Level) {
    MIN_LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Also appends every logged line to `path`, creating it if needed,
/// readable only by the owner on Unix since lines name peer addresses; an
/// existing file is made owner-only too.
///
/// # Errors
/// Fails if the file cannot be opened for appending.
pub fn set_file(path: &Path) -> std::io::Result<()> {
    let file = open_file(path)?;
    *FILE.lock().unwrap_or_else(PoisonError::into_inner) = Some(file);
    Ok(())
}

fn open_file(path: &Path) -> std::io::Result<File> {
    let file = crate::paths::private_open_options()
        .create(true)
        .append(true)
        .open(path)?;
    crate::paths::restrict(&file)?;
    Ok(file)
}

/// Stops writing the log file, if one is set.
pub fn clear_file() {
    *FILE.lock().unwrap_or_else(PoisonError::into_inner) = None;
}

/// Applies the logging options every binary shares: the optional log file,
/// then the minimum level.
///
/// # Errors
/// Fails, changing nothing, if the log file cannot be opened.
pub fn init(level: Level, file: Option<&Path>) -> std::io::Result<()> {
    file.map_or(Ok(()), set_file)?;
    set_level(level);
    Ok(())
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

/// `secs` since the epoch as `HH:MM:SS` in UTC.
fn clock(secs: u64) -> String {
    let secs = secs % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// `secs` since the epoch as `YYYY-MM-DD HH:MM:SS` in UTC.
fn date_time(secs: u64) -> String {
    format!("{} {}", date(secs / 86_400), clock(secs))
}

/// The Gregorian date `days` after 1970-01-01 as `YYYY-MM-DD`, by Howard
/// Hinnant's `civil_from_days` (eras of 400 years starting in March).
// `days` is at most `u64::MAX / 86_400`, so no product overflows, and each
// subtraction removes a part already counted in the value it is taken from.
#[allow(clippy::arithmetic_side_effects)]
fn date(days: u64) -> String {
    let z = days + 719_468;
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let march_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * march_month + 2) / 5 + 1;
    let month = if march_month < 10 {
        march_month + 3
    } else {
        march_month - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
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
    if !enabled(level) {
        return;
    }
    let secs = now();
    println!("{}", line(level, &clock(secs), message, colored()));
    if let Some(file) = FILE.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
        // A failed write has nowhere better to be reported; the console
        // still has the line.
        let _ = append(file, level, secs, message);
    }
}

/// Writes one file line: dated, never colored.
fn append(out: &mut impl Write, level: Level, secs: u64, message: &str) -> std::io::Result<()> {
    writeln!(out, "{}", line(level, &date_time(secs), message, false))
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
    fn dates_follow_the_gregorian_calendar() {
        let cases = [
            (0, "1970-01-01 00:00:00"),
            (951_782_400, "2000-02-29 00:00:00"),
            (1_709_164_800, "2024-02-29 00:00:00"),
            (1_792_658_298, "2026-10-22 08:38:18"),
            (4_102_444_799, "2099-12-31 23:59:59"),
        ];
        for (secs, want) in cases {
            assert_eq!(date_time(secs), want, "{secs}");
        }
    }

    // These tests never install the global file: other tests log in
    // parallel and would write into it.
    #[test]
    fn file_lines_are_dated_and_never_colored() {
        let mut out = Vec::new();
        append(&mut out, Level::Warn, 1_792_658_298, "careful").unwrap();
        assert_eq!(out, b"2026-10-22 08:38:18 WARN   careful\n");
    }

    #[test]
    fn log_files_are_appended_to_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("debug.log");
        std::fs::write(&path, "earlier\n").unwrap();
        append(&mut open_file(&path).unwrap(), Level::Info, 0, "first").unwrap();
        append(&mut open_file(&path).unwrap(), Level::Info, 0, "second").unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            text,
            "earlier\n1970-01-01 00:00:00 INFO   first\n1970-01-01 00:00:00 INFO   second\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let created = dir.path().join("new.log");
            open_file(&created).unwrap();
            let mode = std::fs::metadata(&created).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let shared = std::fs::Permissions::from_mode(0o644);
            std::fs::set_permissions(&path, shared).unwrap();
            open_file(&path).unwrap();
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "an existing world-readable log");
        }
    }

    #[test]
    fn unopenable_log_files_are_an_error() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open_file(&dir.path().join("missing").join("x.log")).is_err());
        assert!(init(Level::Info, Some(&dir.path().join("missing").join("x.log"))).is_err());
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
