//! Linux desktop integration: the app menu entry and taskbar icon.
//!
//! Wayland compositors, including KDE Plasma and GNOME, take a window's
//! icon from the installed desktop entry named after its app id; the icon a
//! window sets on itself is ignored there. So on Linux the app installs its
//! own entry and icon for the current user at startup, and rewrites them
//! only when they are missing or stale, for example after the binary moved.

use std::fs;
use std::path::Path;

use null_node::Result;

/// The app id: the window's Wayland app id and X11 class, and the desktop
/// entry's file name.
pub const APP_ID: &str = "sh.nullnet.Wallet";

/// The desktop entry, with `@BIN@` and `@ICON@` to fill in.
const TEMPLATE: &str = include_str!("../assets/sh.nullnet.Wallet.desktop");

/// The desktop entry for the binary at `exe` with the icon at `icon`.
pub fn entry(exe: &Path, icon: &Path) -> String {
    TEMPLATE
        .replace("@BIN@", &exec_argument(&exe.to_string_lossy()))
        .replace("@ICON@", &icon.to_string_lossy())
}

/// Quotes a program path for an `Exec` key when it needs it, as the
/// Desktop Entry spec requires for spaces and reserved characters.
fn exec_argument(path: &str) -> String {
    const RESERVED: &[char] = &[
        ' ', '\t', '\n', '"', '\'', '\\', '>', '<', '~', '|', '&', ';', '$', '*', '?', '#', '(',
        ')', '`',
    ];
    if !path.contains(RESERVED) {
        return path.to_owned();
    }
    let mut quoted = String::from('"');
    for c in path.chars() {
        if matches!(c, '"' | '`' | '$' | '\\') {
            quoted.push('\\');
        }
        quoted.push(c);
    }
    quoted.push('"');
    quoted
}

/// Installs the entry into `applications` and the icon at `icon`, writing
/// only what differs. Returns whether anything changed.
///
/// # Errors
/// Fails if a directory or file cannot be written.
pub fn install(applications: &Path, icon: &Path, exe: &Path, icon_png: &[u8]) -> Result<bool> {
    let entry_path = applications.join(format!("{APP_ID}.desktop"));
    let wrote_icon = write_if_changed(icon, icon_png)?;
    let wrote_entry = write_if_changed(&entry_path, entry(exe, icon).as_bytes())?;
    Ok(wrote_icon || wrote_entry)
}

/// [`install`] for the running binary into the user's XDG data directory:
/// `applications/` for the entry and `icons/` for the icon.
///
/// # Errors
/// Fails if the data directory is unknown or a file cannot be written.
#[cfg(target_os = "linux")]
pub fn install_for_user(icon_png: &[u8]) -> Result<bool> {
    let home = null_node::paths::data_home()?;
    let exe = std::env::current_exe()?;
    install(
        &home.join("applications"),
        &home.join("icons").join(format!("{APP_ID}.png")),
        &exe,
        icon_png,
    )
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool> {
    if fs::read(path).is_ok_and(|current| current == bytes) {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_name_the_binary_icon_and_window_class() {
        let text = entry(Path::new("/opt/null/null-desktop"), Path::new("/i/n.png"));
        assert!(text.contains("\nExec=/opt/null/null-desktop\n"), "{text}");
        assert!(text.contains("\nIcon=/i/n.png\n"));
        assert!(text.contains(&format!("\nStartupWMClass={APP_ID}\n")));
        assert!(!text.contains('@'), "every placeholder is filled");
    }

    #[test]
    fn exec_paths_with_spaces_or_specials_are_quoted_and_escaped() {
        assert_eq!(exec_argument("/usr/bin/null"), "/usr/bin/null");
        assert_eq!(exec_argument("/my apps/null"), "\"/my apps/null\"");
        assert_eq!(exec_argument("/a$b\"c"), "\"/a\\$b\\\"c\"");
    }

    #[test]
    fn installing_twice_writes_once_and_a_moved_binary_rewrites_the_entry() {
        let dir = tempfile::tempdir().unwrap();
        let (apps, icon) = (
            dir.path().join("applications"),
            dir.path().join("icons/n.png"),
        );
        let png = [1u8, 2, 3];
        assert!(install(&apps, &icon, Path::new("/a/null"), &png).unwrap());
        assert!(!install(&apps, &icon, Path::new("/a/null"), &png).unwrap());
        assert_eq!(fs::read(&icon).unwrap(), png);
        assert!(install(&apps, &icon, Path::new("/b/null"), &png).unwrap());
        let text = fs::read_to_string(apps.join(format!("{APP_ID}.desktop"))).unwrap();
        assert!(text.contains("Exec=/b/null"));
    }
}
