//! Embeds the app icon in the Windows executable, so Explorer, the taskbar
//! and shortcuts show it instead of the generic program icon. The window
//! icon at runtime comes from `assets/icon.png` and is set separately.

/// The multi-size icon, generated from `assets/icon.png`.
const WINDOWS_ICON: &str = "assets/icon.ico";

fn main() {
    println!("cargo:rerun-if-changed={WINDOWS_ICON}");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let mut resource = winresource::WindowsResource::new();
    resource.set_icon(WINDOWS_ICON);
    // A missing resource compiler (a cross build without windres) costs
    // only the icon; it must not fail the build.
    if let Err(error) = resource.compile() {
        println!("cargo:warning=executable icon not embedded: {error}");
    }
}
