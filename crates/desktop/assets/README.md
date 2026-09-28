# Desktop brand assets

Copied unchanged from
[NullNetProtocol/brand-assets](https://github.com/NullNetProtocol/brand-assets)
at commit `f6c5e25`:

- `icon.png`: 1024×1024 app icon on the dark background, embedded as the
  window and taskbar icon.
- `icon.svg`: the same icon as a vector, for packaging.

`sh.nullnet.Wallet.desktop` is the Linux desktop entry template. Wayland
compositors take a window's icon from the entry matching its app id, so on
Linux the app installs this entry and the icon for the current user at
startup (`src/desktop_entry.rs`), rewriting them only when they change.
