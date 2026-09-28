# Desktop brand assets

Copied unchanged from
[NullNetProtocol/brand-assets](https://github.com/NullNetProtocol/brand-assets)
at commit `f6c5e25`:

- `icon.png`: 1024×1024 app icon on the dark background, embedded as the
  window and taskbar icon.
- `icon.svg`: the same icon as a vector, for packaging.

`sh.nullnet.Wallet.desktop` is the Linux desktop entry template. Wayland
compositors take a window's icon from the entry matching its app id, so
the window icon alone shows a generic one there. `make desktop-entry`
fills in this checkout's paths and installs it for the current user.

The sidebar logo is not an image. `src/ui/brand.rs` draws the mark and
wordmark from the stroke geometry in `banner-white.svg`, so it stays sharp
at any scale. Update both together if the brand changes.
