# Desktop wallet

`null-desktop` is an egui/eframe desktop binary. The GUI, full node, wallet
service, and HTTP JSON-RPC server run in one OS process. Tokio and proving
workers use threads. The application does not launch `nulld`,
`null-wallet-rpc`, a browser, or a sidecar.

## Run

```
cargo run --release -p null-desktop -- --network test --connect 127.0.0.1:19000
# equivalent:
make desktop ARGS="--network test --connect 127.0.0.1:19000"
```

Start a testnet node separately as described in the README to have a peer
to connect to; desktop itself embeds its own node. On the main network it
also dials the release's seed nodes (`seed1`–`seed5.nullnet.sh`); they are
never written to `null.conf`. The test network has no public seeds. A
desktop instance without peers can create and open wallets, but cannot
learn new blocks or broadcast to other nodes.

The native window needs a graphical desktop and an OpenGL-capable driver.
Linux builds use the X11/Wayland development libraries required by eframe.
The backend integration tests run without a display.

Defaults:

- Network: `test` for a new installation; saved in `null.conf`.
- Application data directory: Linux `$XDG_DATA_HOME/null`, falling back to
  `~/.local/share/null`; macOS `~/Library/Application Support/Null`;
  Windows `%LOCALAPPDATA%\Null`, falling back to `%APPDATA%\Null`.
- Configuration: `null.conf` inside the application data directory,
  generated automatically on first launch. It uses TOML syntax.
- Chain: `<network>/chain/chain.redb` inside the application data directory. A default
  `nulld run` uses the same chain, so stop the desktop app before running
  it (and the other way around).
- Wallet: `<network>/wallet.redb`, detected automatically.
- Combined RPC: `127.0.0.1:18448`; override with `--rpc 127.0.0.1:0` for an
  available port, shown on the Node screen.
- RPC token: `desktop-rpc.token` inside the network data directory,
  regenerated on startup, owner-only permissions on Unix.
- P2P: outbound connections only unless `--listen` is supplied.
- SOCKS5: `--proxy <host:port>`; this connects to an existing proxy.

Launch without arguments for ordinary use. On first launch, choose **Create
a new wallet** to generate a 24-word recovery phrase, or **Import recovery
phrase** to restore a wallet. Both flows ask for a passphrase to encrypt the
local wallet. No wallet-file selection is needed. Creation shows the phrase
once; save it before dismissing the backup screen. Later launches detect the
wallet and show only the unlock screen. A passphrase is still required to
decrypt it; neither the seed nor the passphrase is stored in `null.conf`.

Existing wallets and configuration files are never overwritten by setup.
New application directories are owner-only on Unix, as is the generated
configuration. The Node screen shows the storage and configuration paths.
An unlocked wallet is held only by the backend service. Locking waits for
the current scan/payment pass, then releases its database and keys.

Edit `null.conf` and restart to change saved settings, for example:

```toml
network = "test"
rpc = "127.0.0.1:18448"
connect = ["127.0.0.1:19000"]
lock_after_minutes = 15
mine = false
mining_threads = 4
# listen = "127.0.0.1:18445"
# proxy = "127.0.0.1:9050"
```

CLI flags override saved settings for that launch; on the first launch,
the initial effective settings are written to the new config. `--datadir`
selects another application directory, and `--conf` selects another config.
Use different data directories and RPC ports for multiple instances.
`--wallet` remains an advanced override; relative CLI paths resolve from
the working directory, while a relative `wallet` setting in `null.conf`
resolves inside the selected network directory.

When upgrading the scaffold, a first default launch checks for
`.null-desktop/<network>/wallet.redb` in the current directory. If found,
it saves that network's absolute wallet path under `[wallets]` in the new
config and reuses the file
in place. Alternatively, `--datadir .null-desktop` retains the previous
wallet and chain directories. New installations use the OS data location.

The send screen accepts decimal NULL amounts with up to eight places and
checks the address network and memo. Review then asks the wallet's
`quotepayment` for the exact fee and total, selecting notes as the payment
worker would. The fee depends on the transaction's action class, which can
grow when many small notes are spent. Confirming queues the payment. The
normal wallet payment queue builds, proves, and submits it and records
progress in Activity, where a queued payment can be cancelled before it is
proved. A payment's notes are selected when it is built, so a queued
payment can end up differing from its quote if notes arrive or other
payments reserve some first.

Receive shows the newest address, or the one picked with **Show QR**, as a
QR code with the address alongside. Activity shows text memos on received
notes.

After creating a wallet, the recovery phrase is shown once. The user must
then type three randomly chosen words back from their written copy before
the phrase is dismissed. The words are compared in constant time, and
answer buffers are zeroized.

An unlocked wallet locks itself after `lock_after_minutes` without keyboard
or pointer input (15 by default; 0 disables it). The lock is skipped while
a backend request is running or the recovery phrase is on screen.

## Mining

The Node page has a Mining card with an on/off switch and a thread slider
(1 to the machine's CPU count; the default is half). Mining needs an
unlocked wallet and always pays the wallet's main address, the one at
index 0. While the wallet is locked the switch is disabled. Locking stops
the miner, and a saved `mine = true` starts it again on the next unlock.
Moving the slider while mining restarts the miner with the new count.

The switch saves `mine` and `mining_threads` to `null.conf` in place;
other settings and comments are kept. The first start builds the coinbase
proving key, which takes a few seconds. The card shows the payout address
and how many blocks this session found and how many are in the main chain.

## RPC

The endpoint serves the existing node and wallet methods with the same
bearer-token transport documented in `rpc.md`:

```
curl -H "Authorization: Bearer $(cat "${XDG_DATA_HOME:-$HOME/.local/share}/null/test/desktop-rpc.token")" \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:18448/
```

Wallet calls return `REJECTED` while the wallet is locked. Create/import/unlock
and lock are local GUI actions; RPC cannot unlock it. When unlocked, authorized
RPC clients can submit payments using the same wallet as the GUI.

Wallet method names win collisions, including `gettransaction`. Prefix
node methods with `node.` when necessary, e.g. `node.gettransaction`.
`help` lists both method sets. `stop` shuts down the entire backend; the
window reports that it stopped and can be closed. `node.stop` is refused
so callers cannot stop the node while leaving wallet synchronization running.
The desktop endpoint accepts loopback bind addresses only.

## Structure

- `crates/desktop/src/main.rs`: configuration, native event loop, Tokio
  runtime, and final shutdown, including graphics startup failures.
- `crates/desktop/src/config.rs`: persistent settings and wallet discovery.
  OS data paths and directory creation come from `null_node::paths`,
  shared with `nulld` and `null-wallet-rpc`.
- `crates/desktop/src/backend.rs`: bounded command queue shared by GUI and
  RPC, wallet ownership, secret-bearing commands, read-only snapshots.
- `crates/desktop/src/ui/`: the GUI shell and screens; asynchronous
  commands keep node/scan/proof work off the render thread. See
  [UI conventions](#ui-conventions).
- `node::walletd::start(ServiceConfig)`: wallet service without an HTTP
  listener. Standalone `null-wallet-rpc` uses the same service.
- `node::rpc::Source`: embedded event channel or authenticated remote
  endpoint. Both reuse existing command semantics and wallet sync logic.
  The embedded adapter still uses the line command codec internally;
  replacing it with a fully typed wallet/node API is a future optimization.

Shutdown stops the desktop RPC listener, finishes the wallet's active pass,
then stops the node and its owned listener tasks. Finally the desktop drops
its dedicated runtime, cancelling remaining networking tasks. Closing during
proving can take time because aborting an async future cannot cancel an
already-running blocking prover or release its wallet references.

## UI conventions

The GUI is split into three layers. Add new screens by following them rather
than styling egui widgets directly.

- `ui/theme.rs` holds every design token: colors, spacing, radii, sizes,
  and the `Tone` enum (neutral, info, success, warning, danger). Tests check
  that every text color meets WCAG AA contrast on every background, and
  that each tone is readable on its own tint. No other file names a color
  or a literal size.
- The palette follows the NULL website's dark theme: near-black neutrals
  and one terminal-green accent (`#51E57E`), with the brand's `#030303`
  for chrome. `ui/brand.rs` draws the ∅ mark and NULL wordmark from the
  `brand-assets` stroke geometry, always white. `ui/icons.rs` holds line
  icons on a 16×16 grid in the same stroke style. Add icons there rather
  than using an icon font or images.
- `ui/widgets.rs` holds the building blocks made from those tokens: `page`,
  `card`, `highlighted_card`, `section`, `card_title`, `caption`, `stat`,
  `display_amount`, `field_label`, `primary_button`, `secondary_button`,
  `badge`, `notice`, `empty_state`, `copyable`, `hash`, `key_value`,
  `secret_input`, `qr_code`, and `nav_item`.
- `ui/screens/<name>.rs` holds one page each. A screen draws from the
  read-only `Snapshot` and returns an `Effect` (`Submit` a backend action
  or `Notify` the status bar) instead of calling the backend. Screens with
  inputs keep them in their own `Form` struct; secrets use `Zeroizing`.
  Keep validation and effect-building in plain methods so unit tests can
  run without a window.
- A screen that needs a result sends `Effect::Call` with a `Reply`:
  `Notice` shows a fixed success message, and `Quote` hands the result or
  error back to the send form. Add a `Reply` variant when a new screen
  consumes call results.
- `ui/idle.rs` tracks input for automatic locking.
- `ui/format.rs` reads backend JSON and formats amounts, heights, and hashes.
  Missing values display as `—`.
- `ui/mod.rs` is the shell: sidebar, status bar, routing, and performing
  effects. Its headless test renders every page with empty, locked, and
  populated snapshots.

The window icon is the official `assets/icon.png`. On Wayland the
compositor shows the icon from the desktop entry matching the app id
`sh.nullnet.Wallet`; `make desktop-entry` installs one for this checkout.

To add a screen: create `ui/screens/<name>.rs` with a `show` function (and
`Form` if it has inputs), wrap it in `widgets::page`, group content in
cards, use one `primary_button` per view, add a `Page` variant with its
title and icon to `Page::ALL`, and route it in `route`.

## Remaining desktop work

This is a functional development scaffold, not a finished wallet release.
Remaining work includes full transaction detail views, file pickers,
pagination, push-driven snapshots,
packaging/signing, accessibility review, and native smoke tests on all three
desktop platforms. Status snapshots currently refresh once a second, and
the UI checks for updates every 200 ms.

The desktop intentionally puts P2P handling and unlocked spending keys in
the same process. The standalone daemons remain available for deployments
that need process isolation. GUI input buffers use zeroizing storage and
clear widget undo histories; a review of toolkit-internal copies and rendered
secret text is still needed before treating the desktop as hardened.
