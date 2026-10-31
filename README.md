<p align="center">
  <img src="logo.png" alt="Osza Browser" width="180" />
</p>

<h1 align="center">Osza Browser</h1>

<p align="center">
  <strong>A fast, secure and privacy-focused web browser built with Qt.</strong><br/>
  Maintained by the <a href="https://github.com/osza-tools">Osza Tools</a> team.
</p>

---

## About

Osza Browser is a lightweight yet full-featured web browser powered by the
**QtWebEngine** rendering engine. It combines speed and privacy with a clean,
familiar interface, and it runs on **Linux, Windows and macOS**.

Osza Browser is a fork of [Falkon](https://www.falkon.org), deeply rebranded
and evolved as an independent project. We are grateful to the original Falkon
and KDE contributors for their work.

## Features

- **Speed** — a lightweight interface on top of the Chromium-based
  QtWebEngine rendering engine.
- **Privacy first** — built-in private browsing, per-site settings and
  full control over cookies, JavaScript and other permissions.
- **Ad blocking** — integrated AdBlock support with filter subscriptions.
- **Everything in its place** — bookmarks, history, downloads and RSS
  feeds, all reachable from collapsible sidebars.
- **Speed Dial** — your favorite sites one click away on the start page.
- **Sessions** — save and restore complete browsing sessions.
- **Themes** — flexible theming with bundled themes for every platform.
- **Extendable** — native C++/Qt plugins plus Python (PySide6) plugins.

## Downloads

The current release is [**Osza Browser 0.1.1**](https://github.com/osza-tools/osza-browser/releases/tag/v0.1.1),
the first under the Osza name:

| Platform | File | Notes |
|---|---|---|
| Linux x86_64 | `Osza-Browser-0.1.1-linux-x86_64.tar.gz` | Extract and run `usr/bin/osza` (plain `/usr` layout). |
| Linux (Snap) | `osza-browser_0.1.1_amd64.snap` | `sudo snap install ./osza-browser_0.1.1_amd64.snap --dangerous` |
| macOS (Apple Silicon) | `Osza-Browser-0.1.1-macos-arm64.dmg` | Drag **Osza** to Applications. Not notarized — right-click → Open on first launch. |
| Windows x64 | `Osza-Browser-0.1.1-windows-x64.zip` | Extract and run `osza.exe` (MSVC 2022, Qt 6.8 LTS). |

For older releases and checksums see the
[releases page](https://github.com/osza-tools/osza-browser/releases),
or [build from source](#building).

## Building

### Requirements

- Qt >= 6.4 (with QtWebEngine, WebChannel, Sql, Network, Widgets, QuickWidgets, PrintSupport, DBus)
- KF6 Archive (required), ECM (Extra CMake Modules)
- OpenSSL
- Optional: KF6 Wallet / KIO / Crash / CoreAddons / Purpose (enables the *System Integration* plugin),
  PySide6 + Shiboken6 (enables Python plugins)

### Linux / macOS

```sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
make install
```

### Install to a custom prefix

When installing Osza Browser to a custom prefix, you may need to adjust the
`XDG_DATA_DIRS` environment variable:

```sh
# Build
cmake -DCMAKE_INSTALL_PREFIX=$HOME/osza

# Run
export XDG_DATA_DIRS="$HOME/osza/share:$XDG_DATA_DIRS"
$HOME/osza/bin/osza
```

## Contributing

Want to contribute? Great!

- Open an [issue](https://github.com/osza-tools/osza-browser/issues) for bugs
  and feature requests.
- Send pull requests against the `main` branch — keep changes focused and
  describe the *why* in the commit message.

## License

Osza Browser is free software licensed under the
**GNU General Public License version 3 or (at your option) any later version**
(see [COPYING](COPYING)).

It is based on Falkon — Copyright (C) David Rosca, Juraj Oravec and Falkon/KDE
contributors.
