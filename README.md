# ratbox — a simple proxy client

[![AI Slop Inside](https://sladge.net/badge.svg)](https://sladge.net)

```text
               __  __
   _________ _/ /_/ /_  ____  _  __
  / ___/ __ `/ __/ __ \/ __ \| |/_/  (\_/)
 / /  / /_/ / /_/ /_/ / /_/ />  <   ( o.o )
/_/   \__,_/\__/_.___/\____/_/|_|    > ^ <
```

## Overview

A lightweight, simple proxy client for **Linux**, written in **Go** and powered
by **sing-box**.

## Features

- **Import** subscriptions and individual server links.
- **Manage subscription profiles:** select, rename, clear, and update them.
- **Check server availability** with color-coded results.
- **Select the fastest server.**
- **Local HTTP/SOCKS proxy** and **TUN mode**.

## Goal

Built for performance and control directly from the terminal, without a complex
GUI. **sing-box is installed separately.**

## Getting started

Requirements: Linux, Go 1.27+, and a `sing-box` core binary in `PATH`.
TUN mode additionally needs `sudo`, `nft` (nftables), `resolvectl`
(systemd-resolved) and iproute2.

Build and install:

```sh
git clone https://github.com/v0dol4zik/ratbox
cd ratbox
make build
install -Dm755 bin/ratbox ~/.local/bin/ratbox
```

Put the core in `PATH` and allow it to create TUN devices:

```sh
install -Dm755 sing-box ~/.local/bin/sing-box
sudo setcap 'cap_net_admin,cap_net_raw=ep' ~/.local/bin/sing-box
```

(The TUI can also grant this itself on the first TUN start through a masked
sudo prompt — no password is ever stored.)

Run `ratbox` (`~/.local/bin` must be in `PATH`):

1. `2` → `a` — add a subscription url or a share link, Enter
2. `1` → `a` — test all nodes (`t` — the node under the cursor)
3. Enter — connect through that node; `s` — start/stop the core
4. `m` — TUN (system-wide) mode, `y` — auto (fastest node)

The footer always lists the keys of the current tab.

## References

Projects and documentation studied while writing ratbox. ratbox is an
independent MIT implementation and shares no code with the GPL projects
below; sing-box runs as a separate external program that ratbox configures
and supervises.

- **sing-box** (GPL-3.0) — the core itself: configuration schema, TUN inbound,
  DNS. https://sing-box.sagernet.org · https://github.com/SagerNet/sing-box
- **sing-tun** (MIT) — Linux TUN stacks, `auto_redirect` and nftables table
  semantics. https://github.com/sagernet/sing-tun
- **Throne** (GPL-3.0) — reference for the Linux TUN/DNS layout, subscription
  headers and auto-connect UX. https://github.com/throneproj/Throne
- **FlClash** (GPL-3.0) — reference for subscription conventions
  (User-Agent, `subscription-userinfo`, `content-disposition`).
  https://github.com/chen08209/FlClash
- Libraries: [Bubble Tea](https://github.com/charmbracelet/bubbletea) and
  [Lipgloss](https://github.com/charmbracelet/lipgloss) (MIT),
  [gopkg.in/yaml.v3](https://github.com/go-yaml/yaml) (Apache-2.0).

TUN research notes with sources: [docs/TUN_RESEARCH.md](docs/TUN_RESEARCH.md).

## License

[MIT License](LICENSE).
