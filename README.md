# ratbox — a fast CLI/TUI proxy frontend for sing-box cores

ratbox is a terminal-first proxy client. It supervises an external
sing-box core, generates its config, imports subscriptions, tests node
latency and lets you switch nodes instantly via the clash api.

## Features

- subscriptions: base64 and raw share-link lists
- protocols: vless (incl. reality), vmess, shadowsocks, trojan, hysteria2, tuic
- instant node switching without core restart (clash api selector)
- URLTest / delay measurement per node and for the whole list
- traffic counters (up/down, per-second rate)
- live core logs and generated-config inspection
- TUN mode with auto_route + dns hijack (press `m` to toggle)

## Install

    go install github.com/v0dol4zik/ratbox/cmd/ratbox@latest

You also need a sing-box binary in your PATH (or set `core_binary` in
`~/.local/share/ratbox/store.json`).

## Usage

Run `ratbox`, then:

- `2` → subscriptions tab, `a` to add a subscription URL
- `1` → nodes tab, `Enter` to select the active node
- `t` — test selected node latency, `T` — test all
- `s` — start/stop the core, `3` — logs tab
- `q` — quit

Local proxy endpoint: `127.0.0.1:12334` (mixed http+socks; change `mixed_port` in
`~/.local/share/ratbox/store.json` if something else occupies the port).

## TUN mode

TUN routes the whole system traffic through the core. On Linux the sing-box
binary needs CAP_NET_ADMIN, once:

    sudo setcap 'cap_net_admin,cap_net_raw=ep' $(readlink -f $(which sing-box))

Then in the TUI press `m` to enable/disable and start the core. All traffic
(including other apps) will go through the active node; DNS is hijacked and
resolved via 1.1.1.1 through the tunnel to avoid poisoning.

If the network breaks after a hard core crash (SIGKILL), starting and
gracefully stopping the core again cleans up the routes; reboot also works.

## Notes on performance

ratbox never sits on the data path: all traffic is handled by the core
process. That keeps throughput identical to a bare sing-box setup.

## License

MIT (see LICENSE). The sing-box core ratbox supervises is GPLv3 and is
not bundled with ratbox.
