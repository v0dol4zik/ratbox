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
- TUN mode with auto_route (press `m` to toggle)

## Install

    go install github.com/v0dol4zik/ratbox/cmd/ratbox@latest

You also need a sing-box binary in your PATH (or set `core_binary` in
`~/.local/share/ratbox/store.json`).

## Usage

Run `ratbox`, then:

- `2` → subscriptions tab, `a` to add a subscription URL
- `1` → nodes tab, `Enter` to select the active node
- `t` — test the node under the cursor, `a` — test all nodes (`T` stays as an alias)
- `s` — start/stop the core, `3` — logs tab
- `q` — quit

Local proxy endpoint: `127.0.0.1:12334` (mixed http+socks; change `mixed_port` in
`~/.local/share/ratbox/store.json` if something else occupies the port).

## TUN mode

TUN routes the whole system traffic through the core. On Linux the sing-box
binary needs CAP_NET_ADMIN, once:

    sudo setcap 'cap_net_admin,cap_net_raw=ep' $(readlink -f $(which sing-box))

Then in the TUI press `m` to enable/disable and start the core. Stop other
TUN/VPN clients (including Throne) first: ratbox refuses to start TUN when
another active TUN interface exists. Otherwise another client's more-specific
routes may capture traffic even while ratbox reports that its core is running.
Mixed-proxy mode can still be used alongside another VPN.

ratbox uses its own interface `ratbox0`, routing table `12334`, rule range
starting at `12300`, and addresses `172.28.123.1/30`, `fdfe:7261:7462::1/126`.
It does not delete other clients' interfaces or routing rules.

With sing-box 1.14+, `dns_mode: disabled` avoids native systemd-resolved
configuration and its polkit prompts. DNS packets reaching the TUN are
hijacked and resolved through the proxy, but the system stub/LAN resolver
is **not** automatically redirected; this is not a DNS-leak-free setup.

Traffic totals come from the core's cumulative `/connections` counters,
including closed connections. Rates use actual elapsed time; restarting the
core resets the session counters. A green latency test verifies the node,
not the host's TUN routing.

After a hard core crash (SIGKILL), stale routes can remain. Do not blindly
flush shared tables or delete other VPNs' rules. A reboot clears transient
interfaces/routes if you cannot identify their owner safely.

## Notes on performance

ratbox never sits on the data path: all traffic is handled by the core
process. That keeps throughput identical to a bare sing-box setup.

## License

MIT (see LICENSE). The sing-box core ratbox supervises is GPLv3 and is
not bundled with ratbox.
