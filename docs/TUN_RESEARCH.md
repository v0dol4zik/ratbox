# Linux TUN: upstream implementations and remaining throughput issue

## Sources reviewed

- [sing-box TUN documentation](https://sing-box.sagernet.org/configuration/inbound/tun/):
  recommends `auto_route` with `auto_redirect` on Linux for routing and performance.
  `auto_redirect` uses nftables. Current documentation also covers 1.15 features;
  ratbox's installed core is **1.14.4**, so new-stack/multi-queue advice for 1.15
  must not be applied blindly.
- [Throne 1.2.4 config generator](https://github.com/throneproj/Throne/blob/1.2.4/src/configs/generate.cpp#L1024-L1034):
  generates `auto_route`, configurable stack/MTU/strict routing, and Linux
  `auto_redirect` when enabled. The user's saved settings were `system`, MTU
  1500, `auto_redirect=true`, `strict_route=false`.
- [sing-box 1.14.4 TUN implementation](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/tun/inbound.go):
  passes the fixed nftables table name `sing-box` to sing-tun.
- [sing-tun version used by 1.14.4](https://github.com/SagerNet/sing-tun/blob/040db71fcd33/redirect_linux.go):
  auto-redirect startup cleans its named table before installing rules.
  [Cleanup implementation](https://github.com/SagerNet/sing-tun/blob/040db71fcd33/redirect_nftables.go)
  deletes that table. Different route tables/marks alone do not isolate two
  clients using the same nftables table name.

These implementations were inspected, not copied into ratbox. Traffic handling
continues to be provided by the external sing-box binary.

## Reproducible checks

`go test -v ./internal/core/process -run '^TestTUNNamespace$' -count=1`

All routing/firewall changes in this test are inside disposable namespaces.

| Configuration | INPUT default DROP | Result |
| --- | --- | --- |
| mixed, no auto-redirect | yes | TCP times out; explicit ratbox0 drop counter grows |
| gvisor, no auto-redirect | yes | IPv4/IPv6 payloads and 2 MiB uploads/echoes pass |
| system + auto-redirect | yes | IPv4/IPv6 payloads and 2 MiB uploads/echoes pass |

The last configuration is a **test-only opt-in**, not a new production default.
Tests include ingress attribution, exact payload comparison, per-transfer API
upload/download growth, clean shutdown and successful restart.

Additional `wan_gvisor` and `wan_redirect_system` cases add netem delay of 25 ms
and a 20 Mbit/s rate limit in each uplink direction. Both took about 2.15 seconds
for a 2 MiB upload plus echo in the observed run. These are regression checks,
not general performance benchmarks: no Internet, real proxy encryption,
WebSocket/CDN, packet loss, or Telegram is present.

## Root cause of the coexistence failure (confirmed 2026-11-04)

While ThroneCore runs with `auto_redirect` enabled, it installs sing-tun
mark-mode policy rules on the host:

```
9000: from all fwmark 0x2024 goto 9002
9001: from all fwmark 0x2023 lookup 2022
```

and an nftables OUTPUT redirect that captures **all unmarked local TCP before
it can reach any other TUN device**. Consequences measured on the live host:

- ratbox mixed inbound through the same node: 1 MiB POST/GET `200 OK` (the node itself is fine);
- ratbox TUN: HTTPS requests die with `TLS unexpected eof`, while only IPv6
  tun connections appear in ratbox logs; the completed ingress probe is
  **not observable in ratbox** — its IPv4 connection was captured upstream;
- with Throne stopped, ratbox TUN previously passed messages and the ingress
  probe (`tun ingress ok` header).

Two sing-box clients using TUN on one host cannot share this mechanism: the
first client with an active auto_redirect wins, and sing-box 1.14 hardcodes
the shared nftables table name `sing-box` and the default marks. ratbox does
**not** enable auto_redirect in production (it would delete another client's
shared table). Instead ratbox detects the capture and warns:

```
another VPN client with sing-box auto_redirect is active and captures local
TCP before ratbox TUN; stop the other client, then restart ratbox tun
```

The practical rule: run one TUN VPN client at a time. When testing ratbox TUN,
fully stop Throne/ThroneCore first.

## What this does and does not establish

- The previous firewall/TCP failure has a reproducer and a working gvisor path.
- The recommended upstream auto-redirect mechanism also works with the tested
  firewall. It should be evaluated rather than inventing custom nft rules.
- The tests **do not reproduce the user's near-zero Telegram media upload**.
  They do not prove gvisor is causing it or that auto-redirect would fix it.
- On the host, generated 1 MiB upload data reached a public HTTP endpoint through
  Poland SS and Finland TLS mixed proxies. That does not measure Telegram/TUN.
- The header rate is current aggregate core traffic, not a capacity benchmark;
  a failed/stalled connection can have low traffic despite a fast relay.
- Do not enable auto-redirect on the live host while another core can own the
  shared `sing-box` table. A safe production design needs privileged ownership
  checking/coordination or an upstream configurable unique table name. Never
  delete foreign rules to make startup succeed.

## Next discriminating check

With the **same node**, compare Telegram using ratbox TUN versus Telegram's
built-in SOCKS5 client pointing to ratbox's mixed inbound `127.0.0.1:12334`
(with ratbox TUN off for the latter check). The app/core must remain running.
Disable the Telegram-specific proxy after the comparison. Record complete core
errors at the failed media transfer; `tun ingress ok` alone is not a media test.

This is a diagnostic comparison, not a proposed permanent SOCKS-only workaround.
