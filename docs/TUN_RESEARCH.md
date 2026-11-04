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

Since v0.6.12 the TUI uses `system + auto_redirect`, MTU 1500 and
`strict_route=false`, following the working Linux layout in Throne. Before
launch, ratbox reads nftables through bounded `sudo -n nft list tables` and
refuses an existing `inet sing-box` table rather than letting the core delete
it. This is a preflight, not an atomic lock against another application starting
at exactly the same time: do not launch two auto-redirect clients concurrently.
No firewall table is flushed by ratbox.

Tests include ingress attribution, exact payload comparison, per-transfer API
upload/download growth, clean shutdown and successful restart. They also verify
that an existing shared table survives a refused start.

Additional `wan_gvisor` and `wan_redirect_system` cases add netem delay of 25 ms
and a 20 Mbit/s rate limit in each uplink direction. Both took about 2.15 seconds
for a 2 MiB upload plus echo in the observed run. These are regression checks,
not general performance benchmarks: no Internet, real proxy encryption,
WebSocket/CDN, packet loss, or Telegram is present.

## Correction: earlier coexistence diagnosis was overstated

While ThroneCore runs with `auto_redirect` enabled, it installs sing-tun
mark-mode policy rules on the host:

```
9000: from all fwmark 0x2024 goto 9002
9001: from all fwmark 0x2023 lookup 2022
```

These rules are consistent with auto-redirect but do **not** establish which
nftables rules are active or that they intercepted a particular connection.
The earlier claim of a proven root cause based on marks alone was incorrect.
Observations on the live host:

- ratbox mixed inbound through the same node: 1 MiB POST/GET `200 OK`;
- ratbox TUN: HTTPS requests die with `TLS unexpected eof`, while only IPv6
  tun connections appear in ratbox logs; the completed ingress probe is
  **not observable in ratbox** — the destination/path was not attributed;
- with Throne stopped, ratbox TUN previously passed messages and the ingress
  probe (`tun ingress ok` header).

The hardcoded shared nftables table is an independently verified ownership
hazard, not proof that it explains all prior failures. v0.6.12 therefore checks
actual table existence before enabling auto-redirect and changes the old mark
warning to an explicitly uncertain hint. No conclusion about successful host
connectivity follows from either the marks or a kernel route lookup.

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

## DNS integration in v0.6.12

Throne separates underlying/bootstrap DNS from application DNS. Its patched
libbox exposes an `underlying` transport that stock sing-box 1.14.4 does not.
ratbox instead discovers the main-table uplink's DNS before starting the core
and configures a direct UDP bootstrap resolver. A loopback resolved stub is
never used as bootstrap after pointing the system DNS at TUN.

Application DNS to `172.28.123.2:53` is hijacked by the core and resolved via
DoH through the selected proxy. After the core API and selector are ready,
ratbox uses `sudo -n resolvectl` to configure DNS, `~.` and default-route on
**ratbox0 only**. Native core DNS configuration remains disabled to avoid
uncontrolled polkit prompts. No global resolv.conf or foreign interface is
modified. Link removal on stop/crash removes link-scoped resolved settings.

The existing masked sudo/setcap flow establishes sudo authorization; it may be
requested again when sudo's normal timestamp expires. No password, helper,
sudoers entry or polkit rule is installed. Missing tools/authorization/DNS cause
an explicit startup failure; a failed post-start DNS setup stops the core.

The namespace test uses actual physical-uplink UDP DNS and proxy-carried HTTPS
DNS with a private trusted test certificate. `sudo` and `resolvectl` are mocked
inside the namespace (no resolved daemon runs there); real nft ownership,
routing, proxy DNS, bulk transfers and cleanup are exercised. **Actual host
resolved integration, browser/media behavior and throughput still need live
verification.** Throne GPL source was inspected as a reference, not copied into
this MIT codebase.
