# ratbox roadmap

Working plan, kept in sync with reality. Everything done gets crossed out
here in the same commit.

## v0.6.0 "Honesty + navigation"

- [x] **F0 tabs with arrows, no more `:`
        (←/→ switch nodes/subs/logs/config from anywhere; the vim-style
        command mode is removed entirely: settings live on the tab)
- [x] **P1.9** drop xray everywhere (decision: sing-box only, xray is
        outdated); resolveBinary no longer falls back to xray
- [x] **P1.1** Manager.UpdateConfig — mixed_port/core_binary changes
        actually apply to a running core instead of lying
- [x] **P1.5** reset traffic counters on core stop/restart (negative rates)
- [x] **P1.6** renderLogs coloring was dead code (local copy); fix + paint
        FATAL/ERROR red
- [x] **P1.7** padRight byte-slice/panic on very narrow terminals
- [x] **P1.8** sudo password: zeroize the append() copy; document that the
        inputBuf string cannot be wiped in Go
- [x] **P1.2/P1.3/P1.4** move all model mutations from Cmd goroutines into
        Update (data races); refuse subscriptions that yield 0 nodes;
        surface restart errors; ensureSelection() whenever the active node
        disappears (update/remove/delete) — no silent dead-node default
        under tun; e2e runs under -race

## v0.6.1 "Tests without a running core"

- [x] pressing t/a with the core stopped spins up a throwaway no-tun
        sing-box on random free ports, probes, and kills it — testing no
        longer requires the main core (tempActive guard, core-test data
        dir, orphan cleanup by config path)

## v0.6.2 "Start reliability + subscription profiles"

- [x] second 's' while a start is in flight no longer kills the just
        started core (starting flag + 3s grace period with an explicit
        "core just started — press s again to stop" status)
- [x] single-instance flock (ratbox.lock): a second ratbox refuses to
        start instead of murdering the first one's core
- [x] pinned list scrolling (top-anchored, one line at a time) — no more
        one-line drift when browsing nodes
- [x] subscription-as-profile: Enter on a subscription pins the tunnel to
        its nodes (header shows the profile, enter again to unpin)

## v0.6.12 "Adopt the upstream Linux TUN layout and explicit DNS lifecycle"

- [x] use Throne 1.2.4 / sing-box's recommended Linux architecture in the TUI:
        system + auto_redirect, MTU 1500, strict_route=false. Independent MIT
        implementation; GPL Throne code inspected, not copied
- [x] read actual nft tables before the core starts; refuse existing inet
        sing-box without modifying it. Use dedicated marks/queue/fallback rule
        (shared table is still a core limitation; preflight is not an atomic
        lock against a foreign client launching concurrently)
- [x] discover physical-uplink DNS before TUN; configure direct bootstrap UDP
        separately from application DoH through the selector to avoid a DNS loop
- [x] apply resolved DNS/~./default-route only to ratbox0 after core and selector
        readiness, through bounded sudo -n; use existing masked sudo authorization
        flow when needed. No persistent helper, sudoers/polkit policy or password
        file; failed DNS setup stops the core, link removal clears link DNS
- [x] namespace tests: actual bootstrap UDP DNS, remote HTTPS DNS, verified TLS
        site request, IPv4/IPv6 bulk upload/echo, growing counters, restart and
        ownership protection. sudo/resolved are mocked inside the namespace
- [x] correct v0.6.11 overclaim: fwmark rules alone do not prove packet capture
        or the root cause of all failures. Details in TUN_RESEARCH.md
- [ ] actual host resolved/sudo integration, browser and Telegram media behavior
        still need validation; no live routing or foreign VPN was changed here

## v0.6.11 "Detect nftables OUTPUT capture by another client"

- [x] live-host repro: with ThroneCore (auto_redirect) running, mixed of the
        same node serves 1 MiB fine while TUN HTTPS fails with TLS unexpected
        eof; the completed ingress probe is absent from ratbox connections —
        IPv4 TCP is captured by the other client's nftables OUTPUT redirect and
        its fwmark 0x2023/0x2024 rules (observed active on the host)
- [x] root cause documented in TUN_RESEARCH.md; sing-box 1.14 hardcodes the
        shared sing-box nft table and default marks, so the first auto_redirect
        client wins and a second TUN client cannot receive local TCP
- [x] ratbox now detects the mark-mode rules and warns in status + log;
        read-only, never blocks or deletes foreign rules
- [x] existing through-TUN diagnostics extended: 1 MiB upload/download with
        per-phase timings, popular-site check and system resolver timings,
        with mixed-path equivalents for the same node

## Linux TUN upstream research (after v0.6.10)

- [x] inspect official sing-box guidance, versioned Throne 1.2.4 generator and
        sing-tun implementation; findings and links in [TUN_RESEARCH.md](TUN_RESEARCH.md)
- [x] test upstream system + auto_redirect with INPUT DROP, IPv4/IPv6 bulk
        uploads and cleanup/restart in private namespaces
- [x] compare gvisor vs system+redirect with a netem 20 Mbit/s, ~50 ms RTT
        uplink; both pass, observed ~2.15 s for 2 MiB POST+echo. This does not
        reproduce or explain the live Telegram upload failure
- [x] keep auto_redirect opt-in for tests only: sing-box 1.14's shared nft table
        cleanup could disrupt another running core. No live host rules changed
- [ ] same-node Telegram TUN vs built-in SOCKS comparison and complete errors
        during failed media transfer; do not claim an untested performance fix

## Post-v0.6.10: media-upload investigation

- [x] user confirmed Telegram messages work through TUN after the stack fix;
        photo uploads still stall. End-to-end Telegram media remains unresolved
- [x] extend namespace regression with 2 MiB POST + full byte-for-byte echo,
        both IPv4 and IPv6, with and without INPUT default DROP. Verify upload
        and download API totals grow by at least the payload size per transfer
- [x] no-TUN selected-node comparison using generated bytes (not user files):
        1 MiB to Cloudflare upload endpoint completed on Poland SS (~316 KB/s)
        and Finland TLS (~825 KB/s). This does not establish Telegram/TUN speed
- [ ] capture the photo failure in the running core and compare the same upload
        with Finland TLS. Do not infer a node fault or change MTU without evidence

## v0.6.10 "Fix TUN TCP with default-deny INPUT firewalls"

- [x] user-provided nft snapshot contains UFW IPv4/IPv6 INPUT default DROP,
        no ratbox0 allowance, and no third-party redirect rules in that snapshot.
        Earlier attribution to Throne was not established for this failing run
- [x] reproduced in private namespaces with an UFW-like INPUT policy: mixed
        stack TCP times out; ratbox0 INPUT drop counter increases. UDP ingress
        in the user's log is consistent with mixed TCP/UDP taking different paths
- [x] explicitly use gvisor for TUN instead of sing-box's implicit mixed stack;
        userspace TCP avoids Linux INPUT reinjection. No host firewall changes,
        sudo rules, broad accept rules or disabling UFW are required
- [x] same namespace topology/firewall succeeds with the new default: exact
        ingress probe, IPv4/IPv6 proxy payload, growing totals, cleanup/restart
- [x] config default/override regression; real core config validation and race tests
- [ ] verify the new default on the real host without competing interception;
        active node's REALITY verification error remains a separate failure

## v0.6.9 "Do not confuse probe dial timeout with TUN failure"

- [x] poll exact probe connection concurrently with dialing, not after a
        successful TCP handshake; node/stack delays no longer prevent observing
        ingress. A dial timeout with no observation is explicitly inconclusive
- [x] regression: ingress visible before dial completes; unrelated mixed
        connections and different source ports must not match
- [x] opt-in host diagnostic accepts explicit stack/node overrides without
        saving the store; gvisor did not cure the observed IPv4 bypass
- [x] host logs also showed reality verification failed for the currently
        selected VLESS node; this is separate from ingress timeout. A known
        Shadowsocks node answered through mixed; system requests bypassed it
- [ ] actual host TUN remains unresolved; test with competing interception
        disabled by the user and capture the failing running core's logs

## v0.6.8 "Detect traffic interception, not just routing-table ownership"

- [x] host comparison: same endpoint via ratbox mixed used the selected Poland
        exit; system/TUN request used a Finland exit and added no ratbox traffic
        while ThroneCore was running. Kernel route alone was a false positive
- [x] bounded asynchronous TUN ingress probe: hold a partial HTTP request open,
        match source port/destination and tun/tun-in in this core's connections
- [x] persistent header state: tun checking / tun ingress ok / tun unverified;
        failures warn but never block startup or stop another client
- [x] namespace regression proves probe success on an isolated TUN data path;
        host diagnostic detects missing ingress and compares mixed/TUN timings
- [x] context-aware Clash connection requests, deadline and stale-message tests
- [ ] validate throughput on the host without external packet interception;
        ingress success does not establish node health, speed, DNS or UDP support

## v0.6.7 "Remove false TUN blocking; prove the data path"

- [x] remove blanket refusal when any TUN exists: persistent/disconnected
        interfaces are not proof of a routing conflict; reserve only ratbox0
- [x] log the kernel route to 1.1.1.1 after startup and show a warning if
        another interface wins; do not call a route lookup a connectivity test
- [x] surface selector failures instead of silently reporting core started
- [x] recover only exact-config-path orphan cores with SIGINT first, allowing
        route cleanup; SIGKILL remains a fallback with process identity recheck
- [x] serialize Manager Start/Stop and make Stop safe to call after exit
- [x] isolated Linux user/network namespace regression with a fake HTTP proxy:
        IPv4 and IPv6 payloads must traverse TUN; Clash counters must increase;
        disconnected throne-tun must not block startup; clean stop removes
        interface/rules, destination fails without TUN, restart works
- [x] bounded test subprocess cleanup; no host routing changes in default tests
- [x] opt-in host diagnostic test checks this core's counters, not just HTTP
        success (another VPN can intercept packets after kernel route lookup)
- [ ] real host/browser validation without another client's packet interception

## v0.6.6 "TUN route conflicts, not imaginary counters"

**Correction (v0.6.7):** checking for any existing TUN was too broad and
blocked disconnected persistent interfaces. Only ratbox's own interface is
reserved now; other route ownership is diagnosed, not prohibited.

- [x] found concurrent Throne TUN and ratbox using table 2022 and the same
        addresses; `ip route get` selected throne-tun, invalidating earlier
        curl-based claims that ratbox TUN worked
- [x] dedicated ratbox0 interface, table 12334, rules from 12300, separate
        IPv4/IPv6 addresses and MTU 1500
- [x] preflight refuses TUN start while another active TUN exists; does not
        kill another client or delete its routes (mixed mode still works)
- [x] discard unproven sysfs-counter workaround: sing-box /connections totals
        are cumulative, confirmed by a local real-core download regression
- [x] reset counters on every session, ignore stale traffic ticks after
        restart, calculate rates using actual elapsed time
- [x] DNS hijack rule before private-IP bypass; document that native DNS
        configuration remains disabled and stub/LAN DNS may bypass the tunnel
- [ ] verify real TUN end-to-end with Throne and the old ratbox core stopped;
        not safe to run automatically on the current live network

## v0.6.5 "The tun that started and froze"

**Correction (v0.6.6):** the following diagnosis overstated what was proven.
Disabling native DNS removed the resolve1 interaction, but successful curl
requests did not prove ratbox carried them: another VPN was present. Shared
routing leftovers are not generally harmless. See v0.6.6 above.

- [x] root cause of "tun core runs but 0 traffic, mixed/clash api dead":
        sing-box 1.14 tun defaults to dns_mode=hijack and calls
        systemd-resolved over D-Bus; as a user process it blocks on
        polkit authorization (pkttyagent prompt lands on our tty, nobody
        answers) — the core starts, then freezes answering nothing.
        Fixed by generating dns_mode "disabled": no resolve1 calls,
        no prompts, nothing to hang on. Verified live: clash api
        answers, outward curl exits with the node IP, traffic counter
        turns. Remaining [detached] ip rules are old crash leftovers and
        are harmless (auto_route re-claims the slots)
- [x] the polkit-rule branch of the sudo grant dropped (no longer needed);
        x in settings stays as a re-grant of the core caps
- [x] latency column colorized: <=150ms green, <=300ms yellow, worse red

## v0.6.4 "The polkit interrogation of systemd-resolved"

- [x] live -race build caught the second one: isRunning() read
        cmd.ProcessState under our mutex while Wait() writes the field
        without taking it — the mutex protects nothing there. isRunning
        now answers from m.started only (single source of truth, updated
        exclusively under the lock)
- [x] why a polkit prompt appears on every TUN start: sing-box 1.14 tun
        dns_mode=hijack talks to systemd-resolved over D-Bus; our core is
        a regular user, resolve1 asks polkit, no desktop agent → the text
        prompt lands right on our tty. The sudo grant flow now installs
        an idempotent polkit rule (49-ratbox-tun-dns.rules) for the
        current user; x in the settings tab re-runs the grant

## v0.6.3 "Profile management + the first caught race"

- [x] profile management keys in the subs tab: c clears the profile's
        nodes (subscription stays, u re-imports), r renames it
- [x] the -race build caught a real one: two concurrent cmd.Wait() calls
        (Start's waiter goroutine vs Stop's timeout waiter) race on
        ProcessState — fixed with single-waiter semantics (waitDone
        channel), Stop waits the channel instead of calling Wait
- [x] clearing the last nodes no longer tries to restart the core with an
        empty node set; the core stops cleanly with an explanatory status
- [x] latency map pruned when nodes/subscriptions are removed (P2.7)

## v0.7.0 "Order"

- [x] P2.1 single-instance lock (flock) — done in v0.6.2
- [ ] P2.2 duplicate subscription urls -> offer update instead
- [ ] P2.3 rewrite footer hints (four tabs, arrows, no lying)
- [ ] P2.4 User-Agent from main.version instead of hardcoded "ratbox/0.1"
- [ ] P2.5 unify log height calc (G misses one line)
- [x] P2.6 (obsolete with the `:` removal) — case ":" without return
- [x] P2.7 clean latency map of removed nodes — done in v0.6.3
- [ ] P2.8 dead code: NodesOfSub, Manager.String, fake retry loop in startCoreCmd
- [ ] unit tests: normKey, padRight, killOrphanCores, ReplaceSubNodes
- [ ] move the e2e harness from /tmp into e2e/ in the repo

## v0.8.0 "Convenience"

- [ ] F1 rename subscription with the `r` hotkey in the subs tab
- [ ] F2 g/G top/end navigation in the nodes list (logs already have it)
- [ ] F3 auto-update subscriptions (interval + on start, via the service
        channel, failures are silent)

## v1.0.0

- [ ] final polish, full hotkey docs in README, harness regression suite

## Known limitations (documented honestly, not fixed)

- one ratbox per machine until the instance lock lands
- Go strings cannot be reliably zeroized (the sudo inputBuf);
  the byte buffers are wiped, the string copy is a documented tradeoff
- terminals do not report Caps Lock; normKey handles it except g/G and T
