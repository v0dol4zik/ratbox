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

## v0.7.0 "Order"

- [ ] P2.1 single-instance lock (flock); second ratbox says so, --force
- [ ] P2.2 duplicate subscription urls -> offer update instead
- [ ] P2.3 rewrite footer hints (four tabs, arrows, no lying)
- [ ] P2.4 User-Agent from main.version instead of hardcoded "ratbox/0.1"
- [ ] P2.5 unify log height calc (G misses one line)
- [x] P2.6 (obsolete with the `:` removal) — case ":" without return
- [ ] P2.7 clean latency map of removed nodes
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
