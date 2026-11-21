package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/store"
)

func (a *App) View() string {
	if a.width == 0 {
		return "loading…"
	}
	var b strings.Builder

	b.WriteString(a.renderHeader())
	b.WriteByte('\n')
	b.WriteString(a.renderTabs())
	b.WriteByte('\n')
	// chrome = header + tabs + separator + status line + key hints
	bodyHeight := a.height - 5
	switch a.view {
	case ViewNodes:
		b.WriteString(a.renderNodes(bodyHeight))
	case ViewSubs:
		b.WriteString(a.renderSubs(bodyHeight))
	case ViewLogs:
		b.WriteString(a.renderLogs(bodyHeight))
	case ViewSettings:
		b.WriteString(a.renderSettings(bodyHeight))
	}
	b.WriteByte('\n')
	b.WriteString(a.renderFooter())
	return b.String()
}

func (a *App) renderHeader() string {
	coreState := "stopped"
	stateStyle := errStyle
	if a.running {
		coreState = "running " + humanUptime(a.startedAt)
		stateStyle = okStyle
	}
	active := "—"
	if a.store.AutoMode {
		active = "auto"
		if a.autoNow != "" {
			active = "auto → " + a.autoNow
		}
	} else if n := a.store.Node(a.store.ActiveNodeID); n != nil {
		active = n.Tag
	}
	parts := []string{
		titleStyle.Render("ratbox"),
		stateStyle.Render(coreState),
		dimStyle.Render(fmt.Sprintf("proxy 127.0.0.1:%d", a.store.MixedPort)),
	}
	if a.store.TunMode {
		tun := warnStyle.Render("tun")
		if a.running {
			switch a.tunIngress {
			case "checking":
				tun = warnStyle.Render("tun checking")
			case "verified":
				tun = okStyle.Render("tun ingress ok")
			case "warning":
				tun = errStyle.Render("tun unverified")
			}
		}
		parts = append(parts, tun)
	}
	if a.store.AutoMode {
		parts = append(parts, okStyle.Render("auto"))
	}
	if a.store.RoutingProfile == process.ProfileRUBypass {
		parts = append(parts, warnStyle.Render("RU→direct"))
	}
	if a.store.ActiveSubID != "" {
		parts = append(parts, "profile: "+a.store.SubName(a.store.ActiveSubID))
	}
	parts = append(parts, "active: "+active)
	if a.running {
		parts = append(parts,
			dimStyle.Render(fmt.Sprintf("↑ %s/s ↓ %s/s", humanBytes(a.rateUp), humanBytes(a.rateDown))),
			dimStyle.Render(fmt.Sprintf("tot %s", humanBytes(a.traffic.UploadTotal+a.traffic.DownloadTotal))),
		)
	}
	return headerStyle.Render(strings.Join(parts, " │ "))
}

func (a *App) renderTabs() string {
	names := []string{"nodes", "subs", "logs", "config"}
	var parts []string
	for i, name := range names {
		style := dimStyle
		label := " " + name + " "
		if a.view == i {
			style = titleStyle.Copy().Bold(true)
		}
		parts = append(parts, style.Render(label))
	}
	return strings.Join(parts, "")
}

// renderSettings draws the vim-style settings menu (opening: :config / :settings).
func (a *App) renderSettings(height int) string {
	voff := visibleOffset(a.setIdx, settingsRows, height)
	var lines []string
	lines = append(lines, " "+dimStyle.Render("SET   VALUE")+padRight("", 44)+
		dimStyle.Render("description"))
	for i := voff; i < settingsRows; i++ {
		marker := " "
		style := normalStyle
		if i == a.setIdx {
			marker = ">"
			style = selectedStyle
		}
		var name, val, hint string
		switch i {
		case setTun:
			name, hint = "tun_mode", "route all system traffic through the core"
			val = onOff(a.store.TunMode)
		case setAuto:
			name, hint = "auto_mode", "selector always on the fastest node"
			val = onOff(a.store.AutoMode)
		case setProfile:
			name, hint = "routing_profile", "global / RU→direct"
			if a.store.RoutingProfile == process.ProfileRUBypass {
				val = "RU→direct"
			} else {
				val = "global"
			}
		case setAutostart:
			name, hint = "autostart", "start the core with ratbox"
			val = onOff(a.store.AutoStart)
		case setMixedPort:
			name, hint = "mixed_port", "local HTTP/SOCKS proxy (enter to change)"
			val = fmt.Sprintf("%d", a.store.MixedPort)
		case setCoreBinary:
			name, hint = "core_binary", "binary path, enter to change (empty = PATH)"
			if a.store.CoreBinary == "" {
				val = "(auto)"
			} else {
				val = a.store.CoreBinary
			}
		}
		lines = append(lines, " "+style.Render(marker+" "+padRight(name, 16)+padRight(val, 38))+
			dimStyle.Render(TruncateVisible(hint, a.width-60)))
	}
	return strings.Join(lines, "\n")
}

func onOff(b bool) string {
	if b {
		return okStyle.Render("on")
	}
	return dimStyle.Render("off")
}

func (a *App) renderNodes(height int) string {
	if len(a.store.Nodes) == 0 {
		return "\n " + dimStyle.Render("no nodes yet — press 2, then `a` to add a subscription") +
			"\n " + dimStyle.Render("or press `n` here to paste a share link")
	}
	// column widths
	avail := a.width - 2
	nameW := avail * 38 / 100
	protoW := 11
	addrW := avail * 30 / 100
	latW := 10

	var lines []string
	lines = append(lines, " "+
		dimStyle.Render(padRight("NAME", nameW)+" "+padRight("PROTOCOL", protoW)+" "+
			padRight("ENDPOINT", addrW)+" "+padRight("LATENCY", latW)))

	visible := height - 1
	offset := visibleOffset(a.nodeIdx, len(a.store.Nodes), visible)
	bar := lipgloss.Color(activeRowBg)
	for i := offset; i < len(a.store.Nodes) && len(lines)-1 < visible; i++ {
		n := a.store.Nodes[i]
		name := cleanTag(n.Tag)
		if len(a.store.Subs) > 1 && n.SubID != "" {
			name = a.store.SubName(n.SubID) + "/" + n.Tag
		}
		lat, latSt := "    —", dimStyle
		if ms, ok := a.latency[n.Tag]; ok {
			if ms < 0 {
				lat, latSt = "    ✗", errStyle // dead node
			} else {
				lat = fmt.Sprintf("%4d ms", ms)
				switch {
				case ms <= 150:
					latSt = okStyle // good
				case ms <= 300:
					latSt = warnStyle // mediocre
				default:
					latSt = errStyle // bad
				}
			}
		}
		active := a.store.ActiveNodeID == n.ID
		cursor := i == a.nodeIdx
		if !active {
			style := normalStyle
			if cursor {
				style = selectedStyle
			}
			row := " " + " " +
				padRight(style.Render(TruncateVisible(name, nameW-2)), nameW) +
				" " + padRight(n.Type(), protoW) +
				" " + padRight(n.Addr(), addrW) +
				" " + latSt.Render(lat)
			lines = append(lines, row)
			continue
		}
		// The active node renders as a full-width bar: while pinging and
		// scanning the list, the connected server must be visible at a glance,
		// not hunted by a small "*" marker. Every cell (including padding)
		// carries the bar background so the highlight has no gaps.
		fg := lipgloss.Color("39")
		if cursor {
			fg = lipgloss.Color("220") // cursor on the active row: yellow on the bar
		}
		nameStyle := lipgloss.NewStyle().Bold(true).Foreground(fg).Background(bar)
		latStyle := latSt.Background(bar)
		if _, tested := a.latency[n.Tag]; !tested {
			latStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("250")).Background(bar) // dim 241 is unreadable on the bar
		}
		cell := func(plain string, w int, st lipgloss.Style) string {
			s := plain
			if lipgloss.Width(s) > w {
				s = TruncateVisible(s, w)
			}
			s = st.Render(s)
			if gap := w + 1 - lipgloss.Width(s); gap > 0 {
				s += rowBarStyle.Render(strings.Repeat(" ", gap))
			}
			return s
		}
		row := cell("●", 1, nameStyle) +
			cell(TruncateVisible(name, nameW-2), nameW, nameStyle) +
			cell(n.Type(), protoW, rowBarStyle) +
			cell(n.Addr(), addrW, rowBarStyle) +
			latStyle.Render(lat)
		if gap := a.width - lipgloss.Width(row); gap > 0 {
			row += rowBarStyle.Render(strings.Repeat(" ", gap))
		}
		lines = append(lines, row)
	}
	return strings.Join(lines, "\n")
}

func (a *App) renderSubs(height int) string {
	if len(a.store.Subs) == 0 {
		return "\n " + dimStyle.Render("no subscriptions — press `a` to add one")
	}
	var lines []string
	maxEntries := (height - 1) / 2 // every entry renders two physical lines
	if maxEntries < 1 {
		maxEntries = 1
	}
	for i, s := range a.store.Subs {
		style := normalStyle
		marker := " "
		if i == a.subIdx {
			style = selectedStyle
		}
		if a.store.ActiveSubID == s.ID {
			marker = "*"
			style = activeStyle
		}
		count := 0
		for _, n := range a.store.Nodes {
			if n.SubID == s.ID {
				count++
			}
		}
		row := fmt.Sprintf("%s %s  %s nodes", marker,
			style.Render(TruncateVisible(s.Name, 24)),
			dimStyle.Render(fmt.Sprintf("%d", count)))
		if meta := subMetaView(s); meta != "" {
			row += "  " + meta
		}
		row += "\n   " + dimStyle.Render(TruncateVisible(s.URL, maxInt(a.width-6, 10)))
		lines = append(lines, row)
		if len(lines) >= maxEntries {
			break
		}
	}
	return strings.Join(lines, "\n")
}

// subMetaView renders the provider-side account state (subscription-userinfo
// header): used traffic and the expiry date, dim by default, warn near the
// end, error once expired.
func subMetaView(s *store.Subscription) string {
	var parts []string
	if s.TrafficTotal > 0 {
		used := s.UploadTotal + s.DownloadTotal
		pct := float64(used) / float64(s.TrafficTotal)
		style := dimStyle
		if pct >= 1 {
			style = errStyle
		} else if pct >= 0.8 {
			style = warnStyle
		}
		parts = append(parts, style.Render(fmt.Sprintf("%s / %s", humanBytes(used), humanBytes(s.TrafficTotal))))
	}
	if s.ExpireUnix > 0 {
		left := time.Until(time.Unix(s.ExpireUnix, 0))
		style := dimStyle
		label := time.Unix(s.ExpireUnix, 0).Format("Jan 2")
		switch {
		case left < 0:
			style, label = errStyle, "expired"
		case left < 72*time.Hour:
			style = warnStyle
			label = fmt.Sprintf("%dd left", int(left.Hours()/24)+1)
		}
		parts = append(parts, style.Render(label))
	}
	if s.LastUpdateUnix > 0 {
		parts = append(parts, dimStyle.Render("upd "+humanAgo(time.Unix(s.LastUpdateUnix, 0))))
	}
	return strings.Join(parts, " ")
}

// humanAgo renders a coarse "2h"-style age for the subs tab.
func humanAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "now"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func (a *App) renderLogs(height int) string {
	lines := a.mgr.Logs()
	if len(lines) == 0 {
		return "\n " + dimStyle.Render("logs are empty")
	}
	maxOff := maxInt(0, len(lines)-height)
	off := a.logOffset
	if off > maxOff {
		off = maxOff
	}
	end := off + height
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	for i, l := range lines[off:end] {
		if i > 0 {
			b.WriteString("\n ")
		}
		b.WriteByte(' ')
		switch {
		case strings.Contains(l, "FATAL"), strings.Contains(l, "ERROR"):
			b.WriteString(errStyle.Render(l))
		case strings.Contains(l, "WARN"):
			b.WriteString(warnStyle.Render(l))
		case strings.Contains(l, "[ratbox]"):
			b.WriteString(titleStyle.Render(l))
		default:
			b.WriteString(normalStyle.Render(l))
		}
	}
	return b.String()
}

func (a *App) renderFooter() string {
	if a.inputActive {
		shown := a.inputBuf
		if a.inputMasked {
			shown = strings.Repeat("*", len([]rune(a.inputBuf)))
		}
		return fmt.Sprintf("\n %s%s▏", titleStyle.Render(a.inputPrompt), shown)
	}
	var keys string
	switch a.view {
	case ViewNodes:
		keys = "↑↓ select · Enter connect · t test · a test all · n add link · d remove · m tun · y auto · p profile · s start/stop"
	case ViewSubs:
		keys = "Enter profile · u update · c clear · r rename · a add · d delete · m tun · y auto · p profile · s start/stop"
	case ViewLogs:
		keys = "j/k,g/G scroll · s start/stop"
	case ViewSettings:
		keys = "↑↓ select · enter/space apply · x fix tun caps (sudo) · esc back"
	}
	keys += " · ←→ tabs · q quit"
	var status string
	if a.status != "" {
		if a.statusErr {
			status = errStyle.Render(" ! ") + errStyle.Render(a.status)
		} else {
			status = okStyle.Render(" ✓ ") + a.status
		}
	}
	statusLine := "\n" + status
	return statusLine + "\n" + helpStyle.Render(keys)
}

// cleanTag strips variation selectors (U+FE0F) and zero-width joiners that
// some terminals count as printable cells, breaking column alignment entirely
// (e.g. "⚡️" renders as ⚡ + a stray box that eats the rest of the row).
func cleanTag(s string) string {
	s = strings.ReplaceAll(s, "\ufe0f", "")
	s = strings.ReplaceAll(s, "\u200d", "")
	return s
}

// visibleOffset keeps the list pinned to the top until the cursor
// reaches the bottom edge, then scrolls one line at a time (and pinned to
// the bottom near the end) — no more center-jumping while browsing.
func visibleOffset(cursor, total, visible int) int {
	if total <= visible || visible <= 0 {
		return 0
	}
	if cursor < visible-1 {
		return 0
	}
	// cursor rides the bottom edge; at the list end the offset naturally
	// reaches total-visible, so no extra clamp branch is needed
	return cursor - visible + 1
}
