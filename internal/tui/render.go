package tui

import (
	"fmt"
	"strings"

	"github.com/v0dol4zik/ratbox/internal/core/process"
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
		parts = append(parts, warnStyle.Render("tun"))
	}
	if a.store.AutoMode {
		parts = append(parts, okStyle.Render("auto"))
	}
	if a.store.RoutingProfile == process.ProfileRUBypass {
		parts = append(parts, warnStyle.Render("RU→direct"))
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

// actionName renders what a command will do, for the live hint.
func actionName(act cmdAction) string {
	switch act {
	case actSettings:
		return "settings"
	case actQuit:
		return "quit"
	case actSave:
		return "save"
	case actHelp:
		return "help"
	}
	return ""
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
	for i := offset; i < len(a.store.Nodes) && len(lines)-1 < visible; i++ {
		n := a.store.Nodes[i]
		name := cleanTag(n.Tag)
		if len(a.store.Subs) > 1 && n.SubID != "" {
			name = a.store.SubName(n.SubID) + "/" + n.Tag
		}
		marker := " "
		style := normalStyle
		if a.store.ActiveNodeID == n.ID {
			marker = "*"
			style = activeStyle
		}
		if i == a.nodeIdx {
			style = selectedStyle
		}
		lat := "    —"
		if ms, ok := a.latency[n.Tag]; ok {
			if ms < 0 {
				lat = "    ✗"
			} else {
				lat = fmt.Sprintf("%4d ms", ms)
			}
		}
		row := marker + " " +
			padRight(style.Render(TruncateVisible(name, nameW-2)), nameW) +
			" " + padRight(n.Type(), protoW) +
			" " + padRight(n.Addr(), addrW) +
			" " + latStyle(lat)
		lines = append(lines, row)
	}
	return strings.Join(lines, "\n")
}

func latStyle(s string) string {
	switch {
	case strings.Contains(s, "✗"):
		return errStyle.Render(s)
	case s == "    —":
		return dimStyle.Render(s)
	default:
		return okStyle.Render(s)
	}
}

func (a *App) renderSubs(height int) string {
	if len(a.store.Subs) == 0 {
		return "\n " + dimStyle.Render("no subscriptions — press `a` to add one")
	}
	var lines []string
	for i, s := range a.store.Subs {
		style := normalStyle
		marker := " "
		if i == a.subIdx {
			style = selectedStyle
		}
		count := 0
		for _, n := range a.store.Nodes {
			if n.SubID == s.ID {
				count++
			}
		}
		lines = append(lines, fmt.Sprintf("%s %s  %s nodes  %s",
			marker,
			style.Render(TruncateVisible(s.Name, 20)),
			dimStyle.Render(fmt.Sprintf("%d", count)),
			dimStyle.Render(TruncateVisible(s.URL, a.width-40)),
		))
		if len(lines) >= height-1 {
			break
		}
	}
	return strings.Join(lines, "\n")
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
	shown := lines[off:end]
	for _, l := range shown {
		if strings.Contains(l, ".INFO") {
			l = normalStyle.Render(l)
		} else if strings.Contains(l, "[ratbox]") {
			l = titleStyle.Render(l)
		}
	}
	return " " + strings.Join(shown, "\n ")
}

func (a *App) renderFooter() string {
	if a.inputActive {
		shown := a.inputBuf
		if a.inputMasked {
			shown = strings.Repeat("*", len([]rune(a.inputBuf)))
		}
		line := fmt.Sprintf("\n %s%s▏", titleStyle.Render(a.inputPrompt), shown)
		if a.cmdMode && !a.inputMasked && strings.TrimSpace(a.inputBuf) != "" {
			if act, _ := resolveCommand(a.inputBuf); act != actNone {
				line += " " + okStyle.Render("→ "+actionName(act))
			} else if m := commandMatches(a.inputBuf); len(m) > 0 {
				line += " " + dimStyle.Render(strings.Join(m, " "))
			}
		}
		return line
	}
	var keys string
	switch a.view {
	case ViewNodes:
		keys = "↑↓ select · Enter connect · t test · T test all · n add link · d remove · m tun · y auto · p profile · s start/stop"
	case ViewSubs:
		keys = "↑↓ select · a add sub · u update · d remove · m tun · y auto · p profile · s start/stop"
	case ViewLogs:
		keys = "j/k,g/G scroll · s start/stop · : commands"
	case ViewSettings:
		keys = "↑↓ select · enter/space apply · esc back · : commands"
	}
	keys += " · 1/2/3 tabs · q quit"
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

func visibleOffset(cursor, total, visible int) int {
	if total <= visible || visible <= 0 {
		return 0
	}
	if cursor < visible/2 {
		return 0
	}
	if cursor > total-visible/2 {
		return total - visible
	}
	return cursor - visible/2
}
