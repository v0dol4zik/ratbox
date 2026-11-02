package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	normalStyle   = lipgloss.NewStyle()
	activeStyle   = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("220"))
	errStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	warnStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	helpStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	headerStyle   = lipgloss.NewStyle().Background(lipgloss.Color("236")).Foreground(lipgloss.Color("252"))
)

func padRight(s string, w int) string {
	if w <= 0 {
		return s
	}
	width := lipgloss.Width(s)
	if width >= w {
		if w > 1 {
			return TruncateVisible(s, w)
		}
		return s[:w]
	}
	return s + strings.Repeat(" ", w-width)
}

// TruncateVisible cuts a string considering double-width runes.
func TruncateVisible(s string, w int) string {
	if lipgloss.Width(s) <= w {
		return s
	}
	var b strings.Builder
	cw := 0
	for _, r := range s {
		rw := lipgloss.Width(string(r))
		if cw+rw > w-1 {
			b.WriteString("…")
			return b.String()
		}
		b.WriteRune(r)
		cw += rw
	}
	return b.String()
}

func humanBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func humanUptime(since time.Time) string {
	if since.IsZero() {
		return "—"
	}
	d := time.Since(since).Round(time.Second)
	if d < time.Minute {
		return d.String()
	}
	if d < time.Hour {
		return fmt.Sprintf("%02d:%02d", int(d.Minutes()), int(d.Seconds())%60)
	}
	h := int(d.Hours())
	return fmt.Sprintf("%d:%02d:%02d", h, int(d.Minutes())%60, int(d.Seconds())%60)
}
