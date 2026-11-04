package process

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// TUNRouteDiagnostic reports the actual kernel route without modifying it.
// A route probe is not an end-to-end connectivity test (nftables may redirect
// packets afterwards), so do not label it as a verified connection.
func (m *Manager) TUNRouteDiagnostic() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "-j", "route", "get", "1.1.1.1").Output()
	if err != nil {
		return "TUN route check unavailable: " + err.Error()
	}
	return tunRouteDiagnostic(out)
}

func tunRouteDiagnostic(data []byte) string {
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(data, &routes); err != nil || len(routes) == 0 || routes[0].Dev == "" {
		return "TUN route check: invalid ip route response"
	}
	if routes[0].Dev != TunName {
		return fmt.Sprintf("TUN routing warning: 1.1.1.1 uses %s, not %s; check other VPN routes", routes[0].Dev, TunName)
	}
	return "TUN kernel route: 1.1.1.1 via " + TunName + " (connectivity not verified)"
}

// TUNForeignCaptureDiagnostic reports policy-rule hints only. These rules do
// not prove that nftables redirects a particular packet. Read-only inspection.
func (m *Manager) TUNForeignCaptureDiagnostic() string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "ip", "rule", "show").Output()
	if err != nil {
		return ""
	}
	return tunForeignCapture(string(out))
}

// tunForeignCapture scans ip-rule output for the sing-tun auto_redirect
// mark-mode pattern (fwmark rules of an auto-redirect client). Only the
// known fwmark/mask pair of sing-box defaults is reported; generic marks are
// ignored to avoid false accusations against unrelated software.
func tunForeignCapture(rules string) string {
	if !strings.Contains(rules, "fwmark 0x2023") && !strings.Contains(rules, "fwmark 0x2024") {
		return ""
	}
	// Our own core does not enable auto_redirect in production, so any such
	// rule set belongs to another client that also owns the shared nft table.
	return "TUN warning: policy rules use sing-box default marks; another client's interception may be active (rules alone do not prove capture)"
}

// LogDiagnostic appends a supervisor diagnostic to the core log ring.
func (m *Manager) LogDiagnostic(text string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.log("[ratbox] " + strings.ReplaceAll(text, "\n", " "))
}

// Only reserve ratbox's own interface. Another client's persistent TUN may
// remain UP/UNKNOWN while disconnected; its existence does not prove a routing
// conflict. Never block mixed mode or delete another client's interface.
func checkTUNConflicts(netDir string) error {
	_, err := os.Stat(filepath.Join(netDir, TunName))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect %s: %w", TunName, err)
	}
	return fmt.Errorf("interface %s already exists: stop the previous ratbox core before starting TUN", TunName)
}
