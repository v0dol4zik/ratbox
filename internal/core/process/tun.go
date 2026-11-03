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
