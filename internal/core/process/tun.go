package process

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkTUNConflicts deliberately refuses concurrent TUN clients rather than
// taking over their routes. Linux tun_flags is present for TUN/TAP devices;
// missing operstate or unreadable flags are errors, not evidence of safety.
func checkTUNConflicts(netDir string) error {
	entries, err := os.ReadDir(netDir)
	if err != nil {
		return fmt.Errorf("inspect TUN interfaces: %w", err)
	}
	for _, entry := range entries {
		base := filepath.Join(netDir, entry.Name())
		flags, err := os.ReadFile(filepath.Join(base, "tun_flags"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect interface %s: %w", entry.Name(), err)
		}
		// IFF_TUN = 1, IFF_TAP = 2. Do not reject bridged TAP devices.
		if !isTUN(flags) {
			continue
		}
		state, err := os.ReadFile(filepath.Join(base, "operstate"))
		if err != nil {
			return fmt.Errorf("inspect interface %s: %w", entry.Name(), err)
		}
		if strings.TrimSpace(string(state)) == "down" {
			continue
		}
		return fmt.Errorf("TUN conflict: %s is active — stop its VPN/client first, or disable TUN in ratbox", entry.Name())
	}
	return nil
}

func isTUN(flags []byte) bool {
	var n uint64
	_, err := fmt.Sscanf(strings.TrimSpace(string(flags)), "0x%x", &n)
	return err == nil && n&1 != 0
}
