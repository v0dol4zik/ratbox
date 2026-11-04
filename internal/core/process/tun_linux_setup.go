package process

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"
)

// ErrTUNAdminRequired requests the existing masked sudo flow. No privileged
// helper is installed and no password or sudo credential is stored by ratbox.
var ErrTUNAdminRequired = errors.New("TUN setup requires sudo authorization")

const tunDNSAddress = "172.28.123.2"

func commandOutput(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Preflight before sing-box can touch its hardcoded shared nftables table.
// Never flush/delete a pre-existing table, even when it looks stale.
func preflightRedirect() error {
	for _, tool := range []string{"sudo", "nft", "resolvectl"} {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("TUN setup requires %s", tool)
		}
	}
	out, err := commandOutput("sudo", "-n", "nft", "list", "tables")
	if err != nil {
		return fmt.Errorf("%w: cannot inspect nftables", ErrTUNAdminRequired)
	}
	return checkRedirectTables(string(out))
}

func checkRedirectTables(out string) error {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == "inet" && fields[2] == "sing-box" {
			return fmt.Errorf("nftables table inet sing-box already exists; ratbox will not overwrite another core's rules. Stop its owner before starting TUN (do not flush the firewall)")
		}
	}
	return nil
}

// Discover DNS from the physical uplink BEFORE changing resolved's link DNS.
// Do not bootstrap a proxy via resolved's VPN default (~.), which would loop
// once system DNS is pointed back at ratbox. This mirrors Throne's separation
// of underlying DNS from proxy DNS without depending on its patched libbox.
func discoverBootstrapDNS() (string, error) {
	out, err := commandOutput("ip", "-j", "route", "show", "table", "main", "default")
	if err != nil {
		return "", fmt.Errorf("discover uplink: %w", err)
	}
	dev, err := defaultUplink(out)
	if err != nil {
		return "", err
	}
	out, err = commandOutput("resolvectl", "dns", dev)
	if err == nil {
		if addr := firstDNSAddress(string(out)); addr != "" {
			return addr, nil
		}
	}
	out, err = os.ReadFile("/etc/resolv.conf")
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 1 && fields[0] == "nameserver" {
				if addr := firstDNSAddress(fields[1]); addr != "" {
					return addr, nil
				}
			}
		}
	}
	return "", fmt.Errorf("no physical-uplink DNS found; cannot safely bootstrap proxy through the system VPN resolver")
}

func defaultUplink(data []byte) (string, error) {
	var routes []struct {
		Dev string `json:"dev"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return "", err
	}
	for _, r := range routes {
		if r.Dev != "" && r.Dev != TunName {
			return r.Dev, nil
		}
	}
	return "", fmt.Errorf("no physical default uplink found")
}

func firstDNSAddress(text string) string {
	for _, field := range strings.Fields(text) {
		addr, err := netip.ParseAddr(field)
		if err == nil && !addr.IsLoopback() && !addr.IsUnspecified() && !addr.IsMulticast() {
			return addr.String()
		}
	}
	return ""
}

// Apply DNS only to ratbox0, not NetworkManager/global resolv.conf or another
// VPN's link. Kernel removal of ratbox0 (also on a crash) removes this resolved
// link configuration; no permanent DNS policy or global polkit grant is used.
func (m *Manager) ConfigureTUNDNS() error {
	for _, args := range [][]string{
		{"dns", TunName, tunDNSAddress},
		{"domain", TunName, "~."},
		{"default-route", TunName, "true"},
		{"flush-caches"},
	} {
		out, err := commandOutput("sudo", append([]string{"-n", "resolvectl"}, args...)...)
		if err != nil {
			return fmt.Errorf("configure TUN DNS (%s): %s (%w)", args[0], strings.TrimSpace(string(out)), err)
		}
	}
	return nil
}
