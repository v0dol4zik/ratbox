package process

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/v0dol4zik/ratbox/internal/model"
)

func TestTUNConflict(t *testing.T) {
	for _, tt := range []struct {
		name, flags, state string
		conflict           bool
	}{
		{"wlan0", "", "up", false},
		{"throne-tun", "0x1001", "unknown", false},
		{"tun0", "0x1001", "up", false},
		{TunName, "0x1001", "unknown", true},
		{"tap0", "0x1002", "unknown", false},
		{"tun0", "0x1001", "down", false},
	} {
		t.Run(tt.name+tt.state, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, tt.name)
			if err := os.Mkdir(base, 0755); err != nil {
				t.Fatal(err)
			}
			for file, value := range map[string]string{"tun_flags": tt.flags, "operstate": tt.state} {
				if value != "" {
					if err := os.WriteFile(filepath.Join(base, file), []byte(value), 0644); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := checkTUNConflicts(dir)
			if (err != nil) != tt.conflict {
				t.Fatalf("conflict = %v, want %v", err, tt.conflict)
			}
			if err != nil && !strings.Contains(err.Error(), tt.name) {
				t.Fatal(err)
			}
		})
	}
}

// Exercises the real preflight only when ratbox's own interface exists.
// Start must reject before creating a config or starting any process.
func TestHostTUNConflictPreventsStart(t *testing.T) {
	conflict := checkTUNConflicts("/sys/class/net")
	if conflict == nil {
		t.Skip("host has no conflicting TUN")
	}
	bin, err := ResolveBinaryPath("")
	if err != nil {
		t.Skip(err)
	}
	dir := filepath.Join(t.TempDir(), "must-not-be-created")
	mgr := NewManager(Config{Binary: bin, DataDir: dir})
	err = mgr.Start(StartOptions{Tun: true})
	if err == nil || err.Error() != conflict.Error() {
		t.Fatalf("want %v, got %v", conflict, err)
	}
	if mgr.Running() {
		t.Fatal("core started despite TUN conflict")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("preflight touched config directory")
	}
	t.Log(conflict)
}

func TestTUNRouteDiagnostic(t *testing.T) {
	for _, tt := range []struct{ data, want string }{
		{`[{"dev":"ratbox0"}]`, "via ratbox0"},
		{`[{"dev":"throne-tun"}]`, "warning: 1.1.1.1 uses throne-tun"},
		{`[{"dev":"wlan0"}]`, "warning: 1.1.1.1 uses wlan0"},
		{`[]`, "invalid"},
		{`bad-json`, "invalid"},
	} {
		if got := tunRouteDiagnostic([]byte(tt.data)); !strings.Contains(got, tt.want) {
			t.Errorf("diagnostic(%s) = %s, want %s", tt.data, got, tt.want)
		}
	}
}

func TestTUNConfigIsolation(t *testing.T) {
	cfg, err := BuildConfig(StartOptions{
		Nodes: []*model.Node{{Tag: "test", Outbound: json.RawMessage(`{"type":"direct"}`)}},
		Tun:   true, ServicePort: 39102,
	}, 2080, "127.0.0.1:9090", "test", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Inbounds []map[string]any `json:"inbounds"`
		Route    struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	tun := parsed.Inbounds[0]
	for key, want := range map[string]any{
		"interface_name":       TunName,
		"iproute2_table_index": float64(TunTableIndex),
		"iproute2_rule_index":  float64(TunRuleIndex),
		"dns_mode":             "disabled",
		"mtu":                  float64(1500),
	} {
		if tun[key] != want {
			t.Errorf("%s = %v, want %v", key, tun[key], want)
		}
	}
	if parsed.Route.Rules[2]["action"] != "hijack-dns" || parsed.Route.Rules[3]["ip_is_private"] != true {
		t.Fatal("DNS must precede private-address bypass")
	}
}
