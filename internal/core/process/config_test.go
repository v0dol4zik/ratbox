package process

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/v0dol4zik/ratbox/internal/model"
	"github.com/v0dol4zik/ratbox/internal/sub"
)

func sbPath(t *testing.T) string {
	t.Helper()
	for _, p := range []string{os.Getenv("SING_BOX_BIN"), "sing-box",
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "sing-box")} {
		if p == "" {
			continue
		}
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	t.Skip("sing-box binary not found")
	return ""
}

// TestBuildConfigChecks generates configs from every supported link type
// and validates them with the real sing-box binary.
func TestBuildConfigChecks(t *testing.T) {
	bin := sbPath(t)
	links := []string{
		"vless://0301020304050607-0809101112131415@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=WgRxwG7Nsex8lbLs2p6Tr5Ph0l1gxl4HgAl5i0EcKwo&sid=ab12&spx=%2F&spx=%2F&type=tcp#Reality",
		"vless://uuid@1.2.3.4:8443?type=ws&security=tls&sni=cd.example.com&host=cd.example.com&path=%2Fws#WS",
		"vless://uuid@grpc.example.com:443?security=tls&type=grpc&serviceName=GrpcSvc&sni=grpc.example.com#GRPC",
		"hysteria2://authpass@hy.example.com:36712?sni=hy.example.com&insecure=1&upmbps=100&downmbps=500&obfs=salamander&obfs-password=obpass&mport=20000-30000&hop_interval=500#Hy2",
		"hysteria2://authpass@hy2.example.com:443?sni=hy2.example.com#Hy2Plain",
		"tuic://4684e978-11e3-46cd-be8b-e91c321bc418:pa55word-1@tuic.example.com:8443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#TUIC",
		"trojan://Pa55word@trojan.example.com:443?security=tls&sni=trojan.example.com&type=tcp#Trojan",
		"trojan://Pa55@troj-ws.example.com:443?security=tls&sni=troj-ws.example.com&type=ws&host=troj-ws.example.com&path=%2Ftw#TrojanWS",
		"ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@5.6.7.8:8388#SS",
		"ss://" + b64std("chacha20-ietf-poly1305:hihihi") + "@9.9.9.9:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#obfs",
		// NOTE: legacy ss link missing: base64 goes to the whole "..." — see below
	}
	var nodes []*model.Node
	for _, link := range links {
		n, err := sub.ParseLink(link)
		if err != nil {
			t.Fatalf("ParseLink(%s): %v", link, err)
		}
		nodes = append(nodes, n)
	}
	// vmess separately (needs base64)
	n, err := sub.ParseLink(vmessLink())
	if err != nil {
		t.Fatalf("ParseLink(vmess): %v", err)
	}
	nodes = append(nodes, n)

	dir := t.TempDir()
	cfg, err := BuildConfig(StartOptions{Nodes: nodes, ActiveTag: nodes[0].Tag}, 2080, "127.0.0.1:9090", "topsecret", dir)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check failed:\n%s", out)
	}
}

func vmessLink() string {
	const payload = `{"v":"2","ps":"Tokyo-01","add":"jp.example.com","port":"8443","id":"93892a3c-0f6f-4f9c-8ca3-b7e6b9e5b0c1","aid":"0","scy":"auto","net":"ws","type":"none","host":"jp.example.com","path":"/ws","tls":"tls","sni":"jp.example.com"}`
	return "vmess://" + b64std(payload)
}

// TestSplithttpRejected ensures xray-only transports do not silently
// produce broken configs.
func TestSplithttpRejected(t *testing.T) {
	_, err := sub.ParseLink("vless://uuid@xh.example.com:443?security=tls&type=splithttp&path=%2Fx&host=xh.example.com&sni=xh.example.com#XHTTP")
	if err == nil {
		t.Fatal("expected error for splithttp transport")
	}
}

// TestBuildConfigTUN validates the tun-mode config against the real binary.
func TestBuildConfigTUN(t *testing.T) {
	bin := sbPath(t)
	links := []string{
		"vless://uuid@1.2.3.4:8443?type=ws&security=tls&sni=cd.example.com&host=cd.example.com&path=%2Fws#WS",
		"hysteria2://authpass@hy.example.com:36712?sni=hy.example.com#Hy2",
	}
	var nodes []*model.Node
	for _, link := range links {
		n, err := sub.ParseLink(link)
		if err != nil {
			t.Fatalf("ParseLink(%s): %v", link, err)
		}
		nodes = append(nodes, n)
	}
	dir := t.TempDir()
	cfg, err := BuildConfig(StartOptions{Nodes: nodes, ActiveTag: nodes[0].Tag, Tun: true}, 2080, "127.0.0.1:9091", "topsecret", dir)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check (tun) failed:\n%s", out)
	}
}

// TestBuildConfigAutoRU validates the auto urltest group and the RU-bypass
// profile against the real binary and checks the generated layout.
func TestBuildConfigAutoRU(t *testing.T) {
	bin := sbPath(t)
	links := []string{
		"vless://uuid@1.2.3.4:8443?type=ws&security=tls&sni=cd.example.com&host=cd.example.com&path=%2Fws#WS",
		"hysteria2://authpass@hy.example.com:36712?sni=hy.example.com#Hy2",
	}
	var nodes []*model.Node
	for _, link := range links {
		n, err := sub.ParseLink(link)
		if err != nil {
			t.Fatalf("ParseLink(%s): %v", link, err)
		}
		nodes = append(nodes, n)
	}
	dir := t.TempDir()
	cfg, err := BuildConfig(StartOptions{
		Nodes:          nodes,
		ActiveTag:      nodes[0].Tag,
		Tun:            true,
		Auto:           true,
		RoutingProfile: ProfileRUBypass,
	}, 2080, "127.0.0.1:9092", "topsecret", dir)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "cfg.json")
	if err := os.WriteFile(cfgPath, cfg, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "check", "-c", cfgPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check (auto+ru) failed:\n%s", out)
	}
	text := string(cfg)
	for _, want := range []string{
		`"type": "urltest"`,
		`"tag": "auto"`,
		`"tag": "geoip-ru"`,
		`"tag": "geosite-gov-ru"`,
		`"outbound": "direct"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("config missing %s", want)
		}
	}
	// selector default must be the auto group, not the manual node
	var parsed struct {
		Outbounds []struct {
			Type      string   `json:"type"`
			Tag       string   `json:"tag"`
			Default   string   `json:"default"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	var sel, auto *struct {
		Type      string   `json:"type"`
		Tag       string   `json:"tag"`
		Default   string   `json:"default"`
		Outbounds []string `json:"outbounds"`
	}
	for i := range parsed.Outbounds {
		switch parsed.Outbounds[i].Tag {
		case SelectorTag:
			sel = &parsed.Outbounds[i]
		case AutoTag:
			auto = &parsed.Outbounds[i]
		}
	}
	if sel == nil || auto == nil {
		t.Fatal("selector or auto group missing")
	}
	if sel.Default != AutoTag {
		t.Errorf("selector default = %q, want %q", sel.Default, AutoTag)
	}
	if len(sel.Outbounds) == 0 || sel.Outbounds[0] != AutoTag {
		t.Errorf("auto must be the first selector option, got %v", sel.Outbounds)
	}
	if auto.Type != "urltest" || len(auto.Outbounds) != len(nodes) {
		t.Errorf("bad urltest group: %+v", auto)
	}
}
