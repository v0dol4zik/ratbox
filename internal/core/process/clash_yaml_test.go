package process

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/v0dol4zik/ratbox/internal/sub"
)

// Clash YAML subscriptions must produce outbounds the real core accepts.
// Masthead of the sub-package conversion with a buildable runtime config.
func TestBuildConfigFromClashYAML(t *testing.T) {
	bin, err := exec.LookPath(sbPath(t))
	if err != nil {
		t.Fatal(err)
	}
	body := `proxies:
  - {name: SS, type: ss, server: 1.2.3.4, port: 8388, cipher: aes-256-gcm, password: pw}
  - {name: VM, type: vmess, server: vm.example.test, port: 443, uuid: 93892a3c-0f6f-4f9c-8ca3-b7e6b9e5b0c1, tls: true, servername: vm.example.test, network: ws, ws-opts: {path: /vm, headers: {Host: vm.example.test}}}
  - {name: VL, type: vless, server: vless.example.test, port: 443, uuid: 11111111-2222-3333-4444-555555555555, flow: xtls-rprx-vision, tls: true, servername: about.example.test, client-fingerprint: chrome, reality-opts: {public-key: WgRxwG7Nsex8lbLs2p6Tr5Ph0l1gxl4HgAl5i0EcKwo, short-id: ab12}, network: grpc, grpc-opts: {grpc-service-name: svc}}
  - {name: TR, type: trojan, server: troj.example.test, port: 443, password: pw, sni: troj.example.test}
  - {name: HY, type: hysteria2, server: hy.example.test, port: 36712, password: pw, sni: hy.example.test}
  - {name: TU, type: tuic, server: tuic.example.test, port: 8443, uuid: 4684e978-11e3-46cd-be8b-e91c321bc418, password: pw, sni: tuic.example.test}
`
	nodes, err := sub.ParseClashYAML(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 6 {
		t.Fatalf("expected 6 nodes, got %d", len(nodes))
	}
	dir := t.TempDir()
	cfg, err := BuildConfig(StartOptions{Nodes: nodes, ActiveTag: nodes[0].Tag, ServicePort: 39105}, 2080, "127.0.0.1:9099", "secret", dir)
	if err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "clash.json")
	if err := os.WriteFile(cfgPath, cfg, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "check", "-c", cfgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("sing-box check (clash yaml nodes) failed:\n%s", out)
	}
}
