package sub

import (
	"encoding/json"
	"strings"
	"testing"
)

const clashYAMLBody = `mixed-port: 7890
mode: rule
proxies:
  - name: "SS Plugin"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: secret
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      tls: true
      host: cdn.example.test
      path: /ws
  - name: "VMESS WS"
    type: vmess
    server: vm.example.test
    port: 443
    uuid: 93892a3c-0f6f-4f9c-8ca3-b7e6b9e5b0c1
    alterId: 0
    cipher: auto
    tls: true
    servername: vm.example.test
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /vm
      headers:
        Host: vm.example.test
  - name: "VLESS REALITY"
    type: vless
    server: vless.example.test
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    flow: xtls-rprx-vision
    tls: true
    servername: about.example.test
    client-fingerprint: chrome
    reality-opts:
      public-key: PUBKEY123
      short-id: ab12
    network: grpc
    grpc-opts:
      grpc-service-name: GrpcSvc
  - name: "TROJAN TCP"
    type: trojan
    server: troj.example.test
    port: 443
    password: troypass
    sni: troj.example.test
    client-fingerprint: firefox
  - name: "HY2"
    type: hysteria2
    server: hy.example.test
    port: 36712
    password: hyauth
    sni: hy.example.test
    up: "100 Mbps"
    down: 500
    obfs: salamander
    obfs-password: obpass
  - name: "TUIC"
    type: tuic
    server: tuic.example.test
    port: 8443
    uuid: 4684e978-11e3-46cd-be8b-e91c321bc418
    password: tuicpass
    sni: tuic.example.test
    congestion-controller: bbr
    alpn: [h3]

proxy-groups: []
rules: []
`

func parseClashMap(t *testing.T, body string) map[string]map[string]any {
	t.Helper()
	nodes, err := ParseSubscriptionBody(body)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, n := range nodes {
		var m map[string]any
		if err := json.Unmarshal(n.Outbound, &m); err != nil {
			t.Fatalf("node %s: %v", n.Tag, err)
		}
		out[n.Tag] = m
	}
	return out
}

func TestParseClashYAMLFull(t *testing.T) {
	byTag := parseClashMap(t, clashYAMLBody)
	if len(byTag) != 6 {
		t.Fatalf("expected 6 nodes, got %d", len(byTag))
	}
	ss := byTag["SS Plugin"]
	if ss["type"] != "shadowsocks" || ss["plugin"] != "v2ray-plugin" ||
		ss["plugin_opts"] != "mode=websocket;tls;host=cdn.example.test;path=/ws" {
		t.Fatalf("ss: %+v", ss)
	}
	vm := byTag["VMESS WS"]
	if vm["security"] != "auto" || vm["alter_id"] != float64(0) {
		t.Fatalf("vmess: %+v", vm)
	}
	vmTLS := vm["tls"].(map[string]any)
	vmTR := vm["transport"].(map[string]any)
	if vmTLS["insecure"] != true || vmTLS["server_name"] != "vm.example.test" ||
		vmTR["type"] != "ws" || vmTR["path"] != "/vm" {
		t.Fatalf("vmess tls/transport: %+v %+v", vmTLS, vmTR)
	}
	vl := byTag["VLESS REALITY"]
	reality := vl["tls"].(map[string]any)["reality"].(map[string]any)
	if vl["flow"] != "xtls-rprx-vision" || reality["public_key"] != "PUBKEY123" ||
		reality["short_id"] != "ab12" ||
		vl["transport"].(map[string]any)["service_name"] != "GrpcSvc" {
		t.Fatalf("vless: %+v", vl)
	}
	tr := byTag["TROJAN TCP"]
	if tr["password"] != "troypass" || tr["tls"].(map[string]any)["server_name"] != "troj.example.test" {
		t.Fatalf("trojan: %+v", tr)
	}
	hy := byTag["HY2"]
	if hy["up_mbps"] != float64(100) || hy["down_mbps"] != float64(500) ||
		hy["obfs"].(map[string]any)["type"] != "salamander" {
		t.Fatalf("hysteria2: %+v", hy)
	}
	tu := byTag["TUIC"]
	if tu["congestion_control"] != "bbr" || tu["tls"].(map[string]any)["alpn"].([]any)[0] != "h3" {
		t.Fatalf("tuic: %+v", tu)
	}
}

func TestParseClashJSONShape(t *testing.T) {
	// Panels serving a json-shaped clash config ("proxies": [...]).
	body := `{"mixed-port": 7890, "proxies": [{"name": "J", "type": "trojan", "server": "j.example.test", "port": 443, "password": "pw"}]}`
	nodes, err := ParseSubscriptionBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "J" || nodes[0].Protocol != "trojan" {
		t.Fatalf("nodes: %+v", nodes)
	}
}

func TestSingBoxConfigSkipsUnsupportedTransports(t *testing.T) {
	// xhttp is an xray-only transport; a config mixing it in must not make
	// the whole subscription unusable.
	body := `{"outbounds":[` +
		`{"type":"vless","tag":"ok","server":"1.2.3.4","server_port":443,"uuid":"u"},` +
		`{"type":"vless","tag":"xh","server":"1.2.3.4","server_port":443,"uuid":"u","transport":{"type":"xhttp"}}]}`
	nodes, err := ParseSubscriptionBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "ok" {
		t.Fatalf("nodes: %+v", nodes)
	}
}

func TestParseClashYAMLBase64(t *testing.T) {
	nodes, err := ParseSubscriptionBody(base64Std(clashYAMLBody))
	if err != nil || len(nodes) != 6 {
		t.Fatalf("base64 yaml: %v (%d nodes)", err, len(nodes))
	}
}

func TestClashYAMLUnsupportedOnly(t *testing.T) {
	body := "proxies:\n  - {name: x, type: socks5, server: 1.2.3.4, port: 1080}\n"
	_, err := ParseSubscriptionBody(body)
	if err == nil || !strings.Contains(err.Error(), "0 of 1 proxies supported") {
		t.Fatalf("expected the 0-supported error, got %v", err)
	}
}

func TestClashYAMLParsesForPlaceholderDetection(t *testing.T) {
	body := "proxies:\n  - {name: Unsupported app, type: ss, server: 0.0.0.0, port: 1, cipher: aes-128-gcm, password: x}\n"
	nodes, err := ParseSubscriptionBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if !placeholderNodes(nodes) {
		t.Fatal("placeholder yaml response not detected")
	}
}
