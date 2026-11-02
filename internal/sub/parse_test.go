package sub

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func parse(t *testing.T, link string) map[string]any {
	t.Helper()
	node, err := ParseLink(link)
	if err != nil {
		t.Fatalf("ParseLink(%q): %v", link, err)
	}
	if node.Tag == "" {
		t.Fatalf("empty tag")
	}
	var m map[string]any
	if err := json.Unmarshal(node.Outbound, &m); err != nil {
		t.Fatalf("outbound is not valid json: %v", err)
	}
	return m
}

func TestParseVLESSReality(t *testing.T) {
	m := parse(t, "vless://0301020304050607-0809101112131415@server.example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.yahoo.com&fp=chrome&pbk=PUB_KEY&sid=ab12&spx=%2F&type=tcp#MyNode")
	if m["type"] != "vless" || m["server"] != "server.example.com" || m["server_port"] != float64(443) {
		t.Fatalf("bad server fields: %v", m)
	}
	if m["flow"] != "xtls-rprx-vision" {
		t.Fatalf("bad flow: %v", m["flow"])
	}
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("missing tls block")
	}
	reality, ok := tls["reality"].(map[string]any)
	if !ok || reality["public_key"] != "PUB_KEY" || reality["short_id"] != "ab12" {
		t.Fatalf("bad reality: %v", tls)
	}
}

func TestParseVLESSWS(t *testing.T) {
	m := parse(t, "vless://uuid@1.2.3.4:8443?type=ws&security=tls&sni=cd.example.com&host=cd.example.com&path=%2Fws#WS-Node")
	tr, ok := m["transport"].(map[string]any)
	if !ok || tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Fatalf("bad transport: %v", m["transport"])
	}
	hdr, ok := tr["headers"].(map[string]any)
	if !ok || hdr["Host"] != "cd.example.com" {
		t.Fatalf("bad ws host header: %v", tr)
	}
	tls, ok := m["tls"].(map[string]any)
	if !ok || tls["server_name"] != "cd.example.com" {
		t.Fatalf("bad tls: %v", m["tls"])
	}
}

func TestParseVMess(t *testing.T) {
	payload := `{"v":"2","ps":"Tokyo-01","add":"jp.example.com","port":"8443","id":"93892a3c-0f6f-4f9c-8ca3-b7e6b9e5b0c1","aid":"0","scy":"auto","net":"ws","type":"none","host":"jp.example.com","path":"/ws","tls":"tls","sni":"jp.example.com"}`
	link := "vmess://" + base64.StdEncoding.EncodeToString([]byte(payload))
	m := parse(t, link)
	if m["type"] != "vmess" || m["server"] != "jp.example.com" || m["server_port"] != float64(8443) {
		t.Fatalf("bad server fields: %v", m)
	}
	tr, ok := m["transport"].(map[string]any)
	if !ok || tr["type"] != "ws" || tr["path"] != "/ws" {
		t.Fatalf("bad transport: %v", m["transport"])
	}
	if tls, ok := m["tls"].(map[string]any); !ok || tls["enabled"] != true {
		t.Fatalf("bad tls: %v", m["tls"])
	}
}

func TestParseShadowsocksSIP002(t *testing.T) {
	m := parse(t, "ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@5.6.7.8:8388#SS-Node")
	if m["type"] != "shadowsocks" || m["method"] != "aes-256-gcm" || m["password"] != "password" {
		t.Fatalf("bad ss: %v", m)
	}
}

func TestParseShadowsocksObfs(t *testing.T) {
	link := "ss://" + b64url("aes-128-gcm:secretpass") + "@9.9.9.9:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dcdn.example.com#obfs"
	m := parse(t, link)
	if m["plugin"] != "obfs-local" {
		t.Fatalf("bad plugin: %v", m["plugin"])
	}
	if m["plugin_opts"] != "obfs=http;obfs-host=cdn.example.com" {
		t.Fatalf("bad plugin_opts: %v", m["plugin_opts"])
	}
}

func TestParseTrojan(t *testing.T) {
	m := parse(t, "trojan://Pa55word@trojan.example.com:443?security=tls&sni=trojan.example.com&type=tcp#Trojan-Node")
	if m["type"] != "trojan" || m["password"] != "Pa55word" {
		t.Fatalf("bad trojan: %v", m)
	}
	if tls, ok := m["tls"].(map[string]any); !ok || tls["enabled"] != true {
		t.Fatalf("trojan must have tls: %v", m["tls"])
	}
}

func TestParseHysteria2(t *testing.T) {
	m := parse(t, "hysteria2://authpass@hy.example.com:36712?sni=hy.example.com&insecure=1&upmbps=100&downmbps=500&obfs=salamander&obfs-password=obpass&mport=20000-30000#Hy2")
	if m["type"] != "hysteria2" || m["password"] != "authpass" {
		t.Fatalf("bad hy2: %v", m)
	}
	tls, ok := m["tls"].(map[string]any)
	if !ok || tls["insecure"] != true {
		t.Fatalf("bad tls: %v", m["tls"])
	}
	if m["up_mbps"] != float64(100) || m["down_mbps"] != float64(500) {
		t.Fatalf("bad mbps: %v", m)
	}
	if ports, ok := m["server_ports"].([]any); !ok || ports[0] != "20000:30000" {
		t.Fatalf("bad server_ports: %v", m["server_ports"])
	}
	if obfs, ok := m["obfs"].(map[string]any); !ok || obfs["type"] != "salamander" {
		t.Fatalf("bad obfs: %v", m["obfs"])
	}
}

func TestParseTUIC(t *testing.T) {
	m := parse(t, "tuic://9a6e9c7e-61d8-4ce5-bfb4-1673944b63b4:pa55word-1@tuic.example.com:8443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#TUIC-Node")
	if m["type"] != "tuic" || m["uuid"] != "9a6e9c7e-61d8-4ce5-bfb4-1673944b63b4" || m["password"] != "pa55word-1" {
		t.Fatalf("bad tuic: %v", m)
	}
	if m["congestion_control"] != "bbr" {
		t.Fatalf("bad cc: %v", m["congestion_control"])
	}
}

func TestParseSubscriptionBodyBase64(t *testing.T) {
	raw := strings.Join([]string{
		"vless://uuid@1.1.1.1:443?type=tcp&security=tls#NodeOne",
		"trojan://pass@2.2.2.2:443#NodeTwo",
		"",
	}, "\n")
	body := base64.StdEncoding.EncodeToString([]byte(raw))
	nodes, err := ParseSubscriptionBody(body)
	if err != nil {
		t.Fatalf("ParseSubscriptionBody: %v", err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if nodes[0].Tag != "NodeOne" || nodes[1].Tag != "NodeTwo" {
		t.Fatalf("bad tags: %v, %v", nodes[0].Tag, nodes[1].Tag)
	}
}

func b64url(s string) string {
	return strings.ReplaceAll(base64.RawStdEncoding.EncodeToString([]byte(s)), "+", "-")
}
