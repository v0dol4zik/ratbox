// Package sub parses proxy share links and subscriptions and converts them
// into sing-box outbound configs.
package sub

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/v0dol4zik/ratbox/internal/model"
)

// ParseLink parses a single share link (vless://, vmess://, ss://, trojan://,
// hysteria2://, tuic://) and returns a node with a ready sing-box outbound.
func ParseLink(raw string) (*model.Node, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse uri: %w", err)
	}
	var (
		outbound map[string]any
		proto    string
	)
	switch strings.ToLower(u.Scheme) {
	case "vless":
		outbound, err = parseVLESS(u)
		proto = "vless"
	case "vmess":
		outbound, err = parseVMess(raw)
		proto = "vmess"
	case "ss":
		outbound, err = parseShadowsocksLink(u)
		proto = "shadowsocks"
	case "trojan":
		outbound, err = parseTrojan(u)
		proto = "trojan"
	case "hysteria2", "hy2":
		outbound, err = parseHysteria2(u)
		proto = "hysteria2"
	case "tuic":
		outbound, err = parseTUIC(u)
		proto = "tuic"
	default:
		return nil, fmt.Errorf("unsupported scheme %q", u.Scheme)
	}
	if err != nil {
		return nil, err
	}
	tag := decodeFragment(u.Fragment)
	if tag == "" {
		tag = fmt.Sprintf("%v:%v", outbound["server"], outbound["server_port"])
	}
	data, err := json.Marshal(outbound)
	if err != nil {
		return nil, err
	}
	return &model.Node{Tag: tag, Protocol: proto, Outbound: data}, nil
}

func decodeFragment(f string) string {
	if f == "" {
		return ""
	}
	if s, err := url.QueryUnescape(f); err == nil {
		return strings.TrimSpace(s)
	}
	return f
}

// ---------------------------------------------------------------------------
// vless
// ---------------------------------------------------------------------------

func parseVLESS(u *url.URL) (map[string]any, error) {
	if u.User == nil || u.User.String() == "" {
		return nil, fmt.Errorf("vless: missing uuid")
	}
	uuid := u.User.String()
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("vless: %w", err)
	}
	q := u.Query()

	out := map[string]any{
		"type":            "vless",
		"server":          host,
		"server_port":     port,
		"uuid":            uuid,
		"packet_encoding": "xudp",
	}
	if flow := q.Get("flow"); flow != "" {
		out["flow"] = flow
	}
	if tls := buildTLS(q, false); tls != nil {
		out["tls"] = tls
	}
	tr, terr := buildTransport(q.Get("type"), q)
	if terr != nil {
		return nil, terr
	}
	if tr != nil {
		out["transport"] = tr
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// vmess
// ---------------------------------------------------------------------------

type vmessJSON struct {
	V    any    `json:"v"`
	Ps   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	Aid  any    `json:"aid"`
	Scy  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	Tls  string `json:"tls"`
	Sni  string `json:"sni"`
	Alpn string `json:"alpn"`
	Fp   string `json:"fp"`
}

func parseVMess(raw string) (map[string]any, error) {
	payload := strings.TrimPrefix(strings.TrimSpace(raw), "vmess://")
	decoded, err := base64Decode(payload)
	if err != nil {
		return nil, fmt.Errorf("vmess: invalid base64: %w", err)
	}
	var v vmessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("vmess: invalid json payload: %w", err)
	}
	if v.Add == "" || v.ID == "" {
		return nil, fmt.Errorf("vmess: missing address or uuid")
	}
	port, _ := anyToInt(v.Port)
	if port == 0 {
		return nil, fmt.Errorf("vmess: missing port")
	}
	out := map[string]any{
		"type":        "vmess",
		"server":      v.Add,
		"server_port": port,
		"uuid":        v.ID,
		"security":    "auto",
		"alter_id":    0,
	}
	if v.Scy != "" {
		out["security"] = v.Scy
	}
	if aid, ok := anyToInt(v.Aid); ok && aid > 0 {
		out["alter_id"] = aid
	}
	// Fake Q-Values map to reuse buildTLS/buildTransport helpers.
	q := url.Values{}
	if v.Tls != "" {
		q.Set("security", "tls")
	}
	if strings.EqualFold(v.Tls, "reality") {
		q.Set("security", "reality")
	}
	if v.Sni != "" {
		q.Set("sni", v.Sni)
	}
	if v.Alpn != "" {
		q.Set("alpn", v.Alpn)
	}
	if v.Fp != "" {
		q.Set("fp", v.Fp)
	}
	if v.Tls != "" {
		if tls := buildTLS(q, false); tls != nil {
			out["tls"] = tls
		}
	}
	tr, terr := buildTransport(v.Net, nil)
	if terr != nil {
		return nil, terr
	}
	if tr != nil {
		applyTransportExtras(tr, v)
		out["transport"] = tr
	}
	return out, nil
}

// applyTransportExtras fills path/host/service_name for vmess json links
// since buildTransport only knows about generic query params.
func applyTransportExtras(tr map[string]any, v vmessJSON) {
	switch tr["type"] {
	case "ws", "http", "httpupgrade", "splithttp":
		if v.Path != "" {
			tr["path"] = v.Path
		}
		if v.Host != "" {
			if tr["type"] == "http" {
				tr["host"] = []string{v.Host}
			} else {
				setHeader(tr, "Host", v.Host)
			}
		}
	case "grpc":
		if v.Path != "" {
			tr["service_name"] = v.Path
		}
	}
}

func setHeader(tr map[string]any, k, val string) {
	h, _ := tr["headers"].(map[string]any)
	if h == nil {
		h = map[string]any{}
		tr["headers"] = h
	}
	h[k] = val
}

// ---------------------------------------------------------------------------
// shadowsocks
// ---------------------------------------------------------------------------

func parseShadowsocksLink(u *url.URL) (map[string]any, error) {
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	var method, password, plugin, pluginOpts string

	if u.User != nil {
		// SIP002: userinfo is base64(method:password)
		userInfo := decodeUserinfo(u.User.String())
		parts := strings.SplitN(userInfo, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("ss: invalid userinfo")
		}
		method, password = parts[0], parts[1]
	} else {
		return nil, fmt.Errorf("ss: missing userinfo")
	}

	if pluginParam := u.Query().Get("plugin"); pluginParam != "" {
		segs := strings.SplitN(pluginParam, ";", 2)
		plugin = segs[0]
		if len(segs) == 2 {
			pluginOpts = segs[1]
		}
		switch plugin {
		case "obfs-local", "simple-obfs":
			plugin, pluginOpts = "obfs-local", strings.TrimPrefix(pluginOpts, "obfs-local;")
		case "v2ray-plugin":
			plugin = "v2ray-plugin"
		case "shadow-tls":
			plugin = "shadow-tls"
		case "":
			plugin = ""
		default:
			return nil, fmt.Errorf("ss: unknown plugin %q", plugin)
		}
	}

	out := map[string]any{
		"type":        "shadowsocks",
		"server":      host,
		"server_port": port,
		"method":      method,
		"password":    password,
	}
	if plugin != "" {
		out["plugin"] = plugin
		if pluginOpts != "" {
			out["plugin_opts"] = pluginOpts
		}
	}
	return out, nil
}

func decodeUserinfo(s string) string {
	decoded, err := base64Decode(s)
	if err != nil {
		if unescaped, uerr := url.QueryUnescape(s); uerr == nil {
			return unescaped
		}
		return s
	}
	return string(decoded)
}

// ---------------------------------------------------------------------------
// trojan
// ---------------------------------------------------------------------------

func parseTrojan(u *url.URL) (map[string]any, error) {
	if u.User == nil || u.User.String() == "" {
		return nil, fmt.Errorf("trojan: missing password")
	}
	password, err := url.QueryUnescape(u.User.String())
	if err != nil {
		password = u.User.String()
	}
	host, port, err2 := splitHostPort(u.Host)
	if err2 != nil {
		return nil, fmt.Errorf("trojan: %w", err2)
	}
	q := u.Query()

	out := map[string]any{
		"type":        "trojan",
		"server":      host,
		"server_port": port,
		"password":    password,
	}
	// trojan implies TLS by default
	if q.Get("security") == "" {
		q.Set("security", "tls")
	}
	if tls := buildTLS(q, false); tls != nil {
		out["tls"] = tls
	}
	tr, terr := buildTransport(q.Get("type"), q)
	if terr != nil {
		return nil, terr
	}
	if tr != nil {
		out["transport"] = tr
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// hysteria2
// ---------------------------------------------------------------------------

func parseHysteria2(u *url.URL) (map[string]any, error) {
	auth := ""
	if u.User != nil {
		if escaped, err := url.QueryUnescape(u.User.String()); err == nil {
			auth = escaped
		} else {
			auth = u.User.String()
		}
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("hysteria2: %w", err)
	}
	q := u.Query()

	tls := map[string]any{"enabled": true}
	if q.Get("sni") != "" {
		tls["server_name"] = q.Get("sni")
	}
	if q.Get("insecure") == "1" || strings.EqualFold(q.Get("insecure"), "true") {
		tls["insecure"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	} else {
		tls["alpn"] = []string{"h3"}
	}
	if pin := q.Get("pinSHA256"); pin != "" {
		_ = pin // pinning is not supported yet, keep defaults
	}

	out := map[string]any{
		"type":        "hysteria2",
		"server":      host,
		"server_port": port,
		"tls":         tls,
	}
	if auth != "" {
		out["password"] = auth
	}
	if obfs := q.Get("obfs"); obfs != "" {
		out["obfs"] = map[string]any{
			"type":     obfs,
			"password": q.Get("obfs-password"),
		}
	}
	if ports := q.Get("mport"); ports != "" {
		var ranges []string
		for _, p := range strings.Split(ports, ",") {
			ranges = append(ranges, strings.ReplaceAll(p, "-", ":"))
		}
		out["server_ports"] = ranges
		if hop := q.Get("hop_interval"); hop != "" {
			out["hop_interval"] = normalizeMillis(hop)
		}
	}
	if up := q.Get("upmbps"); up != "" {
		if n, err := strconv.Atoi(up); err == nil && n > 0 {
			out["up_mbps"] = n
		}
	}
	if down := q.Get("downmbps"); down != "" {
		if n, err := strconv.Atoi(down); err == nil && n > 0 {
			out["down_mbps"] = n
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// tuic
// ---------------------------------------------------------------------------

func parseTUIC(u *url.URL) (map[string]any, error) {
	if u.User == nil {
		return nil, fmt.Errorf("tuic: missing credentials")
	}
	uuid := u.User.Username()
	password, _ := u.User.Password()
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	q := u.Query()

	tls := map[string]any{"enabled": true}
	if q.Get("sni") != "" {
		tls["server_name"] = q.Get("sni")
	}
	if q.Get("alpn") != "" {
		tls["alpn"] = strings.Split(q.Get("alpn"), ",")
	} else {
		tls["alpn"] = []string{"h3"}
	}
	if q.Get("allow_insecure") == "1" || strings.EqualFold(q.Get("disable_sni"), "true") {
		tls["insecure"] = true
	}

	out := map[string]any{
		"type":        "tuic",
		"server":      host,
		"server_port": port,
		"uuid":        uuid,
		"tls":         tls,
	}
	if password != "" {
		out["password"] = password
	}
	if cc := q.Get("congestion_control"); cc != "" {
		out["congestion_control"] = cc
	} else {
		out["congestion_control"] = "bbr"
	}
	if m := q.Get("udp_relay_mode"); m != "" {
		out["udp_relay_mode"] = m
	}
	return out, nil
}
