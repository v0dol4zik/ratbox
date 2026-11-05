package sub

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/v0dol4zik/ratbox/internal/model"
)

// Clash YAML subscriptions: many panels serve a `proxies:` list (mihomo/clash
// format) to clients they do not otherwise recognize. Convert each supported
// proxy into a sing-box outbound; the payload is parsed, never echoed.

type clashConfig struct {
	Proxies []clashProxy `yaml:"proxies"`
}

type clashProxy struct {
	Name         string         `yaml:"name"`
	Type         string         `yaml:"type"`
	Server       string         `yaml:"server"`
	Port         int            `yaml:"port"`
	Password     string         `yaml:"password"`
	UUID         string         `yaml:"uuid"`
	Cipher       string         `yaml:"cipher"`
	AlterID      *int           `yaml:"alterId"`
	Flow         string         `yaml:"flow"`
	Network      string         `yaml:"network"`
	TLS          bool           `yaml:"tls"`
	SNI          string         `yaml:"sni"`
	ServerName   string         `yaml:"servername"`
	SkipVerify   bool           `yaml:"skip-cert-verify"`
	Fingerprint  string         `yaml:"client-fingerprint"`
	ALPN         any            `yaml:"alpn"`
	Up           any            `yaml:"up"`
	Down         any            `yaml:"down"`
	Obfs         string         `yaml:"obfs"`
	ObfsPassword string         `yaml:"obfs-password"`
	Plugin       string         `yaml:"plugin"`
	WS           *clashWSOpts   `yaml:"ws-opts"`
	GRPC         *clashGRPCOpts `yaml:"grpc-opts"`
	Reality      *struct {
		PublicKey string `yaml:"public-key"`
		ShortID   string `yaml:"short-id"`
	} `yaml:"reality-opts"`
	Congestion   string `yaml:"congestion-controller"`
	UDPRelayMode string `yaml:"udp-relay-mode"`

	PluginOpts *clashPluginOpts `yaml:"plugin-opts"`
}

type clashPluginOpts struct {
	Mode     string `yaml:"mode"`
	Host     string `yaml:"host"`
	Path     string `yaml:"path"`
	Password string `yaml:"password"`
	TLS      bool   `yaml:"tls"`
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
}

type clashGRPCOpts struct {
	ServiceName string `yaml:"grpc-service-name"`
}

// ParseClashYAML converts a clash/mihomo subscription into nodes.
func ParseClashYAML(body string) ([]*model.Node, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
		return nil, fmt.Errorf("subscription: invalid clash yaml: %v", err)
	}
	if len(cfg.Proxies) == 0 {
		return nil, fmt.Errorf("subscription: clash yaml contains no proxy entries: %w", errEmptySubscription)
	}
	var nodes []*model.Node
	for _, p := range cfg.Proxies {
		out, err := p.outbound()
		if err != nil {
			continue
		}
		data, err := json.Marshal(out)
		if err != nil {
			continue
		}
		tag := p.Name
		if tag == "" {
			tag = fmt.Sprintf("%s:%d", p.Server, p.Port)
		}
		nodes = append(nodes, &model.Node{Tag: tag, Protocol: out["type"].(string), Outbound: data})
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription: clash yaml: 0 of %d proxies supported", len(cfg.Proxies))
	}
	return nodes, nil
}

func (p clashProxy) outbound() (map[string]any, error) {
	if p.Server == "" {
		return nil, fmt.Errorf("missing server")
	}
	if p.Port < 1 || p.Port > 65535 {
		return nil, fmt.Errorf("invalid port %d", p.Port)
	}
	base := map[string]any{"server": p.Server, "server_port": p.Port}
	switch strings.ToLower(p.Type) {
	case "ss":
		base["type"], base["method"], base["password"] = "shadowsocks", p.Cipher, p.Password
		plugin, opts, err := p.shadowsocksPlugin()
		if err != nil {
			return nil, err
		}
		if plugin != "" {
			base["plugin"] = plugin
			if opts != "" {
				base["plugin_opts"] = opts
			}
		}
	case "vmess":
		base["type"], base["uuid"] = "vmess", p.UUID
		security := p.Cipher
		if security == "" {
			security = "auto"
		}
		base["security"] = security
		base["alter_id"] = 0
		if p.AlterID != nil {
			base["alter_id"] = *p.AlterID
		}
		if tls, err := p.tlsBlock(); err != nil {
			return nil, err
		} else if tls != nil {
			base["tls"] = tls
		}
		if err := p.applyTransport(base); err != nil {
			return nil, err
		}
	case "vless":
		base["type"], base["uuid"], base["packet_encoding"] = "vless", p.UUID, "xudp"
		if p.Flow != "" {
			base["flow"] = p.Flow
		}
		if tls, err := p.tlsBlock(); err != nil {
			return nil, err
		} else if tls != nil {
			base["tls"] = tls
		}
		if err := p.applyTransport(base); err != nil {
			return nil, err
		}
	case "trojan":
		base["type"], base["password"] = "trojan", p.Password
		tls := map[string]any{"enabled": true, "server_name": p.tlsName()}
		if p.tlsName() == "" {
			tls["server_name"] = p.Server
		}
		p.decorateTLS(tls)
		base["tls"] = tls
		if err := p.applyTransport(base); err != nil {
			return nil, err
		}
	case "hysteria2", "hy2":
		base["type"], base["password"] = "hysteria2", p.Password
		tls := map[string]any{"enabled": true, "alpn": []string{"h3"}}
		if name := p.tlsName(); name != "" {
			tls["server_name"] = name
		}
		if p.SkipVerify {
			tls["insecure"] = true
		}
		base["tls"] = tls
		if p.Obfs != "" {
			base["obfs"] = map[string]any{"type": p.Obfs, "password": p.ObfsPassword}
		}
		if n := clashMbps(p.Up); n > 0 {
			base["up_mbps"] = n
		}
		if n := clashMbps(p.Down); n > 0 {
			base["down_mbps"] = n
		}
	case "tuic":
		base["type"], base["uuid"] = "tuic", p.UUID
		if p.Password != "" {
			base["password"] = p.Password
		}
		tls := map[string]any{"enabled": true, "server_name": p.Server}
		if name := p.tlsName(); name != "" {
			tls["server_name"] = name
		}
		if alpn := clashStringList(p.ALPN); len(alpn) > 0 {
			tls["alpn"] = alpn
		} else {
			tls["alpn"] = []string{"h3"}
		}
		if p.SkipVerify {
			tls["insecure"] = true
		}
		base["tls"] = tls
		if p.Congestion != "" {
			base["congestion_control"] = p.Congestion
		} else {
			base["congestion_control"] = "bbr"
		}
		if p.UDPRelayMode != "" {
			base["udp_relay_mode"] = p.UDPRelayMode
		}
	default:
		return nil, fmt.Errorf("unsupported clash proxy type %q", p.Type)
	}
	return base, nil
}

func (p clashProxy) tlsName() string {
	if p.SNI != "" {
		return p.SNI
	}
	return p.ServerName
}

func (p clashProxy) tlsBlock() (map[string]any, error) {
	if !p.TLS && p.Reality == nil {
		return nil, nil
	}
	tls := map[string]any{"enabled": true}
	if name := p.tlsName(); name != "" {
		tls["server_name"] = name
	}
	if alpn := clashStringList(p.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if p.SkipVerify {
		tls["insecure"] = true
	}
	if p.Fingerprint != "" || p.Reality != nil {
		fp := p.Fingerprint
		if fp == "" {
			fp = "chrome"
		}
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	if p.Reality != nil {
		reality := map[string]any{"enabled": true}
		if p.Reality.PublicKey != "" {
			reality["public_key"] = p.Reality.PublicKey
		}
		if p.Reality.ShortID != "" {
			reality["short_id"] = p.Reality.ShortID
		}
		tls["reality"] = reality
	}
	return tls, nil
}

func (p clashProxy) decorateTLS(tls map[string]any) {
	if alpn := clashStringList(p.ALPN); len(alpn) > 0 {
		tls["alpn"] = alpn
	}
	if p.Fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": p.Fingerprint}
	}
}

func (p clashProxy) applyTransport(base map[string]any) error {
	network := strings.ToLower(p.Network)
	if network == "" || network == "tcp" {
		return nil
	}
	switch network {
	case "ws", "httpupgrade":
		tr := map[string]any{"type": network, "path": "/"}
		if p.WS != nil {
			if p.WS.Path != "" {
				tr["path"] = p.WS.Path
			}
			if host := p.WS.Headers["Host"]; host != "" {
				setHeader(tr, "Host", host)
			}
		}
		base["transport"] = tr
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if p.GRPC != nil && p.GRPC.ServiceName != "" {
			tr["service_name"] = p.GRPC.ServiceName
		}
		base["transport"] = tr
	case "http", "h2":
		tr := map[string]any{"type": "http"}
		if p.WS != nil {
			if p.WS.Path != "" {
				tr["path"] = p.WS.Path
			}
			if host := p.WS.Headers["Host"]; host != "" {
				tr["host"] = []string{host}
			}
		}
		base["transport"] = tr
	default:
		return fmt.Errorf("unsupported clash network %q", p.Network)
	}
	return nil
}

// shadowsocksPlugin maps SIP003-style clash plugins onto sing-box plugin
// options. Unknown plugins yield an error so the node is skipped instead of
// importing a proxy that cannot connect.
func (p clashProxy) shadowsocksPlugin() (name, opts string, err error) {
	if p.Plugin == "" {
		return "", "", nil
	}
	o := p.PluginOpts
	switch p.Plugin {
	case "obfs", "obfs-local", "simple-obfs":
		var parts []string
		if o != nil {
			if o.Mode != "" {
				parts = append(parts, "obfs="+o.Mode)
			}
			if o.Host != "" {
				parts = append(parts, "obfs-host="+o.Host)
			}
		}
		return "obfs-local", strings.Join(parts, ";"), nil
	case "v2ray-plugin":
		mode := "websocket"
		if o != nil && o.Mode != "" {
			mode = o.Mode
		}
		parts := []string{"mode=" + mode}
		if o != nil {
			if o.TLS {
				parts = append(parts, "tls")
			}
			if o.Host != "" {
				parts = append(parts, "host="+o.Host)
			}
			if o.Path != "" {
				parts = append(parts, "path="+o.Path)
			}
		}
		return "v2ray-plugin", strings.Join(parts, ";"), nil
	default:
		return "", "", fmt.Errorf("unsupported clash plugin %q", p.Plugin)
	}
}

// clashStringList normalizes clash fields that may be a scalar or a list.
func clashStringList(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		var out []string
		for _, s := range strings.Split(t, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// clashMbps parses clash bandwidth values like 100, "100" or "100 Mbps".
func clashMbps(v any) int {
	switch t := v.(type) {
	case int:
		return t
	case float64:
		return int(t)
	case string:
		digits := ""
		for _, r := range t {
			if r >= '0' && r <= '9' {
				digits += string(r)
				continue
			}
			if digits != "" {
				break
			}
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			return 0
		}
		return n
	}
	return 0
}
