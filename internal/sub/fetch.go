package sub

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/v0dol4zik/ratbox/internal/model"
)

// AppVersion is set by the binary so the User-Agent reflects the real build
// instead of a stale hardcoded string.
var AppVersion = "dev"

// Subscription panels commonly gate on the client User-Agent: an unknown agent
// gets a placeholder "app not supported" node (server 0.0.0.0:1) or an HTTP
// error instead of the real list. Request with recognized client identities in
// order and use the first response that yields real nodes. The first entry is
// truthful: ratbox routes everything through a real sing-box core.
func clientUserAgents() []string {
	home := "github.com/v0dol4zik/ratbox"
	return []string{
		"sing-box/1.14.4 (ratbox/" + AppVersion + "; +" + home + ")",
		"v2rayNG/1.9.24 (ratbox/" + AppVersion + ")",
		"clash.meta/1.19.13 (ratbox/" + AppVersion + ")",
	}
}

// Fetch downloads a subscription and parses its contents.
// The payload may be a base64-encoded list or plain text of share links.
// A non-empty proxyURL routes the download through the service channel
// so subscription updates survive a broken active node under tun.
func Fetch(subURL string, timeout time.Duration, proxyURL string) ([]*model.Node, error) {
	subURL = strings.TrimSpace(subURL)
	var lastErr error
	for _, ua := range clientUserAgents() {
		nodes, err := fetchOnce(subURL, timeout, proxyURL, ua)
		if err != nil {
			lastErr = err
			continue
		}
		if placeholderNodes(nodes) {
			lastErr = fmt.Errorf("subscription: %s served a placeholder (app-not-supported) node to every client identity", redactURL(subURL))
			continue
		}
		return nodes, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("subscription: no share links found")
	}
	return nil, lastErr
}

// redactURL keeps the host but drops query strings, which often carry tokens.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host + u.Path
	}
	return raw
}

func fetchOnce(subURL string, timeout time.Duration, proxyURL, ua string) ([]*model.Node, error) {
	transport := &http.Transport{}
	if proxyURL != "" {
		if pu, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	req, err := http.NewRequest(http.MethodGet, subURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("subscription: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return ParseSubscriptionBody(string(body))
}

// ParseSubscriptionBody parses a raw subscription payload: share links,
// base64 of them, or a full sing-box config some panels serve to a
// sing-box User-Agent.
func ParseSubscriptionBody(body string) ([]*model.Node, error) {
	content := strings.TrimSpace(body)
	// try base64 first (the most common case for raw subscriptions)
	if decoded, err := base64Decode(content); err == nil {
		if d := strings.TrimSpace(string(decoded)); recognizedPayload(d) {
			content = d
		}
	}
	if nodes, isConfig, err := parseSingBoxConfig(content); isConfig {
		return nodes, err
	}
	if looksLikeClashYAML(content) {
		return ParseClashYAML(content)
	}
	var (
		nodes []*model.Node
		errs  int
	)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if !isSupportedLink(line) {
			continue
		}
		node, err := ParseLink(line)
		if err != nil {
			errs++
			continue
		}
		nodes = append(nodes, node)
	}
	if len(nodes) == 0 && errs > 0 {
		return nil, fmt.Errorf("subscription: %d links failed to parse", errs)
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("subscription: %s", bodyFormatHint(content))
	}
	return nodes, nil
}

// parseSingBoxConfig extracts proxy outbounds from a full sing-box config
// JSON. Panels of the Marzban kind serve exactly this to a sing-box client
// identity, so it must become nodes instead of a parse failure. The second
// return reports whether the body was a config at all.
func parseSingBoxConfig(content string) ([]*model.Node, bool, error) {
	if !isSingBoxConfigText(content) {
		return nil, false, nil
	}
	var cfg struct {
		Outbounds []json.RawMessage `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		return nil, true, fmt.Errorf("subscription: invalid sing-box config: %v", err)
	}
	nonProxy := map[string]bool{"selector": true, "urltest": true, "direct": true, "block": true, "dns": true}
	var nodes []*model.Node
	for _, raw := range cfg.Outbounds {
		var o struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &o); err != nil || o.Tag == "" || nonProxy[o.Type] {
			continue
		}
		nodes = append(nodes, &model.Node{Tag: o.Tag, Protocol: o.Type, Outbound: raw})
	}
	if len(nodes) == 0 {
		return nil, true, fmt.Errorf("subscription: sing-box config contains no proxy outbounds")
	}
	return nodes, true, nil
}

func isSingBoxConfigText(s string) bool {
	return strings.HasPrefix(s, "{") && strings.Contains(s, "\"outbounds\"")
}

func recognizedPayload(s string) bool {
	return looksLikeLinks(s) || looksLikeClashYAML(s) || isSingBoxConfigText(s)
}

func looksLikeClashYAML(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "proxies:") {
			return true
		}
	}
	return false
}

// bodyFormatHint names the received format when no links were found, so the
// user sees what the panel actually served instead of a generic complaint.
// Never echo the body: payloads carry credentials.
func bodyFormatHint(content string) string {
	trimmed := strings.TrimSpace(content)
	switch {
	case strings.HasPrefix(trimmed, "<"):
		return "html response (likely an error or login page); check the url"
	case looksLikeClashYAML(trimmed):
		return "clash yaml could not be parsed; report it with the subscription url"
	case strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "["):
		return "json without proxy outbounds"
	case trimmed == "":
		return "empty response"
	default:
		return "no share links found"
	}
}

// placeholderNodes reports a response made entirely of "app not supported"
// filler nodes that panels send to user agents they refuse to recognize.
func placeholderNodes(nodes []*model.Node) bool {
	if len(nodes) == 0 {
		return false
	}
	for _, n := range nodes {
		if !isPlaceholderNode(n) {
			return false
		}
	}
	return true
}

func isPlaceholderNode(n *model.Node) bool {
	tag := strings.ToLower(n.Tag)
	if strings.Contains(tag, "unsupported") || strings.Contains(tag, "не поддерживается") {
		return true
	}
	var o struct {
		Server string `json:"server"`
	}
	if err := json.Unmarshal(n.Outbound, &o); err == nil {
		if ip := net.ParseIP(o.Server); ip != nil && (ip.IsUnspecified() || ip.IsLoopback()) {
			return true
		}
	}
	return false
}

var supportedSchemes = []string{
	"vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "tuic",
}

func isSupportedLink(line string) bool {
	low := strings.ToLower(line)
	for _, scheme := range supportedSchemes {
		if strings.HasPrefix(low, scheme+"://") {
			return true
		}
	}
	return false
}

func looksLikeLinks(s string) bool {
	for _, line := range strings.Split(s, "\n") {
		if isSupportedLink(line) {
			return true
		}
	}
	return false
}
