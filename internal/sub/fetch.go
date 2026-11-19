package sub

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/v0dol4zik/ratbox/internal/model"
)

// errEmptySubscription marks an authoritative "allowed but nothing to serve"
// response: the payload parsed, the service confirmed the request, and there
// were zero nodes. Retrying with another client identity cannot help, so the
// fetch loop stops and reports it.
var errEmptySubscription = errors.New("empty subscription")

// AppVersion is set by the binary so the User-Agent reflects the real build
// instead of a stale hardcoded string.
var AppVersion = "dev"

// Subscription panels commonly gate on the client User-Agent, often by
// prefix: an unknown agent gets a placeholder "app not supported" node
// (server 0.0.0.0:1) or an HTTP error instead of the real list. The first
// identity is a plain browser UA — the FlClash approach: panels rarely gate
// browsers and serve their default format (links/base64/yaml), which the
// parser accepts. Client identities follow for panels that format-switch by
// app; the order was verified against real Remnawave-style panels.
func clientUserAgents() []string {
	home := "github.com/v0dol4zik/ratbox"
	note := "; +" + home
	return []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"sing-box/1.14.4 (ratbox/" + AppVersion + note + ")",
		"SFM/2.0.8 (ratbox/" + AppVersion + note + ")",
		"singbox/1.11.0 (ratbox/" + AppVersion + note + ")",
		"v2rayNG/1.9.24 (ratbox/" + AppVersion + ")",
		"ClashMetaForAndroid/2.11.5 (ratbox/" + AppVersion + ")",
		"Karing/1.0.13.324 (ratbox/" + AppVersion + ")",
		"ClashforWindows/0.20.39 (ratbox/" + AppVersion + ")",
	}
}

// ErrDeviceIDRequired reports a panel that demands a device-id header
// (X-HWID) before serving the subscription. The caller generates a persistent
// random device id and retries once.
var ErrDeviceIDRequired = errors.New("device id required")

// deviceIDRequired detects the server-side wording observed in the wild
// ("Включите X-HWID в настройках клиента", "device id" variants).
func deviceIDRequired(body string) bool {
	b := strings.ToLower(body)
	return strings.Contains(b, "hwid") || strings.Contains(b, "id устройства") || strings.Contains(b, "device id")
}

// SubscriptionInfo carries the provider-side account state panels deliver
// in the subscription-userinfo response header (the FlClash/Throne
// convention: "upload=1; download=2; total=3; expire=1700000000").
type SubscriptionInfo struct {
	Upload   int64
	Download int64
	Total    int64
	Expire   int64 // unix seconds; 0 = unknown
}

// FetchResult is a successful subscription download.
type FetchResult struct {
	Nodes    []*model.Node
	Info     *SubscriptionInfo // nil when the service sends no userinfo header
	Filename string            // content-disposition filename, "" when absent
}

// Fetch downloads a subscription and parses its contents.
// The payload may be a base64-encoded list or plain text of share links.
// A non-empty proxyURL routes the download through the service channel
// so subscription updates survive a broken active node under tun.
// A non-empty deviceID is sent as the X-HWID header for panels that bind
// subscriptions to a device identifier.
func Fetch(subURL string, timeout time.Duration, proxyURL, deviceID string) ([]*model.Node, error) {
	res, err := FetchSub(subURL, timeout, proxyURL, deviceID)
	if err != nil {
		return nil, err
	}
	return res.Nodes, nil
}

// FetchSub is Fetch with the subscription metadata attached.
func FetchSub(subURL string, timeout time.Duration, proxyURL, deviceID string) (*FetchResult, error) {
	subURL = strings.TrimSpace(subURL)
	// Credentials in the url userinfo (https://user:pass@host/…) move to the
	// Authorization header — the FlClash pattern; the request url keeps no
	// userinfo so it never leaks into logs or errors.
	target, authHeader := splitSubCredentials(subURL)
	var lastErr error
	for _, ua := range clientUserAgents() {
		res, err := fetchOnce(target, timeout, proxyURL, ua, deviceID, authHeader)
		if errors.Is(err, ErrDeviceIDRequired) {
			return nil, fmt.Errorf("subscription: %w", ErrDeviceIDRequired)
		}
		if err != nil {
			if errors.Is(err, errEmptySubscription) {
				return nil, fmt.Errorf("subscription: the service accepted the request but served no nodes; check the subscription status on the provider's site")
			}
			lastErr = err
			continue
		}
		if placeholderNodes(res.Nodes) {
			lastErr = fmt.Errorf("subscription: %s served a placeholder (app-not-supported) node to every client identity", redactURL(subURL))
			continue
		}
		return res, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("subscription: no share links found")
	}
	return nil, lastErr
}

// splitSubCredentials extracts user:pass@ from the url into a Basic auth
// header. A token-only userinfo (https://token@host/) is sent as the user.
func splitSubCredentials(raw string) (target, authHeader string) {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw, ""
	}
	authHeader = "Basic " + base64.StdEncoding.EncodeToString([]byte(u.User.String()))
	u.User = nil
	return u.String(), authHeader
}

// redactURL keeps the host but drops query strings, which often carry tokens.
func redactURL(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host + u.Path
	}
	return raw
}

func fetchOnce(target string, timeout time.Duration, proxyURL, ua, deviceID, authHeader string) (*FetchResult, error) {
	transport := &http.Transport{}
	if proxyURL != "" {
		if pu, err := url.Parse(proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(pu)
		}
	}
	client := &http.Client{Timeout: timeout, Transport: transport}
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	if deviceID != "" {
		req.Header.Set("X-HWID", deviceID)
	}
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if resp.StatusCode == http.StatusBadRequest && deviceIDRequired(string(body)) {
			return nil, ErrDeviceIDRequired
		}
		// Short plain-text explanations ("Достигнут лимит устройств…") are
		// more useful than a bare status code; structured payloads stay hidden.
		if s := strings.TrimSpace(string(body)); s != "" && len(s) <= 200 && !strings.ContainsAny(s, "{}<") {
			return nil, fmt.Errorf("subscription: http %d: %s", resp.StatusCode, strings.ReplaceAll(s, "\n", " "))
		}
		return nil, fmt.Errorf("subscription: http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	nodes, err := ParseSubscriptionBody(string(body))
	if err != nil {
		return nil, err
	}
	return &FetchResult{
		Nodes:    nodes,
		Info:     parseSubscriptionUserInfo(resp.Header.Get("Subscription-Userinfo")),
		Filename: dispositionFilename(resp.Header.Get("Content-Disposition")),
	}, nil
}

// parseSubscriptionUserInfo parses "upload=1; download=2; total=3;
// expire=1700000000" into an info struct. Unknown or malformed fields are
// skipped rather than failing the whole header.
func parseSubscriptionUserInfo(h string) *SubscriptionInfo {
	if strings.TrimSpace(h) == "" {
		return nil
	}
	info := &SubscriptionInfo{}
	for _, field := range strings.Split(h, ";") {
		i := strings.Index(field, "=")
		if i < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(field[:i]))
		value, err := strconv.ParseInt(strings.TrimSpace(field[i+1:]), 10, 64)
		if err != nil || value < 0 {
			continue
		}
		switch key {
		case "upload":
			info.Upload = value
		case "download":
			info.Download = value
		case "total":
			info.Total = value
		case "expire":
			info.Expire = value
		}
	}
	if info.Upload == 0 && info.Download == 0 && info.Total == 0 && info.Expire == 0 {
		return nil
	}
	return info
}

// dispositionFilename extracts a usable name from a content-disposition
// header ("attachment; filename=\"name\"" or filename*=UTF-8”name).
func dispositionFilename(h string) string {
	if h == "" {
		return ""
	}
	if i := strings.Index(h, "filename*="); i >= 0 {
		s := strings.TrimSpace(h[i+len("filename*="):])
		if j := strings.Index(s, "''"); j >= 0 {
			s = s[j+2:]
		}
		s = strings.Trim(strings.SplitN(s, ";", 2)[0], `"`)
		if un, err := url.QueryUnescape(s); err == nil {
			return strings.TrimSpace(un)
		}
		return s
	}
	if i := strings.Index(h, "filename="); i >= 0 {
		s := strings.TrimSpace(h[i+len("filename="):])
		s = strings.Trim(strings.SplitN(s, ";", 2)[0], `"`)
		return strings.TrimSpace(s)
	}
	return ""
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
		if content == "" {
			return nil, fmt.Errorf("subscription: empty response: %w", errEmptySubscription)
		}
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
	// sing-box supports a fixed transport set; panels occasionally mix in
	// xray-only transports (xhttp) that make the core reject the whole config.
	supportedTransport := map[string]bool{"http": true, "ws": true, "grpc": true, "quic": true, "httpupgrade": true}
	var nodes []*model.Node
	for _, raw := range cfg.Outbounds {
		var o struct {
			Type      string `json:"type"`
			Tag       string `json:"tag"`
			Transport *struct {
				Type string `json:"type"`
			} `json:"transport"`
		}
		if err := json.Unmarshal(raw, &o); err != nil || o.Tag == "" || nonProxy[o.Type] {
			continue
		}
		if o.Transport != nil && !supportedTransport[o.Transport.Type] {
			continue
		}
		nodes = append(nodes, &model.Node{Tag: o.Tag, Protocol: o.Type, Outbound: raw})
	}
	if len(nodes) == 0 {
		return nil, true, fmt.Errorf("subscription: sing-box config contains no proxy outbounds: %w", errEmptySubscription)
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
	// clash configs appear both as yaml and as json (a json document is
	// valid yaml; panels of this kind serve json-shaped clash payloads)
	if strings.HasPrefix(s, "{") && strings.Contains(s, "\"proxies\"") {
		return true
	}
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
