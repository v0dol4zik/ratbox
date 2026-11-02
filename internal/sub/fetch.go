package sub

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/v0dol4zik/ratbox/internal/model"
)

var supportedSchemes = []string{
	"vless", "vmess", "ss", "trojan", "hysteria2", "hy2", "tuic",
}

// Fetch downloads a subscription and parses its contents.
// The payload may be a base64-encoded list or plain text of share links.
func Fetch(subURL string, timeout time.Duration) ([]*model.Node, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodGet, strings.TrimSpace(subURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ratbox/0.1 (github.com/v0dol4zik/ratbox)")
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

// ParseSubscriptionBody parses a raw subscription payload.
func ParseSubscriptionBody(body string) ([]*model.Node, error) {
	content := strings.TrimSpace(body)
	// try base64 first (the most common case for raw subscriptions)
	if decoded, err := base64Decode(content); err == nil {
		if d := strings.TrimSpace(string(decoded)); looksLikeLinks(d) {
			content = d
		}
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
	if len(nodes) == 0 && errs == 0 {
		return nil, fmt.Errorf("subscription: no share links found")
	}
	return nodes, nil
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
	lines := 0
	for _, line := range strings.Split(s, "\n") {
		if isSupportedLink(line) {
			lines++
			if lines > 0 {
				return true
			}
		}
	}
	return false
}
