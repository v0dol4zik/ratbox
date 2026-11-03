// Package clash is a minimal client for the sing-box clash api,
// used for node switching, latency tests and traffic stats.
package clash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const DefaultTestURL = "http://www.gstatic.com/generate_204"

type Client struct {
	baseURL string
	secret  string
	hc      *http.Client
}

func New(baseURL, secret string) *Client {
	return &Client{
		baseURL: baseURL,
		secret:  secret,
		hc:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Client) do(method, path string, body []byte) ([]byte, error) {
	return c.doContext(context.Background(), method, path, body)
}

func (c *Client) doContext(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return nil, err
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		var msg struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &msg)
		if msg.Message != "" {
			return nil, fmt.Errorf("clash api %s: http %d: %s", path, resp.StatusCode, msg.Message)
		}
		return nil, fmt.Errorf("clash api %s: http %d", path, resp.StatusCode)
	}
	return data, nil
}

type Proxy struct {
	Now  string `json:"now"`
	Type string `json:"type"`
}

// Proxies returns the proxy map from /proxies.
func (c *Client) Proxies() (map[string]Proxy, error) {
	data, err := c.do(http.MethodGet, "/proxies", nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Proxies map[string]Proxy `json:"proxies"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return res.Proxies, nil
}

// Select switches the selector group to the given node.
func (c *Client) Select(group, node string) error {
	body, err := json.Marshal(map[string]string{"name": node})
	if err != nil {
		return err
	}
	_, err = c.do(http.MethodPut, "/proxies/"+url.PathEscape(group), body)
	return err
}

type delayResult struct {
	Delay int `json:"delay"`
}

// Delay performs an urltest through the named proxy and returns the delay in ms.
func (c *Client) Delay(node string, timeout time.Duration, testURL string) (int, error) {
	if testURL == "" {
		testURL = DefaultTestURL
	}
	query := "?timeout=" + strconvMs(timeout) + "&url=" + url.QueryEscape(testURL)
	data, err := c.do(http.MethodGet, "/proxies/"+url.PathEscape(node)+"/delay"+query, nil)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", node, err)
	}
	var res delayResult
	if err := json.Unmarshal(data, &res); err != nil {
		return 0, err
	}
	return res.Delay, nil
}

// Connection identifies a live connection and the inbound that received it.
type Connection struct {
	Metadata struct {
		Type            string `json:"type"`
		SourcePort      string `json:"sourcePort"`
		DestinationIP   string `json:"destinationIP"`
		DestinationPort string `json:"destinationPort"`
	} `json:"metadata"`
}

func (c *Client) Connections(ctx context.Context) ([]Connection, error) {
	data, err := c.doContext(ctx, http.MethodGet, "/connections", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Connections []Connection `json:"connections"`
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result.Connections, nil
}

// Traffic holds cumulative counters from /connections, including closed connections.
type Traffic struct {
	DownloadTotal int64 `json:"downloadTotal"`
	UploadTotal   int64 `json:"uploadTotal"`
}

func (c *Client) Traffic() (Traffic, error) {
	data, err := c.do(http.MethodGet, "/connections", nil)
	if err != nil {
		return Traffic{}, err
	}
	var res Traffic
	if err := json.Unmarshal(data, &res); err != nil {
		return Traffic{}, err
	}
	return res, nil
}

func (c *Client) Version() (string, error) {
	data, err := c.do(http.MethodGet, "/version", nil)
	if err != nil {
		return "", err
	}
	var res struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return "", err
	}
	return res.Version, nil
}

func strconvMs(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return fmt.Sprintf("%d", ms)
}
