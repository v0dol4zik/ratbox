package sub

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const fetchRealLink = "vless://uuid@1.2.3.4:443?type=tcp&security=tls#RealNode"

// fetchServer imitates a subscription panel that gates on the client
// User-Agent: unknown agents get HTTP 400 or a placeholder node, while a
// recognized identity receives the real list.
func fetchServer(t *testing.T, known []string, unknownStatus int, placeholder, real string) (*httptest.Server, *int32) {
	t.Helper()
	var requests int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&requests, 1)
		_ = count
		ua := strings.ToLower(r.Header.Get("User-Agent"))
		for _, token := range known {
			if strings.Contains(ua, token) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte(real))
				return
			}
		}
		if placeholder != "" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(placeholder))
			return
		}
		http.Error(w, "blocked", unknownStatus)
	}))
	t.Cleanup(srv.Close)
	return srv, &requests
}

func TestFetchAcceptsSingBoxIdentity(t *testing.T) {
	srv, requests := fetchServer(t, []string{"sing-box"}, 0, "", fetchRealLink)
	nodes, err := Fetch(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "RealNode" {
		t.Fatalf("nodes: %+v", nodes)
	}
	if atomic.LoadInt32(requests) != 1 {
		t.Fatalf("expected a single request, got %d", *requests)
	}
}

func TestFetchFallsThroughPlaceholderToRecognizedClient(t *testing.T) {
	// The placeholder every unknown client gets from the panel on the first
	// try: a vless link to 0.0.0.0:1 named "app not supported".
	placeholder := "vless://uuid@0.0.0.0:1?type=tcp#%D0%9F%D1%80%D0%B8%D0%BB%D0%BE%D0%B6%D0%B5%D0%BD%D0%B8%D0%B5%20%D0%BD%D0%B5%20%D0%BF%D0%BE%D0%B4%D0%B4%D0%B5%D1%80%D0%B6%D0%B8%D0%B2%D0%B0%D0%B5%D1%82%D1%81%D1%8F"
	srv, requests := fetchServer(t, []string{"v2rayng"}, 0, placeholder, fetchRealLink)
	nodes, err := Fetch(srv.URL, 5*time.Second, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Tag != "RealNode" {
		t.Fatalf("nodes: %+v", nodes)
	}
	if atomic.LoadInt32(requests) < 2 {
		t.Fatalf("expected fallback attempts, got %d", *requests)
	}
}

func TestFetchRejectsAllPlaceholderResponse(t *testing.T) {
	placeholder := "vless://uuid@0.0.0.0:1?type=tcp#Unsupported-app"
	srv, _ := fetchServer(t, nil, 0, placeholder, "")
	_, err := Fetch(srv.URL, 5*time.Second, "")
	if err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("expected a placeholder error, got %v", err)
	}
}

func TestFetchReportsBlockedStatus(t *testing.T) {
	srv, _ := fetchServer(t, nil, http.StatusBadRequest, "", "")
	_, err := Fetch(srv.URL, 5*time.Second, "")
	if err == nil || !strings.Contains(err.Error(), "http 400") {
		t.Fatalf("expected the blocked status, got %v", err)
	}
}

func TestFetchRedactsQueryTokens(t *testing.T) {
	redacted := redactURL("https://sub.example.test/token/abcd?secret=xyz")
	if strings.Contains(redacted, "secret=xyz") {
		t.Fatalf("token leaked: %s", redacted)
	}
	if !strings.HasPrefix(redacted, "sub.example.test") {
		t.Fatalf("host lost: %s", redacted)
	}
}

func TestPlaceholderParsing(table *testing.T) {
	table.Run("unspecified server", func(t *testing.T) {
		n, err := ParseLink(fetchRealLink)
		if err != nil {
			t.Fatal(err)
		}
		if isPlaceholderNode(n) {
			t.Fatal("real node misclassified as placeholder")
		}
	})
}

// Panels of the Marzban kind serve a full sing-box config to a sing-box
// client identity instead of share links.
const fetchConfigBody = `{
  "outbounds": [
    {"type": "selector", "tag": "ratbox", "outbounds": ["a", "b"]},
    {"type": "vless", "tag": "a", "server": "1.2.3.4", "server_port": 443, "uuid": "u"},
    {"type": "trojan", "tag": "b", "server": "5.6.7.8", "server_port": 443, "password": "p"},
    {"type": "direct", "tag": "direct"}
  ]
}`

func TestParseSingBoxConfigBody(t *testing.T) {
	nodes, err := ParseSubscriptionBody(fetchConfigBody)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 || nodes[0].Tag != "a" || nodes[1].Tag != "b" || nodes[0].Protocol != "vless" {
		t.Fatalf("nodes: %+v", nodes)
	}
}

func TestParseSingBoxConfigBase64Wrapped(t *testing.T) {
	wrapped := base64Std(fetchConfigBody)
	nodes, err := ParseSubscriptionBody(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes: %+v", nodes)
	}
}

func TestClashYAMLGetsNamedFormat(t *testing.T) {
	_, err := ParseSubscriptionBody("mixed-port: 7890\nproxies:\n  - name: x\n    type: ss\n")
	if err == nil || !strings.Contains(err.Error(), "clash yaml") {
		t.Fatalf("expected a clash yaml hint, got %v", err)
	}
}

func TestHTMLResponseGetsNamedFormat(t *testing.T) {
	_, err := ParseSubscriptionBody("<html><body>login required</body></html>")
	if err == nil || !strings.Contains(err.Error(), "html") {
		t.Fatalf("expected an html hint, got %v", err)
	}
}

func TestConfigWithoutProxiesFails(t *testing.T) {
	_, err := ParseSubscriptionBody(`{"outbounds":[{"type":"selector","tag":"s","outbounds":["direct"]},{"type":"direct","tag":"direct"}]}`)
	if err == nil || !strings.Contains(err.Error(), "no proxy outbounds") {
		t.Fatalf("expected the no-proxies error, got %v", err)
	}
}

func base64Std(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
