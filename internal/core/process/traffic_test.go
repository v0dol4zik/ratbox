package process

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/model"
)

// No external requests or TUN: prove the API retains closed-connection totals.
func TestTrafficTotalsSurviveConnectionClose(t *testing.T) {
	bin, err := exec.LookPath(sbPath(t))
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Repeat("x", 128*1024)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, payload)
	}))
	defer target.Close()
	port, err := freeLocalPort()
	if err != nil {
		t.Fatal(err)
	}
	mgr := NewManager(Config{Binary: bin, MixedPort: port, DataDir: t.TempDir()})
	err = mgr.Start(StartOptions{Nodes: []*model.Node{{Tag: "local-test", Outbound: json.RawMessage(`{"type":"direct"}`)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mgr.Stop(); err != nil {
			t.Error(err)
		}
	}()
	api := clash.New(mgr.Controller(), mgr.Secret())
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, err := api.Version(); err == nil {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("core API did not start")
	}
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(port))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != payload {
		t.Fatalf("download failed: %v (%d bytes)", err, len(body))
	}
	time.Sleep(100 * time.Millisecond)
	first, err := api.Traffic()
	if err != nil {
		t.Fatal(err)
	}
	if first.DownloadTotal < int64(len(payload)) {
		t.Fatalf("unaccounted download: %+v", first)
	}
	time.Sleep(100 * time.Millisecond)
	second, err := api.Traffic()
	if err != nil {
		t.Fatal(err)
	}
	if second.DownloadTotal < first.DownloadTotal {
		t.Fatalf("closed totals decreased: %+v -> %+v", first, second)
	}
}
