package process

import (
	"context"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/store"
)

// Explicit opt-in: temporarily changes host routing. Reads the store, never saves it.
func TestLiveTUN(t *testing.T) {
	if os.Getenv("RATBOX_TUN_TEST") != "1" {
		t.Skip("set RATBOX_TUN_TEST=1 for host TUN diagnostics")
	}
	path, err := store.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	opts := StartOptions{Tun: true, Nodes: st.Nodes}
	if n := st.Node(st.ActiveNodeID); n != nil {
		opts.ActiveTag = n.Tag
	}
	if st.ActiveSubID != "" {
		opts.Nodes = nil
		for _, n := range st.Nodes {
			if n.SubID == st.ActiveSubID || n.SubID == "" {
				opts.Nodes = append(opts.Nodes, n)
			}
		}
	}
	mgr, err := NewTestManager(st.CoreBinary, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(opts); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := mgr.Stop(); err != nil {
			t.Error(err)
		}
		for _, l := range mgr.Logs() {
			t.Log(l)
		}
	}()
	api := clash.New(mgr.Controller(), mgr.Secret())
	ready := false
	for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
		if _, err := api.Version(); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		t.Fatal("API not ready")
	}
	for _, args := range [][]string{{"route", "get", "1.1.1.1"}, {"rule", "show"}, {"route", "show", "table", "12334"}} {
		out, err := exec.Command("ip", args...).CombinedOutput()
		t.Logf("ip %v: %s (%v)", args, out, err)
	}
	stats := func() {
		for _, name := range []string{"rx_bytes", "tx_bytes"} {
			b, _ := os.ReadFile(filepath.Join("/sys/class/net", TunName, "statistics", name))
			t.Logf("%s=%s", name, b)
		}
		s, e := api.Traffic()
		t.Logf("API totals %+v (%v)", s, e)
	}
	stats()
	before, err := api.Traffic()
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	for _, u := range []string{"http://1.1.1.1/cdn-cgi/trace", "https://www.gstatic.com/generate_204"} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := hc.Do(req)
		if err != nil {
			t.Errorf("%s: %v", u, err)
		} else {
			b, e := io.ReadAll(io.LimitReader(resp.Body, 4096))
			resp.Body.Close()
			t.Logf("%s: %d body=%s err=%v", u, resp.StatusCode, b, e)
		}
		cancel()
		stats()
	}
	after, err := api.Traffic()
	if err != nil {
		t.Fatal(err)
	}
	if after.DownloadTotal <= before.DownloadTotal {
		t.Fatalf("requests did not register in this core: before=%+v after=%+v; another client may be intercepting traffic", before, after)
	}
}
