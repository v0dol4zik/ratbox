package process

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	opts := StartOptions{Tun: true, Nodes: st.Nodes, TunStack: os.Getenv("RATBOX_TUN_STACK")}
	if n := st.Node(st.ActiveNodeID); n != nil {
		opts.ActiveTag = n.Tag
	}
	if tag := os.Getenv("RATBOX_TEST_NODE"); tag != "" {
		found := false
		for _, n := range st.Nodes {
			if n.Tag == tag {
				opts.ActiveTag, found = tag, true
				break
			}
		}
		if !found {
			t.Fatal("RATBOX_TEST_NODE not found")
		}
	}
	t.Logf("testing node %q, stack %q (store is read-only)", opts.ActiveTag, opts.TunStack)
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
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	probeErr := VerifyTUNIngress(probeCtx, api)
	probeCancel()
	if probeErr != nil {
		t.Errorf("ingress: %v", probeErr)
	}
	stats()
	before, err := api.Traffic()
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 10 * time.Second}
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", mgr.cfg.MixedPort))
	proxyTransport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
	defer proxyTransport.CloseIdleConnections()
	proxyClient := &http.Client{Transport: proxyTransport, Timeout: 10 * time.Second}
	for _, u := range []string{"http://1.1.1.1/cdn-cgi/trace", "https://www.gstatic.com/generate_204"} {
		start := time.Now()
		pr, pe := proxyClient.Get(u)
		if pe != nil {
			t.Logf("mixed %s: %v after %v", u, pe, time.Since(start))
		} else {
			body, readErr := io.ReadAll(io.LimitReader(pr.Body, 4096))
			pr.Body.Close()
			t.Logf("mixed %s: HTTP %d in %v, body=%s err=%v", u, pr.StatusCode, time.Since(start), body, readErr)
		}
		before, _ = api.Traffic()
		start = time.Now()
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
		t.Logf("TUN elapsed: %v", time.Since(start))
		stats()
		after, err := api.Traffic()
		if err != nil {
			t.Fatal(err)
		}
		if after.DownloadTotal <= before.DownloadTotal {
			t.Errorf("TUN request did not register in this core: before=%+v after=%+v; another client may be intercepting traffic", before, after)
		}
	}

	// Stage 2: bulk transfer + DNS through the running TUN itself. Tiny 204
	// checks do not reflect media browsing; measure a real 1 MiB POST/GET with
	// per-phase timings plus a resolver query, and mixed-path equivalents for
	// comparison. All bytes are locally generated, never user files.
	upload := filepath.Join(t.TempDir(), "up")
	if err := os.WriteFile(upload, make([]byte, 1024*1024), 0o600); err != nil {
		t.Fatal(err)
	}
	curlTiming := func(label, proxy string, args ...string) {
		base := []string{"--noproxy", "", "-sS", "--max-time", "20", "-o", "/dev/null",
			"-w", "%{http_code} dns=%{time_namelookup} tcp=%{time_connect} tls=%{time_appconnect} ttfb=%{time_starttransfer} total=%{time_total} down=%{speed_download} up=%{speed_upload}"}
		if proxy != "" {
			base = append(base, "--proxy", proxy)
		}
		start := time.Now()
		argv := append([]string{}, base...)
		argv = append(argv, args...)
		cmd := exec.Command("curl", argv...)
		out, err := cmd.CombinedOutput()
		t.Logf("%s: %s (%v, elapsed %v)", label, strings.TrimSpace(string(out)), err, time.Since(start))
	}
	mixed := fmt.Sprintf("http://127.0.0.1:%d", mgr.cfg.MixedPort)
	for _, path := range []struct{ label, proxy string }{
		{"tun", ""}, {"mixed", mixed},
	} {
		curlTiming("1MiB download/"+path.label, path.proxy, "https://speed.cloudflare.com/__down?bytes=1048576")
		curlTiming("1MiB upload/"+path.label, path.proxy, "-X", "POST", "--data-binary", "@"+upload, "https://speed.cloudflare.com/__up")
		curlTiming("popular site/"+path.label, path.proxy, "https://www.google.com/generate_204")
	}
	for _, host := range []string{"www.youtube.com", "github.com", "en.wikipedia.org", "www.cloudflare.com"} {
		start := time.Now()
		out, err := exec.Command("getent", "ahostsv4", host).CombinedOutput()
		t.Logf("dns %s via system resolver: %v (%v): %s", host, err, time.Since(start), strings.TrimSpace(string(out)))
	}
}
