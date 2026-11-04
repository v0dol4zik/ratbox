package process

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/model"
)

// A private user/network namespace contains a veth uplink and an HTTP proxy in
// a second network namespace. The destination 198.19.0.2 does not exist: only
// the fake proxy can serve it. Thus a successful download proves TUN -> node,
// not an accidental connection through the host's VPN. No host routes change.
func TestTUNNamespace(t *testing.T) {
	switch os.Getenv("RATBOX_NETNS_MODE") {
	case "proxy":
		serveNamespaceProxy(t)
		return
	case "client":
		testNamespaceClient(t)
		return
	}
	for _, tool := range []string{"unshare", "nsenter", "ip", "sh", "mount", "nft", "tc"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not installed")
		}
	}
	if err := exec.Command("unshare", "-Urn", "true").Run(); err != nil {
		t.Skip("user/network namespaces unavailable")
	}
	bin, err := exec.LookPath(sbPath(t))
	if err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, stack, firewall string }{
		{"default", "", ""},
		{"input_drop_mixed_stack", "mixed", "1"},
		{"input_drop_ratbox_default", "", "1"},
		{"input_drop_redirect_system", "redirect-system", "1"},
		{"loose_gvisor", "loose", ""},
		{"wan_gvisor", "", "wan"},
		{"wan_redirect_system", "redirect-system", "wan"},
	} {
		t.Run(tc.name, func(t *testing.T) { runTUNNamespace(t, self, bin, tc.stack, tc.firewall) })
	}
}

func runTUNNamespace(t *testing.T, self, bin, stack, firewall string) {
	dir := t.TempDir()
	script := `set -eu
mount --make-rprivate /
mount -t sysfs sysfs /sys
ip link set lo up
# A disconnected persistent TUN must not prevent ratbox from starting.
ip tuntap add dev throne-tun mode tun
ip link set throne-tun up
unshare -n sleep 60 & peer=$!
proxy=''
trap 'kill ${proxy:-} "$peer" 2>/dev/null || true; wait 2>/dev/null || true' EXIT
sleep 0.2
ip link add rb-up type veth peer name rb-peer
ip link set rb-peer netns "$peer"
ip addr add 198.18.0.1/24 dev rb-up
ip link set rb-up up
ip route add default via 198.18.0.2 dev rb-up
nsenter -t "$peer" -n ip link set lo up
nsenter -t "$peer" -n ip addr add 198.18.0.2/24 dev rb-peer
nsenter -t "$peer" -n ip link set rb-peer up
if [ "$RATBOX_NETNS_FIREWALL" = wan ]; then
 tc qdisc add dev rb-up root netem delay 25ms rate 20mbit
 nsenter -t "$peer" -n tc qdisc add dev rb-peer root netem delay 25ms rate 20mbit
fi
RATBOX_NETNS_MODE=proxy nsenter -t "$peer" -n "$SELF" -test.run '^TestTUNNamespace$' -test.v & proxy=$!
for i in $(seq 1 50); do [ ! -f "$READY" ] || break; sleep 0.1; done
[ -f "$READY" ]
if [ -n "$RATBOX_NETNS_FIREWALL" ]; then
 nft -f - <<'NFT'
table inet ratbox_test_filter {
 chain input {
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  ct state established,related accept
  iifname "ratbox0" counter drop
 }
}
NFT
fi
RATBOX_NETNS_MODE=client "$SELF" -test.run '^TestTUNNamespace$' -test.v
`
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-Urnm", "sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	cmd.Env = append(os.Environ(), "SELF="+self, "READY="+filepath.Join(dir, "ready"), "SING_BOX_BIN="+bin, "RATBOX_NETNS_STACK="+stack, "RATBOX_NETNS_FIREWALL="+firewall)
	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

const tunTestPayload = "ratbox-tun-proxy-path-verified"

func serveNamespaceProxy(t *testing.T) {
	ln, err := net.Listen("tcp", "198.18.0.2:18081")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if err := os.WriteFile(os.Getenv("READY"), []byte("ready"), 0600); err != nil {
		t.Fatal(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(10 * time.Second))
			br := bufio.NewReader(c)
			req, err := http.ReadRequest(br)
			if err != nil || req.Method != "CONNECT" || (req.Host != "198.19.0.2:18080" && req.Host != "[2001:db8::2]:18080" && req.Host != "1.1.1.1:80") {
				return
			}
			_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			request, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			body, err := io.ReadAll(io.LimitReader(request.Body, 4*1024*1024))
			request.Body.Close()
			if err != nil {
				return
			}
			if request.Method == http.MethodPost {
				// Echo the full body: the client verifies both directions byte for byte.
				_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
				_, _ = c.Write(body)
				return
			}
			_, _ = fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(tunTestPayload), tunTestPayload)
		}()
	}
}

func testNamespaceClient(t *testing.T) {
	mgr, err := NewTestManager(os.Getenv("SING_BOX_BIN"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	opts := StartOptions{Tun: true, TunStack: os.Getenv("RATBOX_NETNS_STACK"), ActiveTag: "fake-proxy", Nodes: []*model.Node{{Tag: "fake-proxy", Outbound: json.RawMessage(`{"type":"http","server":"198.18.0.2","server_port":18081}`)}}}
	if opts.TunStack == "redirect-system" {
		opts.TunStack, opts.TunAutoRedirect = "system", true
	}
	loose := opts.TunStack == "loose"
	if loose {
		opts.TunStack, opts.TunStrictRoute = "gvisor", &[]bool{false}[0]
	}
	if err := mgr.Start(opts); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = mgr.Stop()
		for _, l := range mgr.Logs() {
			t.Log(l)
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
		t.Fatal("API did not start")
	}
	out, err := exec.Command("ip", "route", "get", "198.19.0.2").CombinedOutput()
	t.Logf("route: %s", out)
	if err != nil || (!opts.TunAutoRedirect && !strings.Contains(string(out), "dev "+TunName)) {
		t.Fatalf("wrong route: %v", err)
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", TunName)); err != nil {
		t.Fatal("TUN is missing from namespace sysfs:", err)
	}
	if diagnostic := mgr.TUNRouteDiagnostic(); !opts.TunAutoRedirect && !strings.Contains(diagnostic, "via "+TunName) {
		t.Fatal(diagnostic)
	}
	if os.Getenv("RATBOX_NETNS_FIREWALL") != "" && opts.TunStack == "mixed" {
		tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
		defer tr.CloseIdleConnections()
		hc := &http.Client{Transport: tr, Timeout: time.Second}
		if resp, err := hc.Get("http://198.19.0.2:18080/"); err == nil {
			resp.Body.Close()
			t.Fatal("expected mixed stack TCP to be blocked by INPUT drop")
		}
		out, err := exec.Command("nft", "list", "chain", "inet", "ratbox_test_filter", "input").CombinedOutput()
		if err != nil || !regexp.MustCompile(`iifname "ratbox0" counter packets [1-9][0-9]* bytes`).Match(out) {
			t.Fatalf("timeout without proof of INPUT drops: %s (%v)", out, err)
		}
		t.Logf("reproduced: mixed TUN TCP blocked with INPUT drop: %s", out)
		return
	}
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 3*time.Second)
	probeErr := VerifyTUNIngress(probeCtx, api)
	cancelProbe()
	if probeErr != nil {
		t.Fatal("ingress probe:", probeErr)
	}
	tr := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
	resp, err := hc.Get("http://198.19.0.2:18080/")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != tunTestPayload {
		t.Fatalf("TUN payload %q err=%v", b, err)
	}
	// IPv6 must traverse the same TUN even though the uplink is IPv4-only.
	resp6, err := hc.Get("http://[2001:db8::2]:18080/")
	if err != nil {
		t.Fatal("IPv6 TUN:", err)
	}
	body6, err := io.ReadAll(resp6.Body)
	resp6.Body.Close()
	if err != nil || string(body6) != tunTestPayload {
		t.Fatalf("IPv6 payload: %q (%v)", body6, err)
	}
	// Small messages alone do not establish that media uploads work. Send
	// and echo two MiB with non-constant bytes on IPv4 and IPv6 through TUN.
	payload := make([]byte, 2*1024*1024)
	for i := range payload {
		payload[i] = byte((i*31 + i/251) % 256)
	}
	for _, destination := range []string{"http://198.19.0.2:18080/upload", "http://[2001:db8::2]:18080/upload"} {
		before, err := api.Traffic()
		if err != nil {
			t.Fatal(err)
		}
		started := time.Now()
		resp, err := hc.Post(destination, "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			t.Fatal("bulk TUN upload:", err)
		}
		echo, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(echo, payload) {
			t.Fatalf("bulk TUN echo: status=%d len=%d hash=%x err=%v", resp.StatusCode, len(echo), sha256.Sum256(echo), err)
		}
		after, err := api.Traffic()
		if err != nil || after.UploadTotal-before.UploadTotal < int64(len(payload)) || after.DownloadTotal-before.DownloadTotal < int64(len(payload)) {
			t.Fatalf("bulk TUN counters: before=%+v after=%+v err=%v", before, after, err)
		}
		t.Logf("bulk TUN %s: uploaded and echoed %d bytes in %v", destination, len(payload), time.Since(started))
	}
	stats, err := api.Traffic()
	t.Logf("TUN traffic: %+v err=%v", stats, err)
	if err != nil || stats.DownloadTotal < int64(len(b)) {
		t.Fatalf("TUN traffic not counted: %+v (%v)", stats, err)
	}
	if err := mgr.Stop(); err != nil {
		t.Fatal(err)
	}
	if opts.TunAutoRedirect {
		out, err := exec.Command("nft", "list", "tables").CombinedOutput()
		if err != nil || strings.Contains(string(out), "table inet sing-box") {
			t.Fatalf("redirect nft table remains after stop: %s (%v)", out, err)
		}
	}
	if _, err := os.Stat(filepath.Join("/sys/class/net", TunName)); !os.IsNotExist(err) {
		t.Fatal("TUN interface remains after clean stop")
	}
	for _, family := range []string{"-4", "-6"} {
		rules, err := exec.Command("ip", family, "rule", "show").CombinedOutput()
		if err != nil || strings.Contains(string(rules), "12334") || strings.Contains(string(rules), TunName) {
			t.Fatalf("rules remain after stop (%s): %s (%v)", family, rules, err)
		}
	}
	// Without ratbox the fake destination must not become accessible directly.
	if resp, err := hc.Get("http://198.19.0.2:18080/"); err == nil {
		resp.Body.Close()
		t.Fatal("destination is accessible without TUN: invalid test topology")
	}
	// Repeated start must work without rebooting or clearing routing tables.
	if err := mgr.Start(opts); err != nil {
		t.Fatal("restart:", err)
	}
	api = clash.New(mgr.Controller(), mgr.Secret())
	ready = false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if _, err := api.Version(); err == nil {
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		t.Fatal("API did not restart")
	}
	resp, err = hc.Get("http://198.19.0.2:18080/")
	if err != nil {
		t.Fatal("TUN after restart:", err)
	}
	b, err = io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(b) != tunTestPayload {
		t.Fatalf("restart payload: %q (%v)", b, err)
	}
}
