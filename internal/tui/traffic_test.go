package tui

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/model"
	"github.com/v0dol4zik/ratbox/internal/store"
)

func TestNodesEqualIgnoresTags(t *testing.T) {
	mk := func(tag, server string) *model.Node {
		return &model.Node{ID: "x", Tag: tag, Outbound: json.RawMessage(`{"type":"vless","server":"` + server + `","uuid":"u"}`)}
	}
	a := []*model.Node{mk("Old name", "1.2.3.4"), mk("Two", "5.6.7.8")}
	b := []*model.Node{mk("New name", "1.2.3.4"), mk("Two!", "5.6.7.8")}
	if !nodesEqual(a, b) {
		t.Fatal("renamed nodes with identical outbounds must be equal")
	}
	c := []*model.Node{mk("x", "1.2.3.4"), mk("y", "9.9.9.9")}
	if nodesEqual(a, c) {
		t.Fatal("different servers must not be equal")
	}
	if nodesEqual(a, a[:1]) {
		t.Fatal("length mismatch must not be equal")
	}
}

func TestSubMetaView(t *testing.T) {
	fresh := &store.Subscription{TrafficTotal: 100 << 20, UploadTotal: 25 << 20, DownloadTotal: 25 << 20,
		ExpireUnix: time.Now().Add(30 * 24 * time.Hour).Unix(), LastUpdateUnix: time.Now().Add(-2 * time.Hour).Unix()}
	view := subMetaView(fresh)
	if !strings.Contains(view, "50.0 MB / 100.0 MB") || !strings.Contains(view, "upd 2h") {
		t.Fatalf("fresh view: %q", view)
	}
	nearly := &store.Subscription{TrafficTotal: 100, UploadTotal: 95, DownloadTotal: 0,
		ExpireUnix: time.Now().Add(24 * time.Hour).Unix()}
	if view := subMetaView(nearly); !strings.Contains(view, "1d left") {
		t.Fatalf("expiring view: %q", view)
	}
	expired := &store.Subscription{ExpireUnix: time.Now().Add(-time.Hour).Unix()}
	if view := subMetaView(expired); !strings.Contains(view, "expired") {
		t.Fatalf("expired view: %q", view)
	}
}

func TestAutoUpdateSchedulesOnlyWhenStale(t *testing.T) {
	a := New(&store.Store{}, process.NewManager(process.Config{}))
	if cmd := a.autoUpdateSubsCmd(); cmd != nil {
		t.Fatal("no subscriptions: nothing to refresh")
	}
	stale := time.Now().Add(-48 * time.Hour).Unix()
	a.store.Subs = []*store.Subscription{
		{ID: "stale", Name: "stale", URL: "https://stale.example.test", LastUpdateUnix: stale},
	}
	msg := runCmd(t, a.autoUpdateSubsCmd())
	if _, ok := msg.(autoSubsTickMsg); !ok {
		t.Fatalf("expected a tick message, got %T", msg)
	}
	freshSub := &store.Subscription{ID: "f", Name: "fresh", URL: "https://fresh.example.test",
		LastUpdateUnix: time.Now().Add(-time.Hour).Unix()}
	a.store.Subs = []*store.Subscription{freshSub}
	if cmd := a.autoUpdateSubsCmd(); cmd != nil {
		t.Fatal("a fresh subscription must not schedule a refresh")
	}
}

func runCmd(t *testing.T, cmd tea.Cmd) tea.Msg {
	t.Helper()
	if cmd == nil {
		t.Fatal("nil cmd")
	}
	return cmd()
}

func TestTrafficRate(t *testing.T) {
	for _, tt := range []struct {
		current, previous int64
		elapsed           time.Duration
		want              int64
	}{
		{500, 100, 2 * time.Second, 200},
		{500, 100, 500 * time.Millisecond, 800},
		{0, 500, time.Second, 0},
		{500, 100, 0, 0},
	} {
		if got := trafficRate(tt.current, tt.previous, tt.elapsed); got != tt.want {
			t.Errorf("trafficRate(%+v) = %d", tt, got)
		}
	}
}

func TestStaleTrafficTickIgnored(t *testing.T) {
	a := New(&store.Store{}, process.NewManager(process.Config{}))
	a.trafficEpoch = 2
	a.traffic = clash.Traffic{DownloadTotal: 1000}
	_, cmd := a.Update(trafficTickMsg{epoch: 1, traffic: clash.Traffic{DownloadTotal: 99999}})
	if cmd != nil || a.traffic.DownloadTotal != 1000 {
		t.Fatal("stale tick updated traffic or scheduled another timer")
	}
}

func TestTUNIngressMessages(t *testing.T) {
	a := New(&store.Store{}, process.NewManager(process.Config{}))
	a.running, a.trafficEpoch = true, 2
	a.tunIngress = "checking"
	a.Update(tunIngressMsg{epoch: 1, err: errors.New("old failure")})
	if a.tunIngress != "checking" {
		t.Fatal("stale probe changed state")
	}
	a.Update(tunIngressMsg{epoch: 2, err: errors.New("probe missing")})
	if a.tunIngress != "warning" || !a.statusErr {
		t.Fatal("missing warning")
	}
	a.Update(tunIngressMsg{epoch: 2})
	if a.tunIngress != "verified" {
		t.Fatal("missing verified state")
	}
}

func TestTUNUsesUpstreamLinuxLayout(t *testing.T) {
	a := New(&store.Store{TunMode: true}, process.NewManager(process.Config{}))
	opts := a.startOptions()
	if !opts.Tun || !opts.TunAutoRedirect || !opts.TunSystemSetup || opts.TunStack != "system" || opts.TunStrictRoute == nil || *opts.TunStrictRoute {
		t.Fatalf("incomplete Linux TUN layout: %+v", opts)
	}
	a.store.TunMode = false
	opts = a.startOptions()
	if opts.Tun || opts.TunAutoRedirect || opts.TunSystemSetup {
		t.Fatal("mixed must not change host networking")
	}
}

func TestResetTraffic(t *testing.T) {
	a := New(&store.Store{}, process.NewManager(process.Config{}))
	a.traffic = clash.Traffic{DownloadTotal: 999}
	a.rateDown = 50
	a.resetClient()
	if a.traffic.DownloadTotal != 0 || a.rateDown != 0 || a.trafficEpoch != 1 {
		t.Fatal("session counters not reset")
	}
}
