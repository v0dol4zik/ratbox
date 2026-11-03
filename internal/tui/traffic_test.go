package tui

import (
	"testing"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/store"
)

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

func TestResetTraffic(t *testing.T) {
	a := New(&store.Store{}, process.NewManager(process.Config{}))
	a.traffic = clash.Traffic{DownloadTotal: 999}
	a.rateDown = 50
	a.resetClient()
	if a.traffic.DownloadTotal != 0 || a.rateDown != 0 || a.trafficEpoch != 1 {
		t.Fatal("session counters not reset")
	}
}
