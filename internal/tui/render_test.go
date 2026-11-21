package tui

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"

	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/model"
	"github.com/v0dol4zik/ratbox/internal/store"
)

func testNodes() []*model.Node {
	return []*model.Node{
		{ID: "a", Tag: "Alpha", Outbound: json.RawMessage(`{"type":"vless","server":"1.2.3.4","server_port":443}`)},
		{ID: "b", Tag: "Beta", Outbound: json.RawMessage(`{"type":"trojan","server":"5.6.7.8","server_port":443}`)},
	}
}

func testApp(nodes []*model.Node, activeID string) *App {
	s := &store.Store{Nodes: nodes, ActiveNodeID: activeID}
	return New(s, process.NewManager(process.Config{}))
}

func TestRenderNodesActiveBar(t *testing.T) {
	a := testApp(testNodes(), "a")
	a.running = true // the gray bar means "connected through this node now"
	a.width, a.height = 80, 12
	out := a.renderNodes(10)

	var activeLine string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "●") {
			activeLine = line
			break
		}
	}
	if activeLine == "" {
		t.Fatal("the active node row has no ● marker")
	}
	if !strings.Contains(activeLine, "Alpha") {
		t.Fatal("the active row does not show the node name")
	}
	if w := lipgloss.Width(activeLine); w != 80 {
		t.Fatalf("the active row bar must span the full width, got %d", w)
	}
	// inactive rows keep the compact layout (no full-width padding)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Beta") && lipgloss.Width(line) == 80 {
			t.Fatal("inactive rows must not be padded to the full width")
		}
	}
}

func TestRenderNodesCursorBarAlwaysVisible(t *testing.T) {
	a := testApp(testNodes(), "a")
	a.running = true
	a.width, a.height = 80, 12
	a.nodeIdx = 1 // cursor on Beta, away from the active Alpha
	out := a.renderNodes(10)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Beta") {
			if lipgloss.Width(line) != 80 {
				t.Fatalf("the cursor row must always be a full-width bar, got %d", lipgloss.Width(line))
			}
			return
		}
	}
	t.Fatal("cursor row not rendered")
}

func TestRenderNodesStoppedCoreHollowMarker(t *testing.T) {
	// After the VPN is stopped the remembered node must not keep its bar:
	// a lingering gray row reads as a stuck cursor. Only a quiet hollow ○.
	a := testApp(testNodes(), "a")
	a.running = false
	a.width, a.height = 80, 12
	a.nodeIdx = 1 // cursor on Beta: Alpha renders as a plain remembered row
	out := a.renderNodes(10)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Alpha") {
			if strings.Contains(line, "●") {
				t.Fatal("the filled marker must not render while the core is stopped")
			}
			if !strings.Contains(line, "○") {
				t.Fatal("the hollow remembered-node marker is missing")
			}
			if lipgloss.Width(line) == 80 {
				t.Fatal("a stopped core must not paint the full-width bar")
			}
			return
		}
	}
	t.Fatal("row missing")
}

func TestSweepSpinnerHidesResultsUntilDone(t *testing.T) {
	a := testApp(testNodes(), "a")
	a.width, a.height = 80, 12
	// a sweep is in flight: even the already-known latency stays hidden
	a.testing["Alpha"] = true
	a.testing["Beta"] = true
	a.latency["Alpha"] = 42
	a.spinFrame = 3
	out := a.renderNodes(10)
	if strings.Contains(out, "42") {
		t.Fatal("a stale latency leaked while the sweep is running")
	}
	if !strings.Contains(out, string(spinFrames[3])) {
		t.Fatal("the animated spinner frame is missing from the latency column")
	}
	// the sweep finished: the ticker is disarmed and results are revealed
	a.testing = map[string]bool{}
	out = a.renderNodes(10)
	if !strings.Contains(out, "42") {
		t.Fatal("latency results must appear once the whole sweep finished")
	}
}

func TestSpinTickerStopsWithoutWork(t *testing.T) {
	a := testApp(testNodes(), "")
	_, cmd := a.Update(spinTickMsg{})
	if cmd != nil {
		t.Fatal("the ticker must self-stop when nothing is in flight")
	}
	a.testing["Alpha"] = true
	_, cmd = a.Update(spinTickMsg{})
	if cmd == nil {
		t.Fatal("the ticker must continue while a sweep runs")
	}
	if a.spinFrame == 0 {
		t.Fatal("the spinner frame did not advance")
	}
}

func TestDelaySweepCompletionClearsTesting(t *testing.T) {
	a := testApp(testNodes(), "")
	a.testTotal, a.testDone = 2, 1
	a.testing["Alpha"] = true
	a.testing["Beta"] = true
	_, _ = a.Update(delayMsg{tag: "Beta", ms: 12})
	if len(a.testing) != 0 {
		t.Fatalf("the sweep must clear the spinner set once all nodes answered, left %v", a.testing)
	}
	if a.latency["Beta"] != 12 {
		t.Fatal("the result was not recorded")
	}
}
