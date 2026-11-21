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

func TestRenderNodesActiveBar(t *testing.T) {
	s := &store.Store{}
	s.Nodes = []*model.Node{
		{ID: "a", Tag: "Alpha", Outbound: json.RawMessage(`{"type":"vless","server":"1.2.3.4","server_port":443}`)},
		{ID: "b", Tag: "Beta", Outbound: json.RawMessage(`{"type":"trojan","server":"5.6.7.8","server_port":443}`)},
	}
	s.ActiveNodeID = "a"
	a := New(s, process.NewManager(process.Config{}))
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

func TestRenderNodesActiveBarWithCursor(t *testing.T) {
	s := &store.Store{}
	s.Nodes = []*model.Node{
		{ID: "a", Tag: "Alpha", Outbound: json.RawMessage(`{"type":"vless","server":"1.2.3.4","server_port":443}`)},
		{ID: "b", Tag: "Beta", Outbound: json.RawMessage(`{"type":"trojan","server":"5.6.7.8","server_port":443}`)},
	}
	s.ActiveNodeID = "b" // active away from the cursor: the bar must still render
	a := New(s, process.NewManager(process.Config{}))
	a.width, a.height = 80, 12
	a.nodeIdx = 0
	out := a.renderNodes(10)
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "Beta") {
			if !strings.Contains(line, "●") || lipgloss.Width(line) != 80 {
				t.Fatalf("the active row away from the cursor must keep the full-width bar: %q", line)
			}
			return
		}
	}
	t.Fatal("active row not rendered")
}
