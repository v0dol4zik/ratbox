// Package model contains shared data structures used across ratbox.
package model

import (
	"encoding/json"
	"strconv"
)

// Node is a single proxy node imported from a subscription or a share link.
// Outbound keeps the ready-to-use sing-box outbound config as raw JSON,
// so no protocol-specific state leaks into the rest of the app.
type Node struct {
	ID       string          `json:"id"`
	Tag      string          `json:"tag"` // display name, used as outbound tag
	SubID    string          `json:"sub_id"`
	Protocol string          `json:"protocol"` // vless, vmess, ss, trojan, hysteria2, tuic
	Outbound json.RawMessage `json:"outbound"`
}

// outbound is a minimal decoded view of a sing-box outbound.
type outbound struct {
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// Type returns the outbound type (protocol name for sing-box).
func (n *Node) Type() string {
	var o outbound
	if err := json.Unmarshal(n.Outbound, &o); err != nil {
		return "?"
	}
	return o.Type
}

// Addr returns "host:port" for display purposes.
func (n *Node) Addr() string {
	var o outbound
	if err := json.Unmarshal(n.Outbound, &o); err != nil {
		return "?"
	}
	return o.Server + ":" + strconv.Itoa(o.ServerPort)
}
