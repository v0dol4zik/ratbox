// Package store persists ratbox configuration: subscriptions, nodes and settings.
package store

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/v0dol4zik/ratbox/internal/model"
)

type Subscription struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	URL  string `json:"url"`
}

type Store struct {
	Version    int    `json:"version"`
	MixedPort  int    `json:"mixed_port"`
	TunMode    bool   `json:"tun_mode"`
	CoreBinary string `json:"core_binary"` // optional path to sing-box binary
	AutoStart  bool   `json:"autostart"`

	Subs         []*Subscription `json:"subs"`
	Nodes        []*model.Node   `json:"nodes"`
	ActiveNodeID string          `json:"active_node_id"`

	mu   sync.Mutex
	path string
}

const currentVersion = 1

func DefaultDirs() (dataDir, coreDir string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	dataDir = filepath.Join(home, ".local", "share", "ratbox")
	if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
		dataDir = filepath.Join(xdg, "ratbox")
	}
	return dataDir, filepath.Join(dataDir, "bin"), nil
}

func DefaultPath() (string, error) {
	dataDir, _, err := DefaultDirs()
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, "store.json"), nil
}

// Load opens (or creates) the store located at path.
func Load(path string) (*Store, error) {
	s := &Store{path: path, Version: currentVersion, MixedPort: 12334}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if err := s.Save(); err != nil {
				return nil, err
			}
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, fmt.Errorf("store: corrupted %s: %w", path, err)
	}
	if s.MixedPort == 0 {
		s.MixedPort = 12334
	}
	if s.Version == 0 {
		s.Version = currentVersion
	}
	return s, nil
}

// Save atomically writes the store file.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// AddSubscription adds a new subscription and its nodes.
func (s *Store) AddSubscription(name, subURL string, nodes []*model.Node) *Subscription {
	sub := &Subscription{ID: NewID(), Name: name, URL: subURL}
	if sub.Name == "" {
		sub.Name = "sub-" + sub.ID[:6]
	}
	s.Subs = append(s.Subs, sub)
	ReplaceSubNodes(s, sub, nodes)
	return sub
}

// ReplaceSubNodes removes all nodes of the subscription and appends new ones.
func ReplaceSubNodes(s *Store, sub *Subscription, nodes []*model.Node) {
	kept := s.Nodes[:0]
	for _, n := range s.Nodes {
		if n.SubID != sub.ID {
			kept = append(kept, n)
		} else if n.ID == s.ActiveNodeID {
			s.ActiveNodeID = ""
		}
	}
	s.Nodes = kept
	for _, n := range nodes {
		n.ID = NewID()
		n.SubID = sub.ID
		s.Nodes = append(s.Nodes, n)
	}
}

// RemoveSubscription deletes a subscription and its nodes.
func (s *Store) RemoveSubscription(id string) {
	var subs []*Subscription
	for _, sub := range s.Subs {
		if sub.ID == id {
			continue
		}
		subs = append(subs, sub)
	}
	s.Subs = subs
	var nodes []*model.Node
	for _, n := range s.Nodes {
		if n.SubID != id {
			nodes = append(nodes, n)
		} else if n.ID == s.ActiveNodeID {
			s.ActiveNodeID = ""
		}
	}
	s.Nodes = nodes
}

// RemoveNode removes a node by id.
func (s *Store) RemoveNode(id string) {
	var nodes []*model.Node
	for _, n := range s.Nodes {
		if n.ID != id {
			nodes = append(nodes, n)
		} else if n.ID == s.ActiveNodeID {
			s.ActiveNodeID = ""
		}
	}
	s.Nodes = nodes
}

func (s *Store) Node(id string) *model.Node {
	for _, n := range s.Nodes {
		if n.ID == id {
			return n
		}
	}
	return nil
}

func (s *Store) Sub(id string) *Subscription {
	for _, sub := range s.Subs {
		if sub.ID == id {
			return sub
		}
	}
	return nil
}

func (s *Store) SubName(id string) string {
	if sub := s.Sub(id); sub != nil {
		return sub.Name
	}
	return "manual"
}

// UniqueTag fixes duplicates so every node tag is a unique outbound tag.
func (s *Store) UniqueTag(tag string) string {
	seen := make(map[string]bool)
	for _, n := range s.Nodes {
		seen[n.Tag] = true
	}
	if !seen[tag] {
		return tag
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s #%d", tag, i)
		if !seen[candidate] {
			return candidate
		}
	}
}

func (s *Store) NodesOfSub(id string) []*model.Node {
	var out []*model.Node
	for _, n := range s.Nodes {
		if n.SubID == id {
			out = append(out, n)
		}
	}
	return out
}
