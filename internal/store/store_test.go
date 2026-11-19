package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFreshStoreAutoStarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "store.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.AutoStart {
		t.Fatal("a fresh install must connect automatically (Throne-like)")
	}
}

func TestExistingStoreKeepsAutoStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "store.json")
	s, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	s.AutoStart = false
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	s2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.AutoStart {
		t.Fatal("an existing store must keep its own autostart setting")
	}
}

func TestUpdateSubMeta(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	sub := s.AddSubscription("test", "https://example.test", nil)
	s.UpdateSubMeta(sub.ID, 100, 200, 300, 1700000000, 42)
	if sub.UploadTotal != 100 || sub.DownloadTotal != 200 || sub.TrafficTotal != 300 ||
		sub.ExpireUnix != 1700000000 || sub.LastUpdateUnix != 42 {
		t.Fatalf("meta not stored: %+v", sub)
	}
	s.UpdateSubMeta("missing", 1, 2, 3, 4, 5) // must not panic
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(string(data), `"traffic_total": 300`) {
		t.Fatal("meta not persisted")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
