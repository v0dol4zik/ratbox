package process

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedirectPreflight(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"sudo", "nft", "resolvectl"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\nprintf '%s\\n' \"$RATBOX_TEST_TABLES\"\nexit \"${RATBOX_TEST_EXIT:-0}\"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("RATBOX_TEST_TABLES", "table inet sing-box")
	if err := preflightRedirect(); err == nil || !strings.Contains(err.Error(), "will not overwrite") {
		t.Fatal(err)
	}
	t.Setenv("RATBOX_TEST_TABLES", "table ip filter")
	if err := preflightRedirect(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RATBOX_TEST_EXIT", "1")
	if err := preflightRedirect(); !errors.Is(err, ErrTUNAdminRequired) {
		t.Fatalf("missing admin prompt: %v", err)
	}
}

func TestRedirectTableOwnership(t *testing.T) {
	for _, tc := range []struct {
		tables   string
		conflict bool
	}{
		{"table ip filter\ntable ip6 filter\n", false},
		{"table inet sing-box\n", true},
		{"table inet sing-box-other\n", false},
		{"table inet filter\ntable inet sing-box\n", true},
	} {
		err := checkRedirectTables(tc.tables)
		if (err != nil) != tc.conflict {
			t.Fatalf("%q: %v", tc.tables, err)
		}
	}
}

func TestBootstrapDNSParsing(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"Link 3 (wlan0): 192.168.1.1", "192.168.1.1"},
		{"Global: 127.0.0.53 0.0.0.0 9.9.9.9", "9.9.9.9"},
		{"Link 3 (wlan0): 2001:4860:4860::8888", "2001:4860:4860::8888"},
		{"127.0.0.53", ""},
	} {
		if got := firstDNSAddress(tc.input); got != tc.want {
			t.Fatalf("%q: %q != %q", tc.input, got, tc.want)
		}
	}
	dev, err := defaultUplink([]byte(`[{"dst":"default","dev":"wlan0"}]`))
	if err != nil || dev != "wlan0" {
		t.Fatalf("%q %v", dev, err)
	}
	if _, err := defaultUplink([]byte(`[{"dev":"ratbox0"}]`)); err == nil {
		t.Fatal("selected own TUN as bootstrap uplink")
	}
}

func TestForeignRulesAreOnlyHints(t *testing.T) {
	msg := tunForeignCapture("9001: from all fwmark 0x2023 lookup 2022")
	if !strings.Contains(msg, "do not prove capture") {
		t.Fatal("must not claim packet capture from rules alone:", msg)
	}
}
