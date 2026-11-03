package process

import (
	"strings"
	"testing"
)

func TestGrantScript(t *testing.T) {
	s := GrantScript("/usr/sbin/setcap", "/usr/local/bin/sing-box")
	for _, want := range []string{
		"cap_net_admin,cap_net_raw=ep",
		"'/usr/sbin/setcap' cap_net_admin,cap_net_raw=ep '/usr/local/bin/sing-box'",
		"echo ratbox-grant-ok",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
}

func TestShQuote(t *testing.T) {
	// "a b'c" must become 'a b'\''c' (POSIX single-quote escaping)
	want := "'a b'\\''c'"
	if got := shQuote("a b'c"); got != want {
		t.Errorf("shQuote = %q, want %q", got, want)
	}
}
