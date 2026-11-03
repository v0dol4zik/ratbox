package process

import (
	"strings"
	"testing"
)

func TestGrantScript(t *testing.T) {
	t.Setenv("USER", "testuser")
	s := GrantScript("/usr/sbin/setcap", "/usr/local/bin/sing-box")
	for _, want := range []string{
		"cap_net_admin,cap_net_raw=ep",
		"'/usr/local/bin/sing-box'",
		"49-ratbox-tun-dns.rules",
		`subject.user === "testuser"`,
		"org.freedesktop.resolve1.",
		"echo ratbox-grant-ok",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("script missing %q:\n%s", want, s)
		}
	}
}

func TestValidIdent(t *testing.T) {
	for _, ok := range []string{"a", "d6xd", "some_user-1.x"} {
		if !validIdent(ok) {
			t.Errorf("validIdent(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "1abc", "имя", "a;b", strings.Repeat("a", 33)} {
		if validIdent(bad) {
			t.Errorf("validIdent(%q) = true, want false", bad)
		}
	}
}

func TestShQuote(t *testing.T) {
	if got := shQuote("a b'c"); got != `'a b'\''c'` {
		t.Errorf("shQuote = %q", got)
	}
}
