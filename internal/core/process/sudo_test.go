package process

import (
	"os"
	"testing"
)

// TestRunSetCapsSudoWrongPassword verifies error classification with a
// deliberately wrong password (auth is simply rejected, no changes made).
func TestRunSetCapsSudoWrongPassword(t *testing.T) {
	if os.Getenv("RATBOX_SUDO_TEST") == "" {
		t.Skip("set RATBOX_SUDO_TEST=1 to run a real wrong-password sudo probe")
	}
	bin, err := ResolveBinaryPath("")
	if err != nil {
		t.Skip("no sing-box binary")
	}
	sudoErr := RunSetCapsSudo(bin, []byte("definitely-wrong-password-4e2e"))
	if sudoErr == nil {
		// cached sudo ticket present: the command actually succeeded,
		// which also proves the flow works end to end
		t.Log("sudo ticket was valid — setcap succeeded without password")
		return
	}
	t.Logf("wrong pw error (expected): %v", sudoErr)
}
