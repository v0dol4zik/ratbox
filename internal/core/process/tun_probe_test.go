package process

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
)

func TestObserveTUNBeforeDialCompletes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connections":[{"metadata":{"type":"tun/tun-in","sourcePort":"12345","destinationIP":"1.1.1.1","destinationPort":"80"}}]}`))
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// No dial result is ever produced: interception must be checked independently.
	if err := observeTUNProbe(ctx, clash.New(srv.URL, ""), "12345", make(chan error)); err != nil {
		t.Fatal(err)
	}
}

func TestObserveTUNDoesNotMatchAnotherConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"connections":[{"metadata":{"type":"mixed/mixed-in","sourcePort":"12345","destinationIP":"1.1.1.1","destinationPort":"80"}},{"metadata":{"type":"tun/tun-in","sourcePort":"54321","destinationIP":"1.1.1.1","destinationPort":"80"}}]}`))
	}))
	defer srv.Close()
	for _, connected := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		result := make(chan error, 1)
		if connected {
			result <- nil
		} else {
			result <- errors.New("dial timed out")
		}
		err := observeTUNProbe(ctx, clash.New(srv.URL, ""), "12345", result)
		cancel()
		if err == nil {
			t.Fatal("matched unrelated connection")
		}
		if connected && !strings.Contains(err.Error(), "probe connected") {
			t.Fatal(err)
		}
		if !connected && !strings.Contains(err.Error(), "inconclusive") {
			t.Fatal(err)
		}
	}
}
