package clash

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestConnections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connections" || r.Header.Get("Authorization") != "Bearer test" {
			t.Error("unexpected request")
		}
		_, _ = w.Write([]byte(`{"connections":[{"metadata":{"type":"tun/tun-in","sourcePort":"12345","destinationIP":"1.1.1.1","destinationPort":"80"}}]}`))
	}))
	defer srv.Close()
	c := New(srv.URL, "test")
	result, err := c.Connections(context.Background())
	if err != nil || len(result) != 1 {
		t.Fatalf("%+v %v", result, err)
	}
	m := result[0].Metadata
	if m.Type != "tun/tun-in" || m.SourcePort != "12345" || m.DestinationIP != "1.1.1.1" || m.DestinationPort != "80" {
		t.Fatalf("wrong metadata: %+v", m)
	}
}

func TestConnectionsDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := New(srv.URL, "").Connections(ctx); err == nil {
		t.Fatal("deadline ignored")
	}
}
