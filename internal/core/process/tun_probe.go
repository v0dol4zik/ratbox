package process

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
)

// VerifyTUNIngress tests interception, not node speed or Internet reachability.
// Poll while dialing: some stacks wait for the outbound handshake before the
// client-side connect completes. A dial timeout alone cannot diagnose TUN.
func VerifyTUNIngress(ctx context.Context, api *clash.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// Reserve a source port so the connection can be identified before Dial
	// returns. The close/bind window can race; that becomes an inconclusive
	// diagnostic, never a reason to stop the core.
	reservation, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4zero})
	if err != nil {
		return fmt.Errorf("TUN check unavailable: reserve probe port: %w", err)
	}
	port := reservation.Addr().(*net.TCPAddr).Port
	_ = reservation.Close()
	result := make(chan error, 1)
	go func() {
		conn, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4zero, Port: port}}).DialContext(ctx, "tcp4", "1.1.1.1:80")
		if err != nil {
			result <- err
			return
		}
		defer conn.Close()
		if deadline, ok := ctx.Deadline(); ok {
			_ = conn.SetDeadline(deadline)
		}
		// Leave headers unfinished to keep the connection observable.
		_, err = conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\n"))
		result <- err
		<-ctx.Done()
	}()
	return observeTUNProbe(ctx, api, strconv.Itoa(port), result)
}

func observeTUNProbe(ctx context.Context, api *clash.Client, port string, dialResult <-chan error) error {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var dialErr error
	var connected bool
	for {
		connections, err := api.Connections(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("TUN ingress check unavailable: %w", err)
		}
		for _, c := range connections {
			m := c.Metadata
			if m.Type == "tun/tun-in" && m.SourcePort == port && m.DestinationIP == "1.1.1.1" && m.DestinationPort == "80" {
				return nil
			}
		}
		select {
		case err := <-dialResult:
			dialErr, connected = err, err == nil
			dialResult = nil
		case <-tick.C:
		case <-ctx.Done():
			return probeUnverified(connected, dialErr)
		}
	}
	return probeUnverified(connected, dialErr)
}

func probeUnverified(connected bool, dialErr error) error {
	if connected {
		return fmt.Errorf("TUN unverified: probe connected but was not observed in ratbox; check VPN/firewall interception (logs tab)")
	}
	if dialErr != nil {
		return fmt.Errorf("TUN check inconclusive: %v; inspect node errors and routing in logs", dialErr)
	}
	return fmt.Errorf("TUN check inconclusive: connection timed out; this alone does not identify a TUN or node failure (logs tab)")
}
