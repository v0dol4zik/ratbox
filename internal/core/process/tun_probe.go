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
// Keep an incomplete HTTP request open while polling for its exact source
// port in this core's connection table. No DNS, system proxy or downloaded
// payload is involved. Failure is a warning, never a reason to stop the core.
func VerifyTUNIngress(ctx context.Context, api *clash.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", "1.1.1.1:80")
	if err != nil {
		return fmt.Errorf("TUN ingress probe could not connect: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	port := strconv.Itoa(conn.LocalAddr().(*net.TCPAddr).Port)
	if _, err := conn.Write([]byte("GET /cdn-cgi/trace HTTP/1.1\r\nHost: 1.1.1.1\r\n")); err != nil {
		return fmt.Errorf("TUN ingress probe: %w", err)
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		connections, err := api.Connections(ctx)
		if err != nil {
			return fmt.Errorf("TUN ingress check unavailable: %w", err)
		}
		for _, c := range connections {
			m := c.Metadata
			if m.Type == "tun/tun-in" && m.SourcePort == port && m.DestinationIP == "1.1.1.1" && m.DestinationPort == "80" {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("TUN probe did not appear in ratbox; another VPN/firewall may intercept traffic")
		case <-tick.C:
		}
	}
}
