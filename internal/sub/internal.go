package sub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// buildTLS builds a sing-box tls block from common share link params.
// security: none|tls|reality (default "" => no tls unless defaultTLS).
func buildTLS(q url.Values, defaultTLS bool) map[string]any {
	security := strings.ToLower(q.Get("security"))
	if security == "" {
		if defaultTLS {
			security = "tls"
		} else {
			return nil
		}
	}
	switch security {
	case "none", "0":
		return nil
	case "tls", "reality":
	default:
		return nil
	}
	tls := map[string]any{"enabled": true}
	if sni := q.Get("sni"); sni != "" {
		tls["server_name"] = sni
	}
	if hdrHost := q.Get("host"); hdrHost != "" && q.Get("sni") == "" {
		tls["server_name"] = hdrHost
	}
	if insecure := q.Get("allowInsecure"); insecure == "1" ||
		strings.EqualFold(insecure, "true") ||
		strings.EqualFold(insecure, "insecure") {
		tls["insecure"] = true
	}
	if alpn := q.Get("alpn"); alpn != "" {
		var list []string
		for _, a := range strings.Split(alpn, ",") {
			if a = strings.TrimSpace(a); a != "" {
				list = append(list, a)
			}
		}
		if len(list) > 0 {
			tls["alpn"] = list
		}
	}
	if fp := q.Get("fp"); fp != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	} else if security == "reality" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
	}
	if security == "reality" {
		reality := map[string]any{"enabled": true}
		if pbk := q.Get("pbk"); pbk != "" {
			reality["public_key"] = pbk
		}
		if sid := q.Get("sid"); sid != "" {
			reality["short_id"] = sid
		}
		tls["reality"] = reality
	}
	return tls
}

// buildTransport builds a sing-box transport block.
// network: tcp|ws|grpc|http|httpupgrade|quic (others are ssh-based/xray-only
// and unsupported by the sing-box core).
func buildTransport(network string, q url.Values) (map[string]any, error) {
	network = strings.ToLower(network)
	if network == "" || network == "tcp" || network == "raw" {
		// http camouflage over tcp
		if q != nil && strings.EqualFold(q.Get("headerType"), "http") {
			tr := map[string]any{"type": "http"}
			if p := q.Get("path"); p != "" {
				tr["path"] = p
			}
			if h := q.Get("host"); h != "" {
				tr["host"] = []string{h}
			}
			return tr, nil
		}
		return nil, nil
	}
	switch network {
	case "ws", "httpupgrade":
		tr := map[string]any{"type": network}
		path := "/"
		if q != nil && q.Get("path") != "" {
			path = q.Get("path")
		}
		tr["path"] = path
		if q != nil && q.Get("host") != "" {
			setHeader(tr, "Host", q.Get("host"))
		}
		return tr, nil
	case "grpc":
		tr := map[string]any{"type": "grpc"}
		if q != nil {
			sn := q.Get("serviceName")
			if sn == "" {
				sn = q.Get("path")
			}
			tr["service_name"] = sn
		}
		return tr, nil
	case "http", "h2", "h2c":
		tr := map[string]any{"type": "http"}
		if q != nil {
			if p := q.Get("path"); p != "" {
				tr["path"] = p
			}
			if h := q.Get("host"); h != "" {
				tr["host"] = []string{h}
			}
		}
		return tr, nil
	case "quic":
		return map[string]any{"type": "quic"}, nil
	default:
		return nil, fmt.Errorf("transport %q is not supported by the sing-box core", network)
	}
}

// splitHostPort splits "host:port" supporting IPv6 in brackets and domain names with ports.
func splitHostPort(hostport string) (string, int, error) {
	if hostport == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	// IPv6 literal
	addr, err := netip.ParseAddrPort(hostport)
	if err == nil {
		return addr.Addr().String(), int(addr.Port()), nil
	}
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		// hysteria2 style without port on 443
		return strings.Trim(hostport, "[]"), 443, nil
	}
	host := strings.Trim(hostport[:i], "[]")
	port, err := atoiStrict(hostport[i+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %q", hostport)
	}
	return host, port, nil
}

func atoiStrict(s string) (int, error) {
	port, err := strconv.Atoi(s)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return port, nil
}

// base64Decode tries both std and url padding-less alphabets.
func base64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "-", "+")
	s = strings.ReplaceAll(s, "_", "/")
	if mod := len(s) % 4; mod != 0 {
		s += strings.Repeat("=", 4-mod)
	}
	return base64.StdEncoding.DecodeString(s)
}

// anyToInt converts json numbers that may arrive as float64/string/int.
func anyToInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, false
		}
		return int(i), true
	case string:
		i := 0
		if _, err := fmt.Sscanf(n, "%d", &i); err == nil {
			return i, true
		}
	}
	return 0, false
}

// normalizeMillis converts "500" to "500ms" and keeps "30s"/"500ms" as is.
func normalizeMillis(s string) string {
	for _, r := range s {
		if r < '0' || r > '9' {
			return s
		}
	}
	return s + "ms"
}
