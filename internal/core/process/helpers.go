package process

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"net"
	"strconv"
	"time"
)

func nowUnix() int64 { return time.Now().Unix() }

func after5s() <-chan time.Time { return time.After(5 * time.Second) }

// drainLogs reads core stderr into the log ring buffer.
func freeLocalPort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func drainLogs(r interface{ Read([]byte) (int, error) }, m *Manager) {
	scanner := bufio.NewScanner(bufio.NewReader(r))
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		m.mu.Lock()
		m.log(scanner.Text())
		m.mu.Unlock()
	}
}

// freeController picks a free localhost port for the clash api
// (starting from the conventional 9090) and a random secret.
func freeController() (addr, secret string, err error) {
	var port int
	for p := 9090; p < 9090+100; p++ {
		ln, lerr := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(p))
		if lerr != nil {
			continue
		}
		port = p
		_ = ln.Close()
		break
	}
	if port == 0 {
		ln, lerr := net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			return "", "", lerr
		}
		port = ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
	}
	b := make([]byte, 16)
	if _, err = rand.Read(b); err != nil {
		return "", "", err
	}
	return "127.0.0.1:" + strconv.Itoa(port), hex.EncodeToString(b)[:16], nil
}
