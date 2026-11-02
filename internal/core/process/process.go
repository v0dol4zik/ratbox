// Package process manages external core binaries (sing-box, xray).
// ratbox generates the config, supervises the process and talks to its
// clash-api for node switching and traffic stats.
package process

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/v0dol4zik/ratbox/internal/model"
)

const (
	SelectorTag = "ratbox"
	logCap      = 500
)

// Config holds runtime parameters for the core process.
type Config struct {
	Binary    string // path to sing-box binary
	MixedPort int    // local http+socks inbound port
	DataDir   string // where to write the generated config
}

type Manager struct {
	mu            sync.Mutex
	cfg           Config
	cmd           *exec.Cmd
	logs          []string
	started       bool
	startedAtUnix int64
	controller    string // clash api address, set after Start
	secret        string
}

func NewManager(cfg Config) *Manager {
	return &Manager{cfg: cfg}
}

// Running reports whether the core process is alive.
func (m *Manager) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.isRunning()
}

func (m *Manager) isRunning() bool {
	return m.cmd != nil && m.cmd.Process != nil &&
		m.cmd.ProcessState == nil &&
		m.started
}

func (m *Manager) Controller() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.controller
}

func (m *Manager) Secret() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.secret
}

func (m *Manager) StartedAt() int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.startedAtUnix
}

// Logs returns a copy of the captured core logs.
func (m *Manager) Logs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.logs))
	copy(out, m.logs)
	return out
}

func (m *Manager) log(line string) {
	m.logs = append(m.logs, line)
	if len(m.logs) > logCap {
		m.logs = m.logs[len(m.logs)-logCap:]
	}
}

// Start launches the core with the given nodes.
// activeTag is preselected in the "ratbox" selector.
func (m *Manager) Start(nodes []*model.Node, activeTag string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isRunning() {
		return fmt.Errorf("core already running")
	}
	binary, err := resolveBinary(m.cfg.Binary)
	if err != nil {
		return err
	}
	controller, secret, err := freeController()
	if err != nil {
		return fmt.Errorf("controller: %w", err)
	}
	cfgJSON, err := BuildConfig(nodes, activeTag, m.cfg.MixedPort, controller, secret, m.cfg.DataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(m.cfg.DataDir, 0o755); err != nil {
		return err
	}
	cfgPath := filepath.Join(m.cfg.DataDir, "sing-box.json")
	if err := os.WriteFile(cfgPath, cfgJSON, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	cmd := exec.Command(binary, "run", "-c", cfgPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", binary, err)
	}
	m.cmd = cmd
	m.started = true
	m.controller = "http://" + controller
	m.secret = secret
	m.startedAtUnix = nowUnix()

	go drainLogs(stderr, m)
	go func() {
		_ = cmd.Wait()
		m.mu.Lock()
		if m.cmd == cmd {
			m.started = false
			m.log("[ratbox] core exited")
		}
		m.mu.Unlock()
	}()
	return nil
}

// Stop terminates the core process (SIGINT, then SIGKILL after 5s).
func (m *Manager) Stop() error {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGINT); err != nil {
		return fmt.Errorf("kill: %w", err)
	}
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		m.mu.Lock()
		m.log("[ratbox] core stopped")
		m.started = false
		m.mu.Unlock()
		return nil
	case <-after5s():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		m.mu.Lock()
		m.log("[ratbox] core killed")
		m.started = false
		m.mu.Unlock()
		<-done
		return nil
	}
}

func (m *Manager) String() string {
	if m.Running() {
		return fmt.Sprintf("sing-box pid=%d", m.pid())
	}
	return "stopped"
}

func (m *Manager) pid() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cmd != nil && m.cmd.Process != nil {
		return m.cmd.Process.Pid
	}
	return 0
}

func resolveBinary(cfgPath string) (string, error) {
	if cfgPath != "" {
		if _, err := os.Stat(cfgPath); err == nil {
			return cfgPath, nil
		}
		return "", fmt.Errorf("core binary not found at %s", cfgPath)
	}
	for _, name := range []string{"sing-box", "xray"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("sing-box binary not found: install sing-box or set core_binary in the store")
}

// BuildConfig renders a sing-box config with:
// mixed inbound, selector with all nodes, clash api, cache file.
func BuildConfig(nodes []*model.Node, activeTag string, mixedPort int, controller, secret, dataDir string) ([]byte, error) {
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes to start with")
	}
	var tags []string
	selector := map[string]any{
		"type":                        "selector",
		"tag":                         SelectorTag,
		"interrupt_exist_connections": true,
	}
	if activeTag != "" {
		selector["default"] = activeTag
	}
	outbounds := []map[string]any{selector}
	for _, n := range nodes {
		var raw map[string]any
		if err := json.Unmarshal(n.Outbound, &raw); err != nil {
			return nil, fmt.Errorf("node %s: %w", n.Tag, err)
		}
		raw["tag"] = n.Tag
		tags = append(tags, n.Tag)
		outbounds = append(outbounds, raw)
	}
	selector["outbounds"] = tags
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	cfg := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []map[string]any{
				{"type": "local", "tag": "dns-local"},
			},
		},
		"inbounds": []map[string]any{
			{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": mixedPort,
			},
		},
		"outbounds": outbounds,
		"route": map[string]any{
			"auto_detect_interface": true,
			"final":                 SelectorTag,
		},
		"experimental": map[string]any{
			"clash_api": map[string]any{
				"external_controller": controller,
				"secret":              secret,
			},
			"cache_file": map[string]any{
				"enabled": true,
				"path":    filepath.Join(dataDir, "clash.db"),
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
