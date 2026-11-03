// Package process manages external core binaries (sing-box, xray).
// ratbox generates the config, supervises the process and talks to its
// clash-api for node switching and traffic stats.
package process

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	servicePort   int // always-direct loopback inbound port, set after Start
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

// ServicePort returns the loopback port of the always-direct service inbound.
func (m *Manager) ServicePort() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.servicePort
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
// Routing profile knobs (v0.3.0).
const (
	ProfileGlobal   = 0 // everything through the selector
	ProfileRUBypass = 1 // RU sites/IPs bypass the proxy while tun is on
)

// AutoTag is the urltest group that always points to the fastest node.
const AutoTag = "auto"

// ServiceTag is the loopback inbound whose traffic always goes direct.
const ServiceTag = "service-in"

// StartOptions describe the runtime layout selected in the TUI.
type StartOptions struct {
	Nodes          []*model.Node
	ActiveTag      string
	Tun            bool
	Auto           bool // urltest group is the selector default
	RoutingProfile int  // ProfileGlobal | ProfileRUBypass
	ServicePort    int  // loopback port of the always-direct service inbound
}

func (m *Manager) Start(opts StartOptions) error {
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
	if opts.ServicePort == 0 {
		servicePort, err := freeLocalPort()
		if err != nil {
			return fmt.Errorf("service port: %w", err)
		}
		opts.ServicePort = servicePort
	}
	m.servicePort = opts.ServicePort
	cfgJSON, err := BuildConfig(opts, m.cfg.MixedPort, controller, secret, m.cfg.DataDir)
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

// ruRuleSets are the remote rule sets for the RU-bypass profile.
var ruRuleSets = []map[string]any{
	{"type": "remote", "tag": "geoip-ru", "url": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs", "download_detour": "direct"},
	{"type": "remote", "tag": "geosite-gov-ru", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-gov-ru.srs", "download_detour": "direct"},
	{"type": "remote", "tag": "geosite-yandex", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-yandex.srs", "download_detour": "direct"},
	{"type": "remote", "tag": "geosite-vk", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-vk.srs", "download_detour": "direct"},
	{"type": "remote", "tag": "geosite-mailru", "url": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-mailru.srs", "download_detour": "direct"},
}

// BuildConfig renders a sing-box config with mixed inbound, selector
// with all nodes, clash api and a cache file.
func BuildConfig(opts StartOptions, mixedPort int, controller, secret, dataDir string) ([]byte, error) {
	nodes, activeTag, tun := opts.Nodes, opts.ActiveTag, opts.Tun
	if len(nodes) == 0 {
		return nil, fmt.Errorf("no nodes to start with")
	}
	var tags []string
	selector := map[string]any{
		"type":                        "selector",
		"tag":                         SelectorTag,
		"interrupt_exist_connections": true,
	}
	switch {
	case opts.Auto:
		selector["default"] = AutoTag
	case activeTag != "":
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
	// keep "direct" selectable so the user can bypass everything;
	// with auto mode the urltest group is selectable as well
	selOut := append([]string{}, tags...)
	if opts.Auto {
		selOut = append([]string{AutoTag}, selOut...)
		outbounds = append(outbounds, map[string]any{
			"type":      "urltest",
			"tag":       AutoTag,
			"outbounds": append([]string{}, tags...),
			"url":       "https://www.gstatic.com/generate_204",
			"interval":  "5m",
		})
	}
	selOut = append(selOut, "direct")
	selector["outbounds"] = selOut
	outbounds = append(outbounds, map[string]any{"type": "direct", "tag": "direct"})

	// inbounds: tun first (if enabled) + loopback mixed for local tests
	inbounds := []map[string]any{
		{
			"type":        "mixed",
			"tag":         "mixed-in",
			"listen":      "127.0.0.1",
			"listen_port": mixedPort,
		},
	}
	dns := map[string]any{
		"servers": []map[string]any{
			{"type": "local", "tag": "dns-local"},
		},
	}
	route := map[string]any{
		"auto_detect_interface": true,
		"final":                 SelectorTag,
	}
	// service inbound: loopback entry whose traffic always goes direct
	// (subscription updates must survive a dead node under tun)
	inbounds = append(inbounds, map[string]any{
		"type":        "mixed",
		"tag":         ServiceTag,
		"listen":      "127.0.0.1",
		"listen_port": opts.ServicePort,
	})
	rules := []map[string]any{
		{"inbound": []string{ServiceTag}, "action": "route", "outbound": "direct"},
		{"action": "sniff"},
		{"ip_is_private": true, "action": "route", "outbound": "direct"},
	}
	route["default_domain_resolver"] = "dns-local"

	if tun {
		inbounds = append([]map[string]any{{
			"type":         "tun",
			"tag":          "tun-in",
			"address":      []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			"mtu":          9000,
			"auto_route":   true,
			"strict_route": true,
		}}, inbounds...)
		rules = append(rules, map[string]any{"protocol": "dns", "action": "hijack-dns"})
		// dns through the tunnel to protect from poisoning;
		// node hostnames still resolve via dns-local (domain_resolver above)
		dns["servers"] = append(dns["servers"].([]map[string]any), map[string]any{
			"type":   "https",
			"tag":    "dns-remote",
			"server": "1.1.1.1",
			"detour": SelectorTag,
		})
		dns["final"] = "dns-remote"
	}

	if opts.RoutingProfile == ProfileRUBypass {
		ruTags := []string{}
		for _, rs := range ruRuleSets {
			ruTags = append(ruTags, rs["tag"].(string))
		}
		rules = append(rules, map[string]any{
			"rule_set": ruTags,
			"action":   "route",
			"outbound": "direct",
		})
		route["rule_set"] = ruRuleSets
		if tun {
			// RU domains resolve locally so CDNs return nearby mirrors
			dns["rules"] = []map[string]any{
				{"rule_set": ruTags, "server": "dns-local"},
			}
		}
	}
	route["rules"] = rules

	cfg := map[string]any{
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns":       dns,
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"route":     route,
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

// ResolveBinaryPath resolves the core binary location (store path, or PATH lookup).
func ResolveBinaryPath(cfgPath string) (string, error) {
	return resolveBinary(cfgPath)
}

// RunSetCapsSudo grants CAP_NET_ADMIN/CAP_NET_RAW to the core binary with
// a sudo password supplied by the user. The password goes directly into the
// sudo stdin pipe, is zeroized afterwards and is never written to disk.
// A valid cached sudo ticket (or NOPASSWD) skips the password entirely.
func RunSetCapsSudo(binary string, password []byte) error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return fmt.Errorf("sudo not found")
	}
	setcap, err := exec.LookPath("setcap")
	if err != nil {
		return fmt.Errorf("setcap not found (install libcap)")
	}
	caps := "cap_net_admin,cap_net_raw=ep"
	// 1) try without touching the password reader: cached ticket / NOPASSWD
	if err := exec.Command(sudo, "-n", setcap, caps, binary).Run(); err == nil {
		for i := range password {
			password[i] = 0
		}
		return nil
	}
	// 2) feed the password via stdin (-S), empty prompt (-p)
	cmd := exec.Command(sudo, "-S", "-p", "", setcap, caps, binary)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		return err
	}
	_, _ = stdin.Write(append(password, '\n'))
	_ = stdin.Close()
	waitErr := cmd.Wait()
	for i := range password {
		password[i] = 0 // cleared; copy for -n path above cleared too
	}
	password = nil
	if waitErr != nil {
		return fmt.Errorf("%s", firstLine(out.String()))
	}
	return nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	return s
}

// IsAuthError reports whether the sudo failure looks like a rejected password
// (both english and localized variants) rather than a system problem.
func IsAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	// NOTE: the non-english entries below match localized sudo output
	// (e.g. "Попробуйте ещё раз"), they are detection patterns, not UI.
	for _, p := range []string{
		"incorrect password",
		"no password was provided",
		"try again",
		"попробуйте ещё раз",
		"authentication failure",
		"а также не в файле sudoers",
		"is not in the sudoers file",
	} {
		if strings.Contains(msg, p) {
			return true
		}
	}
	return false
}
