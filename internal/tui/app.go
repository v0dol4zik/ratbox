package tui

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/v0dol4zik/ratbox/internal/core/clash"
	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/model"
	"github.com/v0dol4zik/ratbox/internal/store"
	"github.com/v0dol4zik/ratbox/internal/sub"
)

const (
	ViewNodes = iota
	ViewSubs
	ViewLogs
	ViewSettings
)

const refreshInterval = time.Second

type App struct {
	store     *store.Store
	mgr       *process.Manager
	client    *clash.Client
	startedAt time.Time

	view      int
	width     int
	height    int
	nodeIdx   int
	subIdx    int
	logOffset int

	running bool
	latency map[string]int
	// sweep bookkeeping for the latency summary status
	dSem      chan struct{} // caps concurrent delay tests at 5
	testTotal int
	testDone  int
	testOk    int
	testErr   string
	traffic   clash.Traffic
	rateDown  int64
	rateUp    int64

	status    string
	statusErr bool

	inputActive bool
	inputPrompt string
	inputBuf    string
	inputMasked bool // hide characters (sudo password)
	inputSubmit func(string) tea.Cmd

	autoNow string

	setIdx       int // settings cursor
	sudoAttempts int
	sudoBin      string
}

func New(st *store.Store, mgr *process.Manager) *App {
	return &App{
		store:   st,
		mgr:     mgr,
		latency: make(map[string]int),
		dSem:    make(chan struct{}, 5),
	}
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

type trafficTickMsg struct {
	traffic clash.Traffic
	err     error
	autoNow string
}

type delayMsg struct {
	tag string
	ms  int
	err error
}

type opDoneMsg struct {
	text  string
	err   error
	relog bool // refresh logs view
}

// needSudoPromptMsg asks the user for the sudo password inside the TUI.
type needSudoPromptMsg struct {
	binary string
}

type coreStateMsg struct {
	running bool
	text    string
	err     error
	tunPerm bool // failed with missing CAP_NET_ADMIN (fixable via polkit)
}

// ---------------------------------------------------------------------------
// Init / commands
// ---------------------------------------------------------------------------

func (a *App) Init() tea.Cmd {
	if a.store.AutoStart {
		return a.startCoreCmd()
	}
	return nil

}

func (a *App) startCoreCmd() tea.Cmd {
	return func() tea.Msg {
		for attempt := 0; ; attempt++ {
			msg := a.tryStartCore()
			cm, ok := msg.(coreStateMsg)
			if ok && cm.running {
				return msg
			}
			// first failed attempt with a tun permission problem:
			// ask for the sudo password right in the TUI. polkit/pkexec is
			// deliberately NOT used here: without a GUI agent pkexec builds
			// a textual prompt in the terminal on top of the TUI and the
			// keystrokes are stolen by bubbletea — a separate /dev/tty
			// reader cannot coexist with it.
			if ok && cm.tunPerm && attempt == 0 {
				bin, binErr := process.ResolveBinaryPath(a.store.CoreBinary)
				if binErr != nil {
					bin = "sing-box"
				}
				return needSudoPromptMsg{binary: bin}
			}
			return msg
		}
	}
}

// tryStartCore performs a single start attempt and classifies failures.
func (a *App) tryStartCore() tea.Msg {
	if a.mgr.Running() {
		if err := a.mgr.Stop(); err != nil {
			return coreStateMsg{false, "", err, false}
		}
	}
	opts := a.startOptions()
	if err := a.mgr.Start(opts); err != nil {
		return coreStateMsg{false, "", err, false}
	}
	c := clash.New(a.mgr.Controller(), a.mgr.Secret())
	// wait until the clash api is up (max ~5s)
	var ok bool
	for i := 0; i < 50; i++ {
		if _, err := c.Version(); err == nil {
			ok = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		_ = a.mgr.Stop()
		if a.store.TunMode && a.coreDiedOnPerm() {
			return coreStateMsg{false, "", errors.New("insufficient permissions for tun (CAP_NET_ADMIN)"), true}
		}
		detail := a.lastCoreErr()
		return coreStateMsg{false, "", fmt.Errorf("clash api not responding%s", detail), false}
	}
	if opts.Auto {
		_ = c.Select(process.SelectorTag, process.AutoTag)
	} else if opts.ActiveTag != "" {
		_ = c.Select(process.SelectorTag, opts.ActiveTag)
	}
	return coreStateMsg{true, "", nil, false}
}

// toggleTun flips the tun mode (restarts the core when running).
func (a *App) toggleTun() tea.Cmd {
	a.store.TunMode = !a.store.TunMode
	_ = a.store.Save()
	state := "off"
	if a.store.TunMode {
		state = "on"
	}
	if a.mgr.Running() {
		a.status = "tun " + state + " — restarting core…"
		return a.startCoreCmd()
	}
	a.status, a.statusErr = "tun "+state+" (applies at start)", false
	return nil
}

// toggleAuto flips the urltest "auto" group as the selector target.
func (a *App) toggleAuto() tea.Cmd {
	a.store.AutoMode = !a.store.AutoMode
	_ = a.store.Save()
	a.autoNow = ""
	state := "off"
	if a.store.AutoMode {
		state = "on"
	}
	if a.mgr.Running() {
		a.status = "auto " + state + " — restarting core…"
		return a.startCoreCmd()
	}
	a.status, a.statusErr = "auto "+state+" (applies at start)", false
	return nil
}

// cycleProfile switches the routing profile: global -> RU bypass.
func (a *App) cycleProfile() tea.Cmd {
	a.store.RoutingProfile++
	if a.store.RoutingProfile > process.ProfileRUBypass {
		a.store.RoutingProfile = process.ProfileGlobal
	}
	_ = a.store.Save()
	return a.applyProfileStatus()
}

func (a *App) applyProfileStatus() tea.Cmd {
	name := "global"
	if a.store.RoutingProfile == process.ProfileRUBypass {
		name = "RU→direct"
	}
	if a.mgr.Running() {
		a.status = "routing " + name + " — restarting core…"
		return a.startCoreCmd()
	}
	a.status, a.statusErr = "routing "+name+" (applies at start)", false
	return nil
}

// toggleAutostart flips the startup core launch (applies at next start).
func (a *App) toggleAutostart() tea.Cmd {
	a.store.AutoStart = !a.store.AutoStart
	_ = a.store.Save()
	state := "off"
	if a.store.AutoStart {
		state = "on"
	}
	a.status, a.statusErr = "autostart "+state, false
	return nil
}

// settings row order must match applySetting below and renderSettings.
const (
	setTun = iota
	setAuto
	setProfile
	setAutostart
	setMixedPort
	setCoreBinary
	settingsRows
)

// applySetting toggles the setting at the given row index.
func (a *App) applySetting(idx int) tea.Cmd {
	switch idx {
	case setTun:
		return a.toggleTun()
	case setAuto:
		return a.toggleAuto()
	case setProfile:
		return a.cycleProfile()
	case setAutostart:
		return a.toggleAutostart()
	case setMixedPort:
		return a.editSetting(setMixedPort)
	case setCoreBinary:
		return a.editSetting(setCoreBinary)
	}
	return nil
}

// editSetting opens an input for the value-editable settings.
func (a *App) editSetting(idx int) tea.Cmd {
	switch idx {
	case setMixedPort:
		a.beginInput(fmt.Sprintf("mixed port [%d]: ", a.store.MixedPort), func(s string) tea.Cmd {
			port, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || port < 1 || port > 65535 {
				return func() tea.Msg {
					return opDoneMsg{text: "port: expected an integer 1-65535", err: fmt.Errorf("%q", s)}
				}
			}
			if port == a.store.MixedPort {
				return func() tea.Msg { return opDoneMsg{text: "port unchanged", err: nil} }
			}
			a.store.MixedPort = port
			_ = a.store.Save()
			if a.mgr.Running() {
				a.status = fmt.Sprintf("port %d — restarting core…", port)
				return a.startCoreCmd()
			}
			return func() tea.Msg {
				return opDoneMsg{text: fmt.Sprintf("mixed port %d (applies at start)", port), err: nil}
			}
		})
	case setCoreBinary:
		cur := a.store.CoreBinary
		if cur == "" {
			cur = "(auto: sing-box from PATH)"
		}
		a.beginInput(fmt.Sprintf("core binary [%s]: ", cur), func(s string) tea.Cmd {
			s = strings.TrimSpace(s)
			if s != "" {
				if _, err := process.ResolveBinaryPath(s); err != nil {
					return func() tea.Msg { return opDoneMsg{text: "binary not found", err: err} }
				}
			}
			_ = a.store.Save()
			a.store.CoreBinary = s
			_ = a.store.Save()
			if a.mgr.Running() {
				a.status = "core binary — restarting core…"
				return a.startCoreCmd()
			}
			return func() tea.Msg { return opDoneMsg{text: "core binary updated", err: nil} }
		})
	}
	return nil
}

// errShort strips the node tag prefix the clash client prepends and the
// url noise, leaving the actionable part of the error.
func errShort(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	msg = strings.ReplaceAll(msg, "\n", " ")
	if len(msg) > 90 {
		msg = msg[:87] + "…"
	}
	return msg
}

// normKey lower-cases a single ASCII letter so hotkeys survive Caps Lock
// being on: the terminal gives us "S" and the app wants "s". The two keys
// where case IS the meaning ("g"/"G" — list top/end, and the legacy "T"
// test-all alias) keep their spelling.
func normKey(k tea.KeyMsg) string {
	s := k.String()
	if len(s) == 1 && s[0] >= 'A' && s[0] <= 'Z' && s != "G" && s != "T" {
		return strings.ToLower(s)
	}
	return s
}

// bestNodeMsg reports the bootstrap node pick result.
type bestNodeMsg struct {
	tag string
	ms  int
	err error
}

// pickBestNodeCmd delay-tests every node in parallel and selects the
// fastest one. Runs after a cold start with no explicit selection.
func (a *App) pickBestNodeCmd() tea.Cmd {
	return func() tea.Msg {
		c := a.client
		if c == nil || len(a.store.Nodes) == 0 {
			return nil
		}
		type result struct {
			tag string
			ms  int
		}
		results := make(chan result, len(a.store.Nodes))
		semi := make(chan struct{}, 5)
		var wg sync.WaitGroup
		for _, n := range a.store.Nodes {
			wg.Add(1)
			semi <- struct{}{}
			go func(tag string) {
				defer wg.Done()
				defer func() { <-semi }()
				if ms, err := c.Delay(tag, 3*time.Second, clash.DefaultTestURL); err == nil {
					results <- result{tag, ms}
				}
			}(n.Tag)
		}
		wg.Wait()
		close(results)
		best, bestMs := "", int(^uint(0)>>1)
		for r := range results {
			if r.ms < bestMs {
				best, bestMs = r.tag, r.ms
			}
		}
		if best == "" {
			return bestNodeMsg{err: errors.New("all nodes failed the delay test")}
		}
		if err := c.Select(process.SelectorTag, best); err != nil {
			return bestNodeMsg{err: err}
		}
		for _, n := range a.store.Nodes {
			if n.Tag == best {
				a.store.ActiveNodeID = n.ID
				_ = a.store.Save()
				break
			}
		}
		return bestNodeMsg{tag: best, ms: bestMs}
	}
}

// serviceProxy returns the always-direct subscription channel of a running
// core, or "" when the core is stopped (plain direct fetch is fine then).
func (a *App) serviceProxy() string {
	if !a.mgr.Running() {
		return ""
	}
	if p := a.mgr.ServicePort(); p > 0 {
		return "http://127.0.0.1:" + strconv.Itoa(p)
	}
	return ""
}

// startOptions assembles the core start request from the store state.
func (a *App) startOptions() process.StartOptions {
	var activeTag string
	if n := a.store.Node(a.store.ActiveNodeID); n != nil {
		activeTag = n.Tag
	}
	return process.StartOptions{
		Nodes:          deepCopyNodes(a.store.Nodes),
		ActiveTag:      activeTag,
		Tun:            a.store.TunMode,
		Auto:           a.store.AutoMode,
		RoutingProfile: a.store.RoutingProfile,
	}
}

// lastCoreErr extracts the last FATAL/ERROR line from the core logs, if any.
func (a *App) lastCoreErr() string {
	for i := len(a.mgr.Logs()) - 1; i >= 0; i-- {
		l := a.mgr.Logs()[i]
		if strings.Contains(l, "FATAL") || strings.Contains(l, "ERROR") {
			// cut ansi/log prefixes: keep the tail after "FATAL]"
			if j := strings.LastIndex(l, "] "); j >= 0 {
				l = l[j+2:]
			}
			return ": " + strings.TrimSpace(l)
		}
	}
	return ", see the logs tab (3)"
}

// coreDiedOnPerm reports whether the core died because of missing capabilities.
func (a *App) coreDiedOnPerm() bool {
	for _, l := range a.mgr.Logs() {
		if strings.Contains(l, "operation not permitted") {
			return true
		}
	}
	return false
}

func (a *App) stopCoreCmd() tea.Cmd {
	return func() tea.Msg {
		err := a.mgr.Stop()
		return coreStateMsg{false, "", err, false}
	}
}

func trafficTickCmd(app *App) tea.Cmd {
	return tea.Tick(refreshInterval, func(time.Time) tea.Msg {
		if app.client == nil {
			return trafficTickMsg{}
		}
		t, err := app.client.Traffic()
		msg := trafficTickMsg{traffic: t, err: err}
		if p, perr := app.client.Proxies(); perr == nil {
			if pr, ok := p[process.AutoTag]; ok {
				msg.autoNow = pr.Now
			}
		}
		return msg
	})
}

func delayCmd(app *App, tag string) tea.Cmd {
	return func() tea.Msg {
		if app.client == nil {
			return delayMsg{tag: tag, err: fmt.Errorf("core is not running")}
		}
		// at most 5 probes in flight: a full-strength volley trips over
		// wifi aps and ISP rate-limits and paints every node dead
		if app.dSem != nil {
			app.dSem <- struct{}{}
			defer func() { <-app.dSem }()
		}
		ms, err := app.client.Delay(tag, 5*time.Second, clash.DefaultTestURL)
		return delayMsg{tag: tag, ms: ms, err: err}
	}
}

func (a *App) submitAddSubCmd(raw string) tea.Cmd {
	return func() tea.Msg {
		name, subURL := parseSubInput(raw)
		if subURL == "" {
			return opDoneMsg{text: "invalid url", err: nil}
		}
		nodes, err := sub.Fetch(subURL, 15*time.Second, a.serviceProxy())
		if err != nil {
			return opDoneMsg{text: "fetch failed", err: err}
		}
		st := a.store
		subObj := st.AddSubscription(name, subURL, uniquifyTags(st, nodes))
		if err := st.Save(); err != nil {
			return opDoneMsg{text: "save failed", err: err}
		}
		a.restartIfRunning()
		return opDoneMsg{text: fmt.Sprintf("subscription %q: %d nodes", subObj.Name, len(nodes))}
	}
}

func (a *App) submitAddLinkCmd(raw string) tea.Cmd {
	return func() tea.Msg {
		// pasted a subscription url -> treat as subscription
		low := strings.ToLower(strings.TrimSpace(raw))
		if strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://") {
			cmd := a.submitAddSubCmd(raw)
			return cmd()
		}
		node, err := sub.ParseLink(raw)
		if err != nil {
			return opDoneMsg{text: "invalid link", err: err}
		}
		st := a.store
		node.Tag = st.UniqueTag(node.Tag)
		node.SubID = ""
		st.Nodes = append(st.Nodes, node)
		if st.ActiveNodeID == "" {
			st.ActiveNodeID = node.ID
		}
		if err := st.Save(); err != nil {
			return opDoneMsg{text: "save failed", err: err}
		}
		a.restartIfRunning()
		return opDoneMsg{text: fmt.Sprintf("node %q added", node.Tag)}
	}
}

func (a *App) updateSubCmd(subID string) tea.Cmd {
	return func() tea.Msg {
		st := a.store
		s := st.Sub(subID)
		if s == nil {
			return opDoneMsg{text: "subscription not found"}
		}
		nodes, err := sub.Fetch(s.URL, 15*time.Second, a.serviceProxy())
		if err != nil {
			return opDoneMsg{text: "update failed", err: err}
		}
		store.ReplaceSubNodes(st, s, uniquifyTags(st, nodes))
		if err := st.Save(); err != nil {
			return opDoneMsg{text: "save failed", err: err}
		}
		a.restartIfRunning()
		return opDoneMsg{text: fmt.Sprintf("updated %q: %d nodes", s.Name, len(nodes))}
	}
}

func (a *App) selectNodeCmd(node *model.Node) tea.Cmd {
	return func() tea.Msg {
		if a.client == nil {
			return opDoneMsg{text: "core is not running", err: nil}
		}
		if err := a.client.Select(process.SelectorTag, node.Tag); err != nil {
			return opDoneMsg{text: "select failed", err: err}
		}
		a.store.ActiveNodeID = node.ID
		if err := a.store.Save(); err != nil {
			return opDoneMsg{text: "save failed", err: err}
		}
		return opDoneMsg{text: fmt.Sprintf("selected: %s", node.Tag)}
	}
}

// restartIfRunning re-instantiates the core so a new config takes effect.
func (a *App) restartIfRunning() {
	if !a.mgr.Running() {
		return
	}
	_ = a.mgr.Stop()
	_ = a.mgr.Start(a.startOptions())
	a.resetClient()
}

func (a *App) resetClient() {
	if a.mgr.Running() {
		a.client = clash.New(a.mgr.Controller(), a.mgr.Secret())
	} else {
		a.client = nil
		a.rateUp, a.rateDown = 0, 0
	}
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = m.Width, m.Height
		return a, nil

	case trafficTickMsg:
		a.autoNow = m.autoNow
		// the core may die outside of our control (crash, kill, port conflict);
		// the tick is a cheap watchdog
		if a.running && !a.mgr.Running() {
			a.running = false
			a.startedAt = time.Time{}
			a.resetClient()
			a.status, a.statusErr = "core died — see the logs tab (3)", true
		}
		if a.client != nil && m.err == nil {
			prev := a.traffic
			a.traffic = m.traffic
			a.rateDown = m.traffic.DownloadTotal - prev.DownloadTotal
			a.rateUp = m.traffic.UploadTotal - prev.UploadTotal
		}
		return a, trafficTickCmd(a)

	case delayMsg:
		if m.err != nil {
			a.latency[m.tag] = -1
			if a.testErr == "" {
				a.testErr = m.err.Error() // first failure carries the cause
			}
		} else {
			a.latency[m.tag] = m.ms
			a.testOk++
		}
		a.testDone++
		if a.testDone >= a.testTotal {
			if a.testTotal == 1 {
				if m.err != nil {
					a.status, a.statusErr = m.tag+": "+errShort(m.err), true
				} else {
					a.status, a.statusErr = fmt.Sprintf("%s: %d ms", m.tag, m.ms), false
				}
			} else if a.testOk == 0 && a.testErr != "" {
				// everything failed: the first error tells why
				a.status, a.statusErr = "all "+fmt.Sprint(a.testTotal)+" nodes failed: "+errShort(errors.New(a.testErr)), true
			} else {
				a.status, a.statusErr = fmt.Sprintf("tested %d: %d alive, %d dead", a.testTotal, a.testOk, a.testTotal-a.testOk), false
			}
		}
		return a, nil

	case needSudoPromptMsg:
		if a.sudoAttempts >= 3 {
			a.status, a.statusErr = "run manually: sudo setcap 'cap_net_admin,cap_net_raw=ep' "+m.binary, true
			return a, nil
		}
		a.sudoBin = m.binary
		a.sudoAttempts++
		bin := m.binary
		if bin == "" {
			if b, err := process.ResolveBinaryPath(a.store.CoreBinary); err == nil {
				bin = b
			} else {
				bin = "<sing-box>"
			}
		}
		a.beginPasswordInput("sudo password (setcap, Esc to cancel): ", func(pw string) tea.Cmd {
			return a.sudoSetcapCmd(pw, bin)
		})
		return a, nil

	case coreStateMsg:
		if m.err != nil {
			a.status, a.statusErr = "core: "+m.err.Error(), true
			return a, nil
		}
		a.running = m.running
		a.resetClient()
		if m.running {
			a.sudoAttempts = 0
			a.startedAt = time.Now()
			a.status, a.statusErr = "core started", false
			cmds := []tea.Cmd{trafficTickCmd(a)}
			// no node selected and no auto mode: the selector would fall
			// back to the first (often dead) node — under tun that kills
			// the whole system connectivity; bootstrap to the fastest node
			if a.store.ActiveNodeID == "" && !a.store.AutoMode {
				a.status, a.statusErr = "core started — picking the fastest node…", false
				cmds = append(cmds, a.pickBestNodeCmd())
			}
			return a, tea.Batch(cmds...)
		}
		a.status, a.statusErr = "core stopped", false
		return a, nil

	case bestNodeMsg:
		if m.err != nil {
			a.status, a.statusErr = "node bootstrap failed: "+m.err.Error()+" — press m to turn tun off", true
			return a, nil
		}
		a.status, a.statusErr = fmt.Sprintf("auto-picked the fastest node: %s (%dms)", m.tag, m.ms), false
		return a, nil

	case opDoneMsg:
		if m.err != nil && process.IsAuthError(m.err) {
			if a.sudoAttempts < 3 {
				a.sudoAttempts++
				a.status, a.statusErr = "wrong password, try again", true
				a.beginPasswordInput("sudo password (setcap, Esc to cancel): ", func(pw string) tea.Cmd {
					return a.sudoSetcapCmd(pw, a.sudoBin)
				})
				return a, nil
			}
			a.status, a.statusErr = "run manually: sudo setcap 'cap_net_admin,cap_net_raw=ep' "+a.sudoBin, true
			return a, nil
		}
		if m.err != nil {
			a.status, a.statusErr = m.text+": "+m.err.Error(), true
		} else if m.text != "" {
			a.status, a.statusErr = m.text, false
		}
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(m)
	}
	return a, nil
}

func (a *App) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	if a.inputActive {
		switch k.Type {
		case tea.KeyEnter:
			raw := a.inputBuf
			a.inputActive = false
			a.inputBuf = "" // drop the secret from memory asap
			cmd := a.inputSubmit(raw)
			a.inputSubmit = nil
			return a, cmd
		case tea.KeyEsc, tea.KeyCtrlC:
			a.inputActive = false
			a.status = "cancelled"
			return a, nil
		case tea.KeyBackspace:
			if len(a.inputBuf) > 0 {
				rs := []rune(a.inputBuf)
				a.inputBuf = string(rs[:len(rs)-1])
			}
			return a, nil

		default:
			if k.Type == tea.KeyRunes || k.Type == tea.KeySpace {
				a.inputBuf += string(k.Runes)
			}
			return a, nil
		}
	}

	switch normKey(k) {
	case "q", "ctrl+c":
		_ = a.mgr.Stop()
		return a, tea.Quit
	case "1":
		a.view = ViewNodes
		return a, nil
	case "2":
		a.view = ViewSubs
		return a, nil
	case "3":
		a.view = ViewLogs
		return a, nil
	case "4":
		a.view = ViewSettings
		return a, nil
	case "tab":
		a.view = (a.view + 1) % 4
		return a, nil
	case "left":
		a.view = (a.view + 3) % 4
		return a, nil
	case "right":
		a.view = (a.view + 1) % 4
		return a, nil
	case "m":
		return a, a.toggleTun()
	case "y":
		return a, a.toggleAuto()
	case "p":
		return a, a.cycleProfile()
	case "s":
		if a.mgr.Running() {
			return a, a.stopCoreCmd()
		}
		if len(a.store.Nodes) == 0 {
			a.status, a.statusErr = "no nodes: add a subscription first", true
			return a, nil
		}
		a.status = "starting core…"
		return a, a.startCoreCmd()
	}

	switch a.view {
	case ViewNodes:
		switch normKey(k) {
		case "up", "k":
			if a.nodeIdx > 0 {
				a.nodeIdx--
			}
		case "down", "j":
			if a.nodeIdx < len(a.store.Nodes)-1 {
				a.nodeIdx++
			}
		case "enter":
			// Enter = connect: selects the node and, when the core is
			// stopped, starts it right away with that node
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			n := a.store.Nodes[a.nodeIdx]
			if a.mgr.Running() {
				return a, a.selectNodeCmd(n)
			}
			a.store.ActiveNodeID = n.ID
			_ = a.store.Save()
			a.status = "starting core on " + n.Tag + "…"
			return a, a.startCoreCmd()
		case "t":
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			if a.client == nil {
				// tests go through the core; pretend nothing instead of
				// painting every node dead with instant crosses
				a.status, a.statusErr = "core is not running — press s to start it, then test", true
				return a, nil
			}
			n := a.store.Nodes[a.nodeIdx]
			a.status = "testing " + n.Tag + "…"
			a.testTotal, a.testDone, a.testOk, a.testErr = 1, 0, 0, ""
			return a, delayCmd(a, n.Tag)
		case "a", "T":
			// "a" = test ALL without reaching for shift; "T" kept for
			// muscle memory of older releases
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			if a.client == nil {
				a.status, a.statusErr = "core is not running — press s to start it, then test", true
				return a, nil
			}
			a.status = "testing all nodes…"
			a.testTotal, a.testDone, a.testOk, a.testErr = len(a.store.Nodes), 0, 0, ""
			var cmds []tea.Cmd
			for _, n := range a.store.Nodes {
				cmds = append(cmds, delayCmd(a, n.Tag))
			}
			return a, tea.Batch(cmds...)
		case "n":
			a.beginInput("share link or subscription url: ", func(s string) tea.Cmd { return a.submitAddLinkCmd(s) })
		case "d":
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			n := a.store.Nodes[a.nodeIdx]
			a.store.RemoveNode(n.ID)
			_ = a.store.Save()
			if a.nodeIdx >= len(a.store.Nodes) && a.nodeIdx > 0 {
				a.nodeIdx--
			}
			a.restartIfRunning()
			a.status = "removed " + n.Tag
		}
	case ViewSubs:
		switch normKey(k) {
		case "up", "k":
			if a.subIdx > 0 {
				a.subIdx--
			}
		case "down", "j":
			if a.subIdx < len(a.store.Subs)-1 {
				a.subIdx++
			}
		case "a":
			a.beginInput("subscription url or share link: ", func(s string) tea.Cmd {
				if isHTTPURL(s) {
					return a.submitAddSubCmd(s)
				}
				return a.submitAddLinkCmd(s)
			})
		case "u":
			if len(a.store.Subs) == 0 {
				return a, nil
			}
			s := a.store.Subs[a.subIdx]
			a.status = "updating " + s.Name + "…"
			return a, a.updateSubCmd(s.ID)
		case "d":
			if len(a.store.Subs) == 0 {
				return a, nil
			}
			s := a.store.Subs[a.subIdx]
			a.store.RemoveSubscription(s.ID)
			_ = a.store.Save()
			if a.subIdx >= len(a.store.Subs) && a.subIdx > 0 {
				a.subIdx--
			}
			a.nodeIdx = 0
			a.restartIfRunning()
			a.status = "removed sub " + s.Name
		}
	case ViewSettings:
		switch normKey(k) {
		case "up", "k":
			if a.setIdx > 0 {
				a.setIdx--
			}
		case "down", "j":
			if a.setIdx < settingsRows-1 {
				a.setIdx++
			}
		case "enter", " ", "m", "y", "p":
			return a, a.applySetting(a.setIdx)
		case "esc":
			a.view = ViewNodes
		}
	case ViewLogs:
		lines := a.mgr.Logs()
		maxOff := maxInt(0, len(lines)-visibleLogLines(a.height))
		switch normKey(k) {
		case "up", "k":
			if a.logOffset > 0 {
				a.logOffset--
			}
		case "down", "j":
			if a.logOffset < maxOff {
				a.logOffset++
			}
		case "g":
			a.logOffset = 0
		case "G":
			a.logOffset = maxOff
		}
	}
	return a, nil
}

func (a *App) beginInput(prompt string, submit func(string) tea.Cmd) {
	a.inputMasked = false
	a.inputActive = true
	a.inputPrompt = prompt
	a.inputBuf = ""
	a.inputSubmit = submit
}

// beginPasswordInput starts a hidden input used for sudo credentials.
func (a *App) beginPasswordInput(prompt string, submit func(string) tea.Cmd) {
	a.beginInput(prompt, submit)
	a.inputMasked = true
}

// sudoSetcapCmd grants caps via sudo using the entered password and
// restarts the core on success. The password lives only in memory:
// cleared on submit, zeroized in RunSetCapsSudo, never stored anywhere.
func (a *App) sudoSetcapCmd(pw, bin string) tea.Cmd {
	return func() tea.Msg {
		err := process.RunSetCapsSudo(bin, []byte(pw))
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "incorrect password") || strings.Contains(msg, "no password was provided") {
				return opDoneMsg{text: "wrong sudo password", err: err}
			}
			return opDoneMsg{text: "setcap", err: err}
		}
		next := a.startCoreCmd()
		return next()
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// isHTTPURL reports whether the input looks like an http(s) subscription url
// rather than a proxy share link.
func isHTTPURL(raw string) bool {
	low := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(low, "http://") || strings.HasPrefix(low, "https://")
}

func deepCopyNodes(src []*model.Node) []*model.Node {
	out := make([]*model.Node, len(src))
	copy(out, src)
	return out
}

func uniquifyTags(st *store.Store, nodes []*model.Node) []*model.Node {
	for _, n := range nodes {
		n.Tag = st.UniqueTag(n.Tag)
	}
	return nodes
}

func parseSubInput(raw string) (name, subURL string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if !strings.Contains(raw, "://") && !strings.Contains(raw, "http") {
		return "", ""
	}
	// "name url" form
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) == 2 && strings.Contains(parts[1], "://") {
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	}
	return "", raw
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func visibleLogLines(height int) int {
	h := height - 6
	if h < 1 {
		h = 1
	}
	return h
}
