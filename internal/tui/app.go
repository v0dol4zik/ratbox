package tui

import (
	"errors"
	"fmt"
	"strings"
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

	running  bool
	latency  map[string]int
	traffic  clash.Traffic
	rateDown int64
	rateUp   int64

	status    string
	statusErr bool

	inputActive bool
	inputPrompt string
	inputBuf    string
	inputMasked bool // hide characters (sudo password)
	inputSubmit func(string) tea.Cmd

	autoNow string

	sudoAttempts int
	sudoBin      string
}

func New(st *store.Store, mgr *process.Manager) *App {
	return &App{
		store:   st,
		mgr:     mgr,
		latency: make(map[string]int),
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
			// try to fix it via polkit (one-time password dialog) and retry
			if ok && cm.tunPerm && attempt == 0 {
				bin, binErr := process.ResolveBinaryPath(a.store.CoreBinary)
				if binErr != nil {
					bin = "sing-box"
				}
				if err := process.SetCapsPKExec(bin); err != nil {
					// no polkit agent or denied — ask in the TUI instead
					return needSudoPromptMsg{binary: bin}
				}
				continue
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
			return coreStateMsg{false, "", errors.New("недостаточно прав для tun (CAP_NET_ADMIN)"), true}
		}
		return coreStateMsg{false, "", errors.New("clash api not responding, смотри логи (3)"), false}
	}
	if opts.Auto {
		_ = c.Select(process.SelectorTag, process.AutoTag)
	} else if opts.ActiveTag != "" {
		_ = c.Select(process.SelectorTag, opts.ActiveTag)
	}
	return coreStateMsg{true, "", nil, false}
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
		nodes, err := sub.Fetch(subURL, 15*time.Second)
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
		nodes, err := sub.Fetch(s.URL, 15*time.Second)
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
			a.status, a.statusErr = "ядро упало — смотри вкладку 3 (логи)", true
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
		} else {
			a.latency[m.tag] = m.ms
		}
		return a, nil

	case needSudoPromptMsg:
		if a.sudoAttempts >= 3 {
			a.status, a.statusErr = "выполни вручную: sudo setcap 'cap_net_admin,cap_net_raw=ep' "+m.binary, true
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
		a.beginPasswordInput("sudo пароль (setcap, Esc — отмена): ", func(pw string) tea.Cmd {
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
		}
		if m.running {
			a.startedAt = time.Now()
			a.status, a.statusErr = "core started", false
			return a, trafficTickCmd(a)
		}
		a.status, a.statusErr = "core stopped", false
		return a, nil

	case opDoneMsg:
		if m.err != nil && process.IsAuthError(m.err) {
			if a.sudoAttempts < 3 {
				a.sudoAttempts++
				a.status, a.statusErr = "неверный пароль, попробуй ещё раз", true
				a.beginPasswordInput("sudo пароль (setcap, Esc — отмена): ", func(pw string) tea.Cmd {
					return a.sudoSetcapCmd(pw, a.sudoBin)
				})
				return a, nil
			}
			a.status, a.statusErr = "выполни вручную: sudo setcap 'cap_net_admin,cap_net_raw=ep' "+a.sudoBin, true
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

	switch k.String() {
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
	case "tab":
		a.view = (a.view + 1) % 3
		return a, nil
	case "m":
		a.store.TunMode = !a.store.TunMode
		_ = a.store.Save()
		state := "off"
		if a.store.TunMode {
			state = "on"
		}
		if a.mgr.Running() {
			a.status = "tun " + state + " — перезапуск ядра…"
			return a, a.startCoreCmd()
		}
		a.status, a.statusErr = "tun "+state+" (применится при старте)", false
	case "y":
		// toggles the urltest "auto" group as the selector target
		a.store.AutoMode = !a.store.AutoMode
		_ = a.store.Save()
		a.autoNow = ""
		state := "off"
		if a.store.AutoMode {
			state = "on"
		}
		if a.mgr.Running() {
			a.status = "auto " + state + " — перезапуск ядра…"
			return a, a.startCoreCmd()
		}
		a.status, a.statusErr = "auto "+state+" (применится при старте)", false
	case "p":
		// cycles the routing profile: global -> RU bypass
		a.store.RoutingProfile++
		if a.store.RoutingProfile > process.ProfileRUBypass {
			a.store.RoutingProfile = process.ProfileGlobal
		}
		_ = a.store.Save()
		name := "global"
		if a.store.RoutingProfile == process.ProfileRUBypass {
			name = "RU→direct"
		}
		if a.mgr.Running() {
			a.status = "маршрутизация " + name + " — перезапуск ядра…"
			return a, a.startCoreCmd()
		}
		a.status, a.statusErr = "маршрутизация "+name+" (применится при старте)", false
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
		switch k.String() {
		case "up", "k":
			if a.nodeIdx > 0 {
				a.nodeIdx--
			}
		case "down", "j":
			if a.nodeIdx < len(a.store.Nodes)-1 {
				a.nodeIdx++
			}
		case "Enter":
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			n := a.store.Nodes[a.nodeIdx]
			if a.store.ActiveNodeID == n.ID {
				return a, nil
			}
			if !a.mgr.Running() {
				a.store.ActiveNodeID = n.ID
				_ = a.store.Save()
				a.status = "selected: " + n.Tag
				return a, nil
			}
			return a, a.selectNodeCmd(n)
		case "t":
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			n := a.store.Nodes[a.nodeIdx]
			a.status = "testing " + n.Tag + "…"
			return a, delayCmd(a, n.Tag)
		case "T":
			if len(a.store.Nodes) == 0 {
				return a, nil
			}
			a.status = "testing all nodes…"
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
		switch k.String() {
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
	case ViewLogs:
		lines := a.mgr.Logs()
		maxOff := maxInt(0, len(lines)-visibleLogLines(a.height))
		switch k.String() {
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
				return opDoneMsg{text: "неверный пароль sudo", err: err}
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
