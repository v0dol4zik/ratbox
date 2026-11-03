// ratbox — a CLI/TUI proxy client for the sing-box core.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/store"
	"github.com/v0dol4zik/ratbox/internal/tui"
)

var version = "dev"

func main() {
	debug := flag.Bool("debug", false, "write a ratbox-debug.log file")
	showVersion := flag.Bool("version", false, "print version")
	flag.Parse()

	if *showVersion {
		fmt.Println("ratbox", version)
		return
	}

	storePath, err := store.DefaultPath()
	if err != nil {
		fatal(err)
	}
	st, err := store.Load(storePath)
	if err != nil {
		fatal(fmt.Errorf("load store: %w", err))
	}

	dataDir, _, err := store.DefaultDirs()
	if err != nil {
		fatal(err)
	}
	mgr := process.NewManager(process.Config{
		Binary:    st.CoreBinary,
		MixedPort: st.MixedPort,
		DataDir:   filepath.Join(dataDir, "core"),
	})

	if *debug {
		if f, err := tea.LogToFile("ratbox-debug.log", "ratbox"); err == nil {
			defer func() { _ = f.Close() }()
		}
	}

	progOpts := []tea.ProgramOption{tea.WithAltScreen()}
	// headless e2e harness: feed keystrokes through a fifo (the pty is only
	// used for rendering in that mode, bubbletea there otherwise swallows input)
	if pipes := os.Getenv("RATBOX_TEST_INPUT"); pipes != "" {
		if f, err := os.OpenFile(pipes, os.O_RDWR, 0); err == nil {
			progOpts = append(progOpts, tea.WithInput(f))
		}
	}

	p := tea.NewProgram(tui.New(st, mgr), progOpts...)
	if _, err := p.Run(); err != nil {
		fatal(fmt.Errorf("tui: %w", err))
	}
	if err := mgr.Stop(); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ratbox:", err)
	os.Exit(1)
}
