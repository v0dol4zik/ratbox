// ratbox — a CLI/TUI proxy client for the sing-box core.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/v0dol4zik/ratbox/internal/core/process"
	"github.com/v0dol4zik/ratbox/internal/store"
	"github.com/v0dol4zik/ratbox/internal/sub"
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

	sub.AppVersion = version // subscription User-Agent matches the real build

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

	// single instance: two ratbox processes would fight over the core
	// (killOrphanCores of one murders the live core of the other)
	lockPath := filepath.Join(dataDir, "ratbox.lock")
	lk, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err == nil {
		if ferr := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); ferr != nil {
			fmt.Fprintln(os.Stderr, "ratbox: another instance is running —", lockPath)
			os.Exit(1)
		}
		// lk stays open for the whole process lifetime: the kernel drops
		// the lock when we exit, however we exit
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
