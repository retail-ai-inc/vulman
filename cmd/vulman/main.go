//go:build !server

package main

import (
	"errors"
	"flag"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"

	"github.com/wailsapp/wails/v3/pkg/application"

	"vulman/internal/engine"
	"vulman/internal/scanner"
	"vulman/internal/store"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() (err error) {
	termination := make(chan os.Signal, 1)
	signal.Notify(termination, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(termination)

	config, err := os.UserConfigDir()
	if err != nil {
		return err
	}

	defaultDir := filepath.Join(config, "Vulman")
	dir := flag.String("data-dir", defaultDir, "desktop data directory (overrides Configuration)")
	sample := flag.Bool("sample", false, "add a sample project if the database is empty")
	flag.Parse()
	if err := configureScannerPath(); err != nil {
		return err
	}

	// The bridge is intended for embedded assets, including in local debug builds.
	if err := os.Unsetenv("FRONTEND_DEVSERVER_URL"); err != nil {
		return err
	}

	assets, err := assetHandler()
	if err != nil {
		return err
	}

	var explicitDirectory bool
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "data-dir" {
			explicitDirectory = true
		}
	})

	var db *store.Store
	var warning string

	if explicitDirectory {
		db, err = store.Open(*dir)
	} else {
		db, warning, err = openSavedWorkspace(defaultDir)
	}

	if err != nil {
		return err
	}

	desktop := &Desktop{store: db, defaultDirectory: defaultDir, storageWarning: warning}
	// Some desktop platforms terminate inside the native event loop.
	closeStore := sync.OnceValue(desktop.close)
	defer func() {
		err = errors.Join(err, closeStore())
	}()

	if err := scanner.CleanScanScratch(filepath.Dir(db.Paths().Database)); err != nil {
		log.Printf("Cleaning temporary code scans: %v", err)
	}

	if *sample {
		if err := addSample(db); err != nil {
			return err
		}
	}
	desktop.engine, err = engine.New(db)
	if err != nil {
		return err
	}

	app := application.New(application.Options{
		Name:  "Vulman",
		Mac:   application.MacOptions{ApplicationShouldTerminateAfterLastWindowClosed: true},
		Linux: application.LinuxOptions{ApplicationID: "com.vulman.app"},
		// Wails debug logs binding arguments, which can include API credentials.
		LogLevel: slog.LevelInfo,
		Assets: application.AssetOptions{
			Handler: assets, DisableLogging: true,
		},
		DisableDefaultSignalHandler: true,
		OnShutdown: func() {
			if err := closeStore(); err != nil {
				log.Printf("Closing Vulman data: %v", err)
			}
		},
	})

	desktop.openBrowser = app.Browser.OpenURL
	app.RegisterService(application.NewService(desktop))
	window := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Name: "vulman", Title: "Vulman", URL: "/#overview",
		Width: 1350, Height: 900, MinWidth: 720, MinHeight: 520,
		DefaultContextMenuDisabled: true,
	})

	if runtime.GOOS == "darwin" {
		// The macOS Edit menu handles Cmd+A before the WebView sees a key event.
		menu := application.DefaultApplicationMenu()
		if selectAll := menu.FindByRole(application.SelectAll); selectAll != nil {
			selectAll.SetRole(application.NoRole).OnClick(func(*application.Context) {
				window.ExecJS(`window.dispatchEvent(new Event('vulman-select-all'))`)
			})
			app.Menu.Set(menu)
		}
	}

	desktop.chooseDirectory = func(title, directory string) (string, error) {
		return app.Dialog.OpenFile().AttachToWindow(window).SetTitle(title).
			SetDirectory(directory).CanChooseDirectories(true).CanChooseFiles(false).
			PromptForSingleSelection()
	}

	select {
	case <-termination:
		return nil
	default:
	}

	appStopped := make(chan struct{})
	defer close(appStopped)
	go func() {
		select {
		case <-termination:
			// Finish disk work even if the native event loop is busy.
			_ = closeStore() // OnShutdown reports the result.
			application.InvokeAsync(app.Quit)
		case <-appStopped:
		}
	}()

	return app.Run()
}
