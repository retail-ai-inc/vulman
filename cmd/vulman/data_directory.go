package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"vulman/internal/engine"
	"vulman/internal/store"
)

const dataDirectoryPreference = "data-directory.json"

func readDataDirectory(defaultDir string) (string, error) {
	root, err := os.OpenRoot(defaultDir)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	defer func() { _ = root.Close() }()

	file, err := root.Open(dataDirectoryPreference)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	data, readErr := io.ReadAll(io.LimitReader(file, 64<<10))
	if err := errors.Join(readErr, file.Close()); err != nil {
		return "", err
	}

	var dir string
	if err := json.Unmarshal(data, &dir); err != nil {
		return "", err
	}

	if !filepath.IsAbs(dir) {
		return "", errors.New("invalid saved data directory")
	}

	return dir, nil
}

func saveDataDirectory(defaultDir, dir string) error {
	if err := os.MkdirAll(defaultDir, 0700); err != nil {
		return err
	}

	file, err := os.CreateTemp(defaultDir, ".data-directory-*")
	if err != nil {
		return err
	}

	defer func() { _ = os.Remove(file.Name()) }()

	err = json.NewEncoder(file).Encode(dir)
	if err == nil {
		err = file.Sync()
	}

	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}

	return os.Rename(file.Name(), filepath.Join(defaultDir, dataDirectoryPreference))
}

func sameDirectory(a, b string) bool {
	if a == b {
		return true
	}

	first, err := os.Stat(a)
	if err != nil {
		return false
	}

	second, err := os.Stat(b)
	return err == nil && os.SameFile(first, second)
}

func dataDirectoryWarning(err error) string {
	if errors.Is(err, store.ErrMissingWorkspaceFiles) || errors.Is(err, os.ErrNotExist) {
		return "dataDirectoryEmpty"
	}

	return "dataDirectoryUnreadable"
}

func openSavedWorkspace(defaultDir string) (*store.Store, string, error) {
	dir, err := readDataDirectory(defaultDir)
	warning := ""

	if err != nil {
		warning = "dataDirectoryUnreadable"
	} else if dir != "" && !sameDirectory(dir, defaultDir) {
		db, err := store.OpenExisting(dir)
		if err == nil {
			return db, "", nil
		}

		warning = dataDirectoryWarning(err)
	}

	db, err := store.Open(defaultDir)
	if err == nil && warning != "" {
		if saveErr := saveDataDirectory(defaultDir, defaultDir); saveErr != nil {
			log.Printf("Saving default data directory: %v", saveErr)
		}
	}

	return db, warning, err
}

func openWorkspace(dir string, isDefault bool) (*store.Store, *engine.Engine, error) {
	open := store.OpenExisting
	if isDefault {
		open = store.Open
	}

	db, err := open(dir)
	if err != nil {
		return nil, nil, err
	}

	eng, err := engine.New(db)
	if err != nil {
		return nil, nil, errors.Join(err, db.Close())
	}

	return db, eng, nil
}

// ChangeDataDirectory switches workspaces after opening the replacement fully.
func (d *Desktop) ChangeDataDirectory(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.closed {
		return errors.New("application is stopping")
	}

	if path == "" {
		path = d.defaultDirectory
	}

	target, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	current := filepath.Dir(d.store.Paths().Database)
	isDefault := sameDirectory(target, d.defaultDirectory)
	if isDefault {
		target = d.defaultDirectory
	}

	var next *store.Store
	var nextEngine *engine.Engine
	warning := ""
	if !sameDirectory(target, current) {
		next, nextEngine, err = openWorkspace(target, isDefault)

		if err != nil && !isDefault {
			warning = dataDirectoryWarning(err)
			target = d.defaultDirectory
			err = nil

			if !sameDirectory(target, current) {
				next, nextEngine, err = openWorkspace(target, true)
			}
		}

		if err != nil {
			return fmt.Errorf("could not open the default data directory: %w", err)
		}
	} else if !isDefault {
		target = current
	}

	if err := saveDataDirectory(d.defaultDirectory, target); err != nil {
		if next != nil {
			nextEngine.Close()
			err = errors.Join(err, next.Close())
		}

		return fmt.Errorf("could not save the data directory: %w", err)
	}

	d.storageWarning = warning

	if next != nil {
		d.engine.Close()
		if err := d.store.Close(); err != nil {
			log.Printf("Closing previous workspace: %v", err)
		}

		d.store, d.engine = next, nextEngine
		d.workspaceGeneration++
	}

	return nil
}

func (d *Desktop) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true

	if d.engine != nil {
		d.engine.Close()
	}

	return d.store.Close()
}
