package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"vulman/internal/store"
)

func seedWorkspace(t *testing.T, dir, name string) {
	t.Helper()
	db, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = (&Desktop{store: db}).CreateProject(ProjectInput{Name: name, Schedule: "off"})
	if err := errors.Join(err, db.Close()); err != nil {
		t.Fatal(err)
	}
}

func TestChangeDataDirectorySwitchesAndFallsBack(t *testing.T) {
	root := t.TempDir()
	defaultDir := filepath.Join(root, "Vulman")
	other := filepath.Join(root, "other")
	seedWorkspace(t, defaultDir, "Default project")
	seedWorkspace(t, other, "Alternate project")
	db, eng, err := openWorkspace(defaultDir, true)
	if err != nil {
		t.Fatal(err)
	}
	d := &Desktop{store: db, engine: eng, defaultDirectory: defaultDir}
	t.Cleanup(func() {
		if err := d.close(); err != nil {
			t.Error(err)
		}
	})
	initial, err := d.State()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ChangeDataDirectory(other); err != nil {
		t.Fatal(err)
	}
	updated, err := d.StateSince(initial.Version)
	if err != nil || updated.State == nil || updated.DataDirectory != other || len(updated.Projects) != 1 || updated.Projects[0].Name != "Alternate project" || updated.StorageWarning != "" {
		t.Fatalf("switch did not load alternate workspace: %+v, %v", updated, err)
	}
	if saved, err := readDataDirectory(defaultDir); err != nil || saved != other {
		t.Fatalf("saved directory %q: %v", saved, err)
	}
	if reopened, err := store.OpenExisting(defaultDir); err != nil {
		t.Fatalf("previous workspace stayed locked: %v", err)
	} else if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	empty := filepath.Join(root, "empty")
	if err := os.Mkdir(empty, 0700); err != nil {
		t.Fatal(err)
	}
	missingKey := filepath.Join(root, "missing key")
	seedWorkspace(t, missingKey, "Missing key")
	if err := os.Remove(filepath.Join(missingKey, "vulman.key")); err != nil {
		t.Fatal(err)
	}
	corrupt := filepath.Join(root, "corrupt")
	seedWorkspace(t, corrupt, "Corrupt project")
	if err := os.WriteFile(filepath.Join(corrupt, "vulman.db"), []byte("broken database"), 0600); err != nil {
		t.Fatal(err)
	}
	wrongKey := filepath.Join(root, "wrong key")
	seedWorkspace(t, wrongKey, "Wrong key project")
	differentKey := make([]byte, 32)
	if err := os.WriteFile(filepath.Join(wrongKey, "vulman.key"), differentKey, 0600); err != nil {
		t.Fatal(err)
	}
	invalidKey := filepath.Join(root, "invalid key")
	seedWorkspace(t, invalidKey, "Invalid key project")
	if err := os.Truncate(filepath.Join(invalidKey, "vulman.key"), 16); err != nil {
		t.Fatal(err)
	}
	for _, choice := range []struct{ path, warning string }{
		{empty, "dataDirectoryEmpty"}, {missingKey, "dataDirectoryEmpty"}, {corrupt, "dataDirectoryUnreadable"},
		{wrongKey, "dataDirectoryUnreadable"}, {invalidKey, "dataDirectoryUnreadable"},
	} {
		t.Run(filepath.Base(choice.path), func(t *testing.T) {
			if err := d.ChangeDataDirectory(other); err != nil {
				t.Fatal(err)
			}
			if err := d.ChangeDataDirectory(choice.path); err != nil {
				t.Fatal(err)
			}
			state, err := d.State()
			if err != nil || state.DataDirectory != defaultDir || len(state.Projects) != 1 || state.Projects[0].Name != "Default project" || state.StorageWarning != choice.warning {
				t.Fatalf("fallback did not restore default workspace: %+v, %v", state, err)
			}
			if saved, err := readDataDirectory(defaultDir); err != nil || saved != defaultDir {
				t.Fatalf("saved fallback directory %q: %v", saved, err)
			}
		})
	}
	if entries, err := os.ReadDir(empty); err != nil || len(entries) != 0 {
		t.Fatalf("empty selection was modified: %v, %v", entries, err)
	}
	if _, err := os.Stat(filepath.Join(missingKey, "vulman.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing key was created: %v", err)
	}
}

func TestSavedDataDirectoryRestoresAndRecoversOnStartup(t *testing.T) {
	root := t.TempDir()
	defaultDir := filepath.Join(root, "Vulman")
	other := filepath.Join(root, "stored")
	seedWorkspace(t, other, "Stored project")
	if err := saveDataDirectory(defaultDir, other); err != nil {
		t.Fatal(err)
	}
	db, warning, err := openSavedWorkspace(defaultDir)
	if err != nil {
		t.Fatal(err)
	}
	state, readErr := db.Read()
	if err := errors.Join(readErr, db.Close()); err != nil {
		t.Fatal(err)
	}
	if warning != "" || len(state.Projects) != 1 || state.Projects[0].Name != "Stored project" {
		t.Fatalf("did not restore saved workspace: %q, %+v", warning, state.Projects)
	}
	if err := os.Remove(filepath.Join(other, "vulman.db")); err != nil {
		t.Fatal(err)
	}
	db, warning, err = openSavedWorkspace(defaultDir)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(db.Paths().Database)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if dir != defaultDir || warning != "dataDirectoryEmpty" {
		t.Fatalf("got %q and %q for missing saved workspace", dir, warning)
	}
	if saved, err := readDataDirectory(defaultDir); err != nil || saved != defaultDir {
		t.Fatalf("saved fallback directory %q: %v", saved, err)
	}
}
