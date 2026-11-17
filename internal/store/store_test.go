package store

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"vulman/internal/model"
)

func TestEncryptedPersistenceAndRollback(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Update(func(st *model.State) error {
		st.Settings.Tokens["openai"] = "secret-test-token"
		st.Projects = append(st.Projects, model.Project{ID: "one", Name: "Private project"})
		return nil
	})

	if err != nil {
		t.Fatal(err)
	}

	rollback := errors.New("rollback")
	if err = s.Update(func(st *model.State) error { st.Projects = nil; return rollback }); err != rollback {
		t.Fatal(err)
	}

	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	raw := readTestDatabase(t, dir)
	for _, secret := range []string{"secret-test-token", "Private project"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("plaintext state found in database")
		}
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	state, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}

	if len(state.Projects) != 1 || state.Settings.Tokens["openai"] != "secret-test-token" {
		t.Fatal("state not preserved")
	}
}

func readTestDatabase(t *testing.T, dir string) []byte {
	t.Helper()
	f, err := os.OpenInRoot(dir, databaseFile)
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestStoreRejectsSymlinksOutsideDataDirectory(t *testing.T) {
	for _, name := range []string{keyFile, databaseFile} {
		t.Run(name, func(t *testing.T) {
			dir, outsideDir := t.TempDir(), t.TempDir()
			var data []byte
			if name == keyFile {
				data = make([]byte, keySize)
			} else if err := os.WriteFile(filepath.Join(dir, keyFile), make([]byte, keySize), 0600); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(outsideDir, name)
			if err := os.WriteFile(outside, data, 0600); err != nil {
				t.Fatal(err)
			}
			target, err := filepath.Rel(dir, outside)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
				if runtime.GOOS == "windows" {
					t.Skipf("creating a symlink requires Windows developer mode or privileges: %v", err)
				}
				t.Fatal(err)
			}
			if s, err := Open(dir); err == nil {
				closeTestStore(t, s)
				t.Fatal("opened a symlink to a file outside the data directory")
			}
			info, err := os.Stat(outside)
			if err != nil {
				t.Fatal(err)
			}
			if info.Size() != int64(len(data)) {
				t.Fatal("external file was modified")
			}
		})
	}
}

func TestMissingKeyDoesNotReplaceExistingDatabase(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "vulman.db"), []byte("existing database"), 0600); err != nil {
		t.Fatal(err)
	}

	if s, err := Open(dir); err == nil {
		closeTestStore(t, s)
		t.Fatal("opened database without key")
	}

	if _, err := os.Stat(filepath.Join(dir, "vulman.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("created a replacement key")
	}
}

func TestRelativeDataDirectoryReportsAbsoluteStoragePaths(t *testing.T) {
	t.Chdir(t.TempDir())
	s, err := Open(filepath.Join("custom", "vulman-data"))
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	paths := s.Paths()
	for _, path := range []string{paths.Database, paths.Key} {
		if !filepath.IsAbs(path) {
			t.Fatalf("relative storage path: %s", path)
		}

		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}

	if filepath.Base(paths.Database) != "vulman.db" || filepath.Base(paths.Key) != "vulman.key" || filepath.Dir(paths.Database) != filepath.Dir(paths.Key) {
		t.Fatalf("wrong storage paths: %+v", paths)
	}
}
