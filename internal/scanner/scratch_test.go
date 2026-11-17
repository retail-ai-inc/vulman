package scanner

import (
	"errors"
	"io/fs"
	"path/filepath"
	"runtime"
	"testing"
)

func TestScanScratchCleanupPreservesLiveScans(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	root, err := openScratchRoot("", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	active, err := newScanScratch(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := active.remove(); err != nil {
			t.Error(err)
		}
	})
	abandoned, err := newScanScratch(root)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(abandoned.name, "cache")
	if err := root.Mkdir(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(filepath.Join(cache, "source.go"), []byte("package fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := root.Chmod(cache, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	if err := abandoned.lease.Close(); err != nil {
		t.Fatal(err)
	}
	if err := CleanScanScratch(""); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Stat(active.name); err != nil {
		t.Fatalf("cleanup removed a live scan: %v", err)
	}
	for _, name := range []string{abandoned.name, abandoned.name + ".lease"} {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("cleanup retained an abandoned scan: %v", err)
		}
	}
}

func TestScanScratchRejectsWorkspaceAsTempDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("TMPDIR", dir)
	t.Setenv("TMP", dir)
	t.Setenv("TEMP", dir)
	if root, err := openScratchRoot(dir, true); err == nil {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
		t.Fatal("allowed temporary scan files inside the workspace")
	}
}
