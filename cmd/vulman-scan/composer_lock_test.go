package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vulman/internal/osvdb"
	"vulman/internal/store"
	"vulman/internal/testutil"
)

func TestStandaloneNativePHPScannerUsesLocalCatalogueReadOnly(t *testing.T) {
	workspace, project := t.TempDir(), t.TempDir()
	s, err := store.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	db, err := s.OpenOSVDatabase()
	if err != nil {
		t.Fatal(err)
	}
	u := osvdb.NewUpdater(db)
	old := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	raw := json.RawMessage(fmt.Sprintf(`{"id":"GHSA-test","modified":%q,"summary":"Example","affected":[{"package":{"ecosystem":"Packagist","name":"vendor/package"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`, old))
	u.HTTP.Transport = testutil.NewOSVTransport(t, "Packagist", []json.RawMessage{raw})
	if err := u.Start(context.Background(), []string{"Packagist"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		stats, err := u.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if !stats.Running {
			if stats.Phase != "complete" {
				t.Fatalf("local fixture import failed: %+v", stats)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("local fixture import timed out")
		}
		time.Sleep(time.Millisecond)
	}
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	files := []string{"vulman.db", "vulman.key", osvdb.Filename}
	root, err := os.OpenRoot(workspace)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	before := map[string][32]byte{}
	for _, file := range files {
		data, err := root.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		before[file] = sha256.Sum256(data)
	}
	if err := os.WriteFile(filepath.Join(project, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"v1.2.3"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--scanners", "composer-lock", "--dir", project, "--data-dir", workspace}, &stdout, &stderr)
	var report scanReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid native report: %v %s", err, &stderr)
	}
	if code != 1 || report.Status != "complete" || len(report.Findings) != 1 || len(report.Scanners) != 1 || report.Scanners[0].Name != "composer-lock" || stderr.Len() != 0 {
		t.Fatalf("native CLI failed without PHP/Composer: %d %s %s", code, &stdout, &stderr)
	}
	for _, file := range files {
		data, err := root.ReadFile(file)
		if err != nil || sha256.Sum256(data) != before[file] {
			t.Fatalf("read-only scan changed %s: %v", file, err)
		}
	}
}

func TestStandaloneNativePHPScannerDoesNotCreateMissingDatabases(t *testing.T) {
	workspace := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--scanners", "composer-lock", "--data-dir", workspace}, &stdout, &stderr)
	entries, err := os.ReadDir(workspace)
	if code != 2 || err != nil || len(entries) != 0 {
		t.Fatalf("missing catalogue initialized a workspace: %d %v %v", code, entries, err)
	}
	for _, args := range [][]string{
		{"--scanners", "composer-lock"},
		{"--scanners", "composer", "--ignore-composer-platform"},
		{"--scanners", "npm", "--generate-lockfiles", "--ignore-composer-platform"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stderr.Len() == 0 {
			t.Fatalf("invalid native/platform arguments accepted: %v, %d", args, code)
		}
	}
}
