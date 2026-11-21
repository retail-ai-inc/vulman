package main

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/cvedb"
	"vulman/internal/model"
	"vulman/internal/store"
)

func catalogueFileHashes(t *testing.T, directory string) map[string][32]byte {
	t.Helper()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()

	hashes := make(map[string][32]byte)
	for _, name := range []string{"vulman-cve.db", "vulman-nvd.db", "vulman-osv.db", "vulman.key"} {
		file, err := root.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(file)
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("could not read catalogue %s: %v, %v", name, readErr, closeErr)
		}
		hashes[name] = sha256.Sum256(data)
	}
	return hashes
}

func TestDesktopClearAPIResponseCacheKeepsCataloguesAndProjectData(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	if _, err := desktop.CreateProject(ProjectInput{Name: "Keep project", Schedule: "off"}); err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(st *model.State) error {
		st.Projects[0].Findings = []model.Finding{{ID: "CVE-2026-1234", Severity: "CRITICAL"}}
		st.Projects[0].Runs = []model.Run{{ID: "previous", Status: "complete", Count: 1}}
		st.Settings.Tokens["github"] = "fixture"
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	cve, err := db.OpenCVEDatabase()
	if err != nil {
		t.Fatal(err)
	}
	if err := cve.Put(cvedb.Record{ID: "CVE-2026-1234", State: "PUBLISHED", Title: "Keep this advisory", CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := cve.Close(); err != nil {
		t.Fatal(err)
	}
	nvd, err := db.OpenNVDDatabase()
	if err != nil {
		t.Fatal(err)
	}
	if err := nvd.Close(); err != nil {
		t.Fatal(err)
	}
	osv, err := db.OpenOSVDatabase()
	if err != nil {
		t.Fatal(err)
	}
	if err := osv.Close(); err != nil {
		t.Fatal(err)
	}

	if err := db.CachePut("api-response", store.CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	before, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(db.Paths().Database)
	hashes := catalogueFileHashes(t, directory)
	stats, err := desktop.ClearAPIResponseCache()
	if err != nil || stats.Entries != 0 || stats.Bytes != 0 {
		t.Fatalf("cache was not cleared: %+v, %v", stats, err)
	}
	after, err := db.Read()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("clearing API responses changed project data or settings", err)
	}
	if !reflect.DeepEqual(hashes, catalogueFileHashes(t, directory)) {
		t.Fatal("clearing API responses modified a local catalogue or encryption key")
	}
	unchanged, err := desktop.StateSince(initial.Version)
	if err != nil || unchanged.State != nil || unchanged.CacheStats.Entries != 0 {
		t.Fatal("cache clearing changed the workspace version or failed to update cache metrics", err)
	}

	desktop.closed = true
	if _, err := desktop.ClearAPIResponseCache(); err == nil || apperror.Public(err).Code != "application_is_stopping" {
		t.Fatal("cache clear was accepted during shutdown")
	}
}
