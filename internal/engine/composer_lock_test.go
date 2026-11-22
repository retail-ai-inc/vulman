package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/testutil"
)

func TestNativePHPScanQueuesForPackagistAndKeepsUnassessedCoverage(t *testing.T) {
	s, e := controlEngine(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"v1.2.3"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := s.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"composer-lock": true}
		st.Settings.OSVEcosystems = []string{"Packagist"}
		st.Settings.OSVUpdateSchedule = "off"
		st.Projects[0] = model.Project{ID: "p", ScanCode: true, LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"composer-lock"}}}, Findings: []model.Finding{
			{ID: "previous-native", AssetID: scanner.FindingAssetID("local", "", "vendor/package"), Match: "scanner", Sources: []string{scanner.ComposerLockLabel}},
			{ID: "other-tool", AssetID: scanner.FindingAssetID("local", "", "vendor/package"), Match: "scanner", Sources: []string{"composer audit"}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	raw := json.RawMessage(fmt.Sprintf(`{"id":"GHSA-test","modified":%q,"summary":"Example","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Packagist","name":"vendor/package"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`, old))
	transport := testutil.NewOSVTransport(t, "Packagist", []json.RawMessage{raw})
	started, release := make(chan struct{}), make(chan struct{})
	signal, unblock := sync.OnceFunc(func() { close(started) }), sync.OnceFunc(func() { close(release) })
	t.Cleanup(unblock)
	e.OSV.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		signal()
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return transport.RoundTrip(r)
	})
	if err := e.UpdateOSVDatabase(); err != nil {
		t.Fatal(err)
	}
	signalControl(t, started)
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p := waitControlStatus(t, s, "queued")
	if len(p.Runs[0].DatabaseWaits) != 1 || p.Runs[0].DatabaseWaits[0].Source != "osv:Packagist" {
		t.Fatalf("native scan did not wait for its local data: %+v", p.Runs[0])
	}
	unblock()
	p = awaitRun(t, s)
	if p.Runs[0].Status != "complete" || len(p.Findings) != 2 {
		t.Fatalf("native scan failed: %+v", p)
	}
	if slices.ContainsFunc(p.Findings, func(item model.Finding) bool { return item.ID == "previous-native" }) || !slices.ContainsFunc(p.Findings, func(item model.Finding) bool { return item.ID == "other-tool" }) {
		t.Fatalf("native scan changed another tool's coverage: %+v", p.Findings)
	}
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"dev-main"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// Scanning uses only the active local snapshot, even with vulnerability API sources off.
	if err := s.Update(func(st *model.State) error { st.Settings.Sources = map[string]bool{}; return nil }); err != nil {
		t.Fatal(err)
	}
	e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
		t.Error("native scan contacted a vulnerability API")
		return nil, context.Canceled
	})
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p = awaitRun(t, s)
	if p.Runs[0].Status == "complete" || len(p.Findings) != 2 || p.Runs[0].RetainedScannerFindings < 1 {
		t.Fatalf("unsupported branch cleared previous native results: %+v", p)
	}
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"2.0.0"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p = awaitRun(t, s)
	if p.Runs[0].Status != "complete" || len(p.Findings) != 1 || p.Findings[0].ID != "other-tool" {
		t.Fatalf("fixed native dependency retained a resolved finding or changed another tool's result: %+v", p)
	}
}
