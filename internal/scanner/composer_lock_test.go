package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/osvdb"
)

type localComposerCatalogue struct {
	records  []osvdb.Record
	calls    []string
	notReady bool
}

func (c *localComposerCatalogue) Query(ctx context.Context, ecosystem, name, version string) (osvdb.QueryResult, error) {
	if err := ctx.Err(); err != nil {
		return osvdb.QueryResult{}, err
	}
	if c.notReady {
		return osvdb.QueryResult{}, osvdb.ErrNotReady
	}
	c.calls = append(c.calls, ecosystem+":"+name+":"+version)
	result := osvdb.QueryResult{}
	for _, record := range c.records {
		matched, unknown := osvdb.Match(record, ecosystem, name, version)
		if matched || unknown {
			result.Records = append(result.Records, record)
		}
		result.Uncertain = result.Uncertain || unknown
	}
	return result, nil
}

func composerRecord(t *testing.T, name string) osvdb.Record {
	t.Helper()
	var record osvdb.Record
	raw := `{"id":"GHSA-test","aliases":["CVE-2026-1234"],"summary":"Example issue","database_specific":{"severity":"HIGH"},"affected":[{"package":{"ecosystem":"Packagist","name":"` + name + `"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func TestNativeComposerScanNeedsNoRuntimeAndIncludesMonorepoDevDependencies(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "php"), 0o700); err != nil {
		t.Fatal(err)
	}
	lock := `{"packages":[{"name":"Vendor/Package","version":"v1.2.3"}],"packages-dev":[{"name":"vendor/dev","version":"1.0.0"},{"name":"vendor/package","version":"v1.2.3"}]}`
	if err := os.WriteFile(filepath.Join(dir, "php", "composer.lock"), []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogue := &localComposerCatalogue{records: []osvdb.Record{composerRecord(t, "vendor/package"), composerRecord(t, "vendor/dev")}}
	p := model.Project{LocalPath: dir, ScanCode: true, ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"composer-lock"}}}}
	s := model.Settings{Scanners: map[string]bool{"composer-lock": true}}
	var jobs []model.ScannerJob
	report := ScanWithReport(context.Background(), p, s, "", func(event ScanEvent) {
		if event.Tool == "composer-lock" && event.Job != nil {
			jobs = append(jobs, *event.Job)
		}
	}, catalogue)
	if len(report.Problems) != 0 || len(report.Findings) != 2 || len(report.Completed) != 1 || report.Completed[0].Path != "php" {
		t.Fatalf("native scan failed without PHP/Composer: %+v", report)
	}
	for _, item := range report.Findings {
		if item.ScanPath != "php" || item.Match != "scanner" || item.ID != "CVE-2026-1234" || !strings.HasPrefix(item.AssetID, "code:local:path:") || len(item.FixedVersions) != 1 {
			t.Fatalf("native finding lost attribution: %+v", item)
		}
	}
	if jobs[len(jobs)-1].Status != "complete" || len(catalogue.calls) != 3 {
		t.Fatalf("duplicates were re-queried: %+v %v", jobs, catalogue.calls)
	}
	result, err := Check(context.Background(), "composer-lock", catalogue)
	if err != nil || result.Status != "ready" || result.Path != "" {
		t.Fatalf("native check tried to find an executable: %+v %v", result, err)
	}
}

func TestNativeComposerIncompleteCoverageRetainsConfirmedFindings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[{"name":"vendor/package","version":"1.2.3"},{"name":"vendor/unknown","version":"dev-main"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	catalogue := &localComposerCatalogue{records: []osvdb.Record{composerRecord(t, "vendor/package"), composerRecord(t, "vendor/unknown")}}
	p := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"composer-lock"}}}}
	report := ScanWithReport(context.Background(), p, model.Settings{Scanners: map[string]bool{"composer-lock": true}}, "", nil, catalogue)
	if len(report.Findings) != 1 || len(report.Completed) != 0 || len(report.Problems) != 1 || !strings.Contains(apperror.Public(report.Problems[0]).English(), "incomplete") {
		t.Fatalf("uncertain dependency produced a clean scan or discarded known findings: %+v", report)
	}
	for _, backend := range []LocalOSV{nil, &localComposerCatalogue{notReady: true}} {
		_, err := scanComposerLock(context.Background(), dir, backend)
		if err == nil || apperror.Public(err).Code != "composer_packagist_required" {
			t.Fatalf("missing local data was treated as clean: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanComposerLock(ctx, dir, catalogue); !errors.Is(err, context.Canceled) {
		t.Fatalf("native scan ignored cancellation: %v", err)
	}
}

func TestNativeComposerRejectsMalformedAndMissingLockfiles(t *testing.T) {
	for _, raw := range []string{`{}`, `{"packages":null}`, `{"packages":[{"name":"vendor/package"}]}`, `{"packages":[{"name":"../private","version":"1.0"}]}`, `{"packages":[],"packages-dev":{}}`, `invalid`} {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := scanComposerLock(context.Background(), dir, &localComposerCatalogue{}); err == nil || apperror.Public(err).Code != "composer_lock_invalid" {
			t.Fatalf("malformed lockfile was clean: %s, %v", raw, err)
		}
	}
	dir := t.TempDir()
	writeProjectFiles(t, dir, "composer.json")
	jobs, err := Plan(context.Background(), dir, model.ScannerProfile{Mode: "custom", Tools: []string{"composer-lock"}, GenerateLockfiles: true}, map[string]bool{"composer-lock": true})
	if err != nil || jobs[0].Tool != "composer-lock" || jobs[0].Status != "blocked" {
		t.Fatalf("native scan resolved a missing lockfile: %+v %v", jobs, err)
	}
}
