package engine

import (
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/testutil"
)

func TestLiveWorkflowThenCompletedHistory(t *testing.T) {
	s := testStore(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/nvd":
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			body = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001"}}]}`
		case "/osv":
			body = `{"vulns":[{"id":"GHSA-demo","aliases":["CVE-2024-0001"]}]}`
		case "/cve/CVE-2024-0001":
			body = `{"cveMetadata":{"state":"PUBLISHED"},"containers":{"cna":{"title":"Test advisory"}}}`
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		if _, err := fmt.Fprint(w, body); err != nil {
			t.Errorf("write mock response for %s: %v", r.URL.Path, err)
		}
	}))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.NVDURL = server.URL + "/nvd"
		st.Settings.OSVURL = server.URL + "/osv"
		st.Settings.CVEURL = server.URL + "/cve"
		st.Settings.Sources["osv"] = true
		st.Projects = []model.Project{{ID: "p", Revision: 1, Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not start")
	}
	st, _ := s.Read()
	run := st.Projects[0].Runs[0]
	if len(run.Steps) != 4 || run.Steps[0].Status != "running" || run.Steps[1].Status != "pending" || len(run.Logs) < 2 {
		t.Fatalf("live progress not persisted: %+v", run)
	}
	close(release)
	p := awaitRun(t, s)
	run = p.Runs[0]
	if run.Status != "complete" || len(p.Findings) != 1 {
		t.Fatalf("assessment failed: %+v", run)
	}
	for _, step := range run.Steps {
		if step.Status != "complete" || step.FinishedAt.IsZero() {
			t.Fatalf("unfinished step: %+v", step)
		}
	}
	if run.Steps[2].Progress.Processed != 1 || run.Steps[2].Progress.Total != 1 {
		t.Fatal("CVE record progress missing")
	}
	if run.Logs[len(run.Logs)-1].Event != "run_finished" {
		t.Fatal("completion not logged")
	}
}

func TestScannerWorkflowLogsConfiguredToolsAndSkipReasons(t *testing.T) {
	s := testStore(t)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": false}
		st.Settings.Scanners = map[string]bool{"govulncheck": true, "trivy": true}
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, tc := range []struct {
		assetID, mode, event, status string
		scanCode                     bool
	}{
		{"a", "auto", "scanner_skipped_component", "complete", true},
		{"", "auto", "scanner_skipped_disabled", "complete", false},
		{"", "local", "scanner_skipped_cache", "failed", true},
	} {
		t.Run(tc.event, func(t *testing.T) {
			if err := s.Update(func(st *model.State) error {
				st.Projects[0].ScanCode = tc.scanCode
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := e.StartAssetMode("p", "manual", tc.assetID, tc.mode); err != nil {
				t.Fatal(err)
			}
			run := awaitRun(t, s).Runs[0]
			if run.Status != tc.status {
				t.Fatalf("run status = %s, want %s", run.Status, tc.status)
			}
			var events []string
			for _, entry := range run.Logs {
				if entry.StepID == "scanner" {
					events = append(events, entry.Event+":"+entry.Detail)
				}
			}
			if strings.Join(events, "|") != "scanner_configured:govulncheck,trivy|"+tc.event+":" {
				t.Fatalf("scanner logs = %+v", events)
			}
		})
	}
}

func TestScannerWorkflowLogsIndividualResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("demo==1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"go.mod", "composer.json", "composer.lock"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	t.Setenv("SNYK_TOKEN", "")
	for name, script := range map[string]string{
		"govulncheck": `echo '{"config":{"scanner_name":"govulncheck"}}'`,
		"composer":    "exit 2",
		"pip-audit":   `echo '{"dependencies":[{"name":"demo","version":"1.0","vulns":[{"id":"PYSEC-2024-1"}]}]}'; exit 1`,
		"trivy":       `echo '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"demo","Severity":"HIGH"}]}]}'`,
	} {
		testutil.WriteShellFixture(t, dir, name, script)
	}
	s := testStore(t)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": false}
		st.Settings.Scanners = map[string]bool{"govulncheck": true, "composer": true, "pip-audit": true, "trivy": true, "snyk": true}
		st.Projects = []model.Project{{ID: "p", ScanCode: true, LocalPath: dir}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.StartFiltered("p", "manual", "", "auto", "CRITICAL"); err != nil {
		t.Fatal(err)
	}
	run := awaitRun(t, s).Runs[0]
	var events []string
	for _, entry := range run.Logs {
		if entry.StepID != "scanner" {
			continue
		}
		detail := entry.Event + ":" + entry.Detail
		if entry.Findings != nil {
			detail += fmt.Sprintf(":%d", *entry.Findings)
		}
		events = append(events, detail)
	}
	got := strings.Join(events, "\n")
	for _, want := range []string{
		"scanner_configured:govulncheck,composer,pip-audit,trivy,snyk",
		"scanning:govulncheck\nscanner_completed:govulncheck:0",
		"scanning:composer\nscanner_failed:composer · exit 2",
		"scanning:pip-audit\nscanner_completed:pip-audit:1",
		"scanning:trivy\nscanner_completed:trivy:1",
		"scanner_missing_token:snyk",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in scanner logs:\n%s", want, got)
		}
	}
	if run.Count != 0 || strings.Contains(got, "scanning:snyk") {
		t.Fatalf("severity filtering or token skip was ignored: %+v", run)
	}
}

func TestCodeScanRefreshesOnlyScannerFindings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("SNYK_TOKEN", "")
	t.Setenv("VULMAN_TEST_EMPTY_TRIVY", "")
	testutil.WriteShellFixture(t, dir, "trivy", `
if [ "$VULMAN_TEST_EMPTY_TRIVY" = "1" ]; then
	echo '{"SchemaVersion":2,"Results":[]}'
else
	echo '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-scanner-new","PkgName":"demo","Severity":"HIGH"},{"VulnerabilityID":"CVE-scanner-new","PkgName":"demo","Severity":"LOW"}]}]}'
fi`)
	s := testStore(t)
	lastSync := time.Now().Add(-time.Hour)
	nextRun := time.Now().Add(time.Hour)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": true, "cve": true, "osv": true}
		st.Settings.Scanners = map[string]bool{"trivy": true}
		st.Projects = []model.Project{{
			ID: "p", LocalPath: dir, ScanCode: true, Schedule: "weekly", NextRun: nextRun,
			LastSync: lastSync, DataCheckedAt: lastSync, Revision: 2, AssessedRevision: 1,
			Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}},
			Findings: []model.Finding{
				{ID: "CVE-inventory", AssetID: "a", Match: "cpe", Severity: "CRITICAL"},
				{ID: "CVE-scanner-old", AssetID: "code:demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "HIGH"},
			},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		t.Errorf("code scan contacted an advisory database: %s", r.URL)
		return nil, fmt.Errorf("unexpected advisory request")
	})
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	run := p.Runs[0]
	if run.Mode != codeScanMode || run.Status != "complete" || len(run.Steps) != 2 || run.Steps[0].Kind != "scanner" || run.Steps[1].Kind != "save" || run.Count != 1 {
		t.Fatalf("unexpected code scan: %+v", run)
	}
	wantSeverities := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	if !maps.Equal(run.SeverityCounts, wantSeverities) {
		t.Fatalf("unexpected severity totals: %v", run.SeverityCounts)
	}
	if len(p.Findings) != 2 || p.Findings[0].ID != "CVE-inventory" || p.Findings[1].ID != "CVE-scanner-new" {
		t.Fatalf("unexpected findings: %+v", p.Findings)
	}
	if !p.LastSync.Equal(lastSync) || !p.DataCheckedAt.Equal(lastSync) || !p.NextRun.Equal(nextRun) || p.AssessedRevision != 1 {
		t.Fatalf("code scan changed full-project assessment metadata: %+v", p)
	}
	if err := s.Update(func(st *model.State) error {
		st.Settings.Scanners["snyk"] = true
		st.Projects[0].Findings[1].ID = "CVE-scanner-retained"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p = awaitRun(t, s)
	if p.Runs[0].Status != "partial" || len(p.Findings) != 3 || p.Findings[2].ID != "CVE-scanner-retained" {
		t.Fatalf("incomplete scan lost previous findings: %+v", p)
	}
	if p.Runs[0].SeverityCounts != nil || !maps.Equal(p.Runs[1].SeverityCounts, wantSeverities) {
		t.Fatalf("partial scan affected saved severity totals: %+v", p.Runs)
	}
	t.Setenv("VULMAN_TEST_EMPTY_TRIVY", "1")
	if err := s.Update(func(st *model.State) error {
		st.Settings.Scanners["snyk"] = false
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p = awaitRun(t, s)
	wantZero := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	if p.Runs[0].Status != "complete" || p.Runs[0].Count != 0 || !maps.Equal(p.Runs[0].SeverityCounts, wantZero) {
		t.Fatalf("empty scan did not save zero severity counts: %+v", p.Runs[0])
	}
}

func TestCodeScanChecksRepositoryLocationsIndependently(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	cloneRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("VULMAN_TEST_SCAN_ROOT", cloneRoot)
	for name, script := range map[string]string{
		"git": `for arg in "$@"; do
  case "$arg" in https://*) repository="$arg";; esac
  destination="$arg"
done
case "$repository" in
  */missing.git) /bin/mkdir -p "$destination" && printf 'partial checkout' > "$destination/version"; exit 2;;
  */second.git) version=3.0.0;;
  *) version=2.0.0;;
esac
case "$destination" in
  "$VULMAN_TEST_SCAN_ROOT"/vulman-scans-*/*/*) ;;
  *) exit 2;;
esac
/bin/mkdir -p "$destination" || exit 2
printf '%s' "$version" > "$destination/version"`,
		"trivy": `version=1.0.0
case "$TRIVY_CACHE_DIR" in
  "$VULMAN_TEST_SCAN_ROOT"/vulman-scans-*/*/trivy) ;;
  *) exit 2;;
esac
/bin/mkdir -p "$TRIVY_CACHE_DIR" || exit 2
printf 'scan cache' > "$TRIVY_CACHE_DIR/scan"
if [ -f version ]; then version=$(/bin/cat version); fi
printf '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-both","PkgName":"demo","InstalledVersion":"%s","Severity":"HIGH"}]}]}' "$version"`,
	} {
		testutil.WriteShellFixture(t, dir, name, script)
	}
	s := testStore(t)
	t.Setenv("TMPDIR", cloneRoot)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"trivy": true}
		st.Projects = []model.Project{{ID: "p", ScanCode: true, LocalPath: dir, Repository: "https://github.com/owner/project.git",
			ScannerProfiles: map[string]model.ScannerProfile{scanner.RemoteTargetKey("https://github.com/owner/project.git"): {Mode: "custom", Tools: []string{"trivy"}}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if p.Runs[0].Status != "complete" || p.Runs[0].Count != 2 || len(p.Findings) != 2 || p.Findings[0].AssetID == p.Findings[1].AssetID {
		t.Fatalf("findings from both targets were not saved separately: %+v", p)
	}
	targets := p.Runs[0].ScanTargets
	if len(targets) != 2 || targets[0] != "local" || targets[1] != scanner.RemoteTargetKey(p.Repository) {
		t.Fatalf("unexpected saved scan targets: %+v", targets)
	}
	versions := map[string]string{}
	for _, finding := range p.Findings {
		versions[finding.ScanTarget] = finding.Version
	}
	if versions["local"] != "1.0.0" || versions["remote"] != "2.0.0" {
		t.Fatalf("unexpected target versions: %+v", versions)
	}
	completed := map[string]bool{}
	cleaned := map[string]bool{}
	for _, entry := range p.Runs[0].Logs {
		switch entry.Event {
		case "scanner_completed":
			completed[entry.ScanTarget] = true
		case "scanner_cleanup_completed":
			if !completed[entry.ScanTarget] {
				t.Fatalf("cleanup preceded scanner completion for %s", entry.ScanTarget)
			}
			cleaned[entry.ScanTarget] = true
		}
	}
	if !cleaned["local"] || !cleaned["remote"] {
		t.Fatalf("missing target-specific cleanup logs: %+v", p.Runs[0].Logs)
	}
	assertScanScratchEmpty(t, cloneRoot)

	if err := s.Update(func(st *model.State) error {
		st.Projects[0].LocalPath = filepath.Join(dir, "missing")
		st.Projects[0].RepositoryURLs = []string{
			"https://gitlab.com/owner/legacy.git",
			"https://github.com/owner/missing.git",
			"https://github.com/owner/second.git?value=hidden",
			"https://github.com/owner/project.git",
		}
		for _, repository := range st.Projects[0].Repositories() {
			st.Projects[0].ScannerProfiles[scanner.RemoteTargetKey(repository)] = model.ScannerProfile{Mode: "custom", Tools: []string{"trivy"}}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := e.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	p = awaitRun(t, s)
	assertScanScratchEmpty(t, cloneRoot)
	var localFailed, remoteFailed, legacyRejected, cleanedAfterFailure bool
	remoteCompleted := map[string]bool{}
	for _, entry := range p.Runs[0].Logs {
		localFailed = localFailed || (entry.Event == "scanner_target_failed" && entry.ScanTarget == "local")
		remoteFailed = remoteFailed || (entry.Event == "scanner_target_failed" && entry.ScanRepository == "github.com/owner/missing.git")
		if entry.Event == "scanner_cleanup_completed" && entry.ScanRepository == "github.com/owner/missing.git" {
			cleanedAfterFailure = remoteFailed
		}
		if entry.ScanRepository == "gitlab.com/owner/legacy.git" {
			if entry.Event == "clone" {
				t.Fatal("legacy non-GitHub repository reached the clone step")
			}
			legacyRejected = legacyRejected || entry.Event == "scanner_target_failed"
		}
		if entry.Event == "scanner_completed" && entry.ScanTarget == "remote" {
			remoteCompleted[entry.ScanRepository] = true
		}
	}
	if p.Runs[0].Status != "partial" || !localFailed || !remoteFailed || !legacyRejected || !remoteCompleted["github.com/owner/project.git"] || !remoteCompleted["github.com/owner/second.git"] || len(p.Findings) != 3 {
		t.Fatalf("target failures blocked the other scans or removed prior findings: %+v", p)
	}
	if !cleanedAfterFailure {
		t.Fatal("temporary file cleanup was not logged after the failed clone")
	}
	remoteVersions := map[string]string{}
	for _, finding := range p.Findings {
		if finding.ScanTarget == "remote" {
			remoteVersions[finding.ScanRepository] = finding.Version
		}
	}
	if remoteVersions["github.com/owner/project.git"] != "2.0.0" || remoteVersions["github.com/owner/second.git"] != "3.0.0" {
		t.Fatalf("remote findings were combined or mislabeled: %+v", remoteVersions)
	}
}

func assertScanScratchEmpty(t *testing.T, temp string) {
	t.Helper()
	roots, err := os.ReadDir(temp)
	if err != nil || len(roots) != 1 || !roots[0].IsDir() {
		t.Fatalf("expected one scan storage directory: %v, %v", roots, err)
	}
	entries, err := os.ReadDir(filepath.Join(temp, roots[0].Name()))
	if err != nil || len(entries) != 0 {
		t.Fatalf("temporary scan files were not cleaned up: %v, %v", entries, err)
	}
}

func TestCancellationClosesWorkflowAndRetainsFindings(t *testing.T) {
	s := testStore(t)
	started := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.NVDURL = server.URL
		st.Settings.Sources["osv"] = true
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}, Findings: []model.Finding{{ID: "CVE-old", AssetID: "a"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	<-started
	e.Close()
	st, _ := s.Read()
	p := st.Projects[0]
	r := p.Runs[0]
	if p.Syncing || r.Status != "interrupted" || len(p.Findings) != 1 {
		t.Fatal("interrupted assessment was not finalized safely")
	}
	for _, step := range r.Steps {
		if step.Status == "pending" || step.Status == "running" {
			t.Fatalf("unfinished cancelled step: %+v", step)
		}
	}
}

func TestWorkflowLogLimitKeepsRecentEvents(t *testing.T) {
	r := model.Run{}
	for i := 0; i < model.MaxSyncLogs+10; i++ {
		addLog(&r, "step", "page", fmt.Sprint(i))
	}
	if len(r.Logs) != model.MaxSyncLogs || r.Logs[0].Detail != "10" || r.Logs[len(r.Logs)-1].Detail != fmt.Sprint(model.MaxSyncLogs+9) {
		t.Fatal("workflow logs were not bounded correctly")
	}
}
