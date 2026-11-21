package engine

import (
	"maps"
	"net/http"
	"runtime"
	"slices"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/testutil"
)

func TestRepositoryScopedScansPreserveOtherResults(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}

	const repository = "https://github.com/owner/selected"
	const other = "https://github.com/owner/other"
	for _, target := range []string{scanner.RemoteTargetKey(repository), "local"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			t.Setenv("SNYK_TOKEN", "")
			t.Setenv("VULMAN_TEST_SCAN_FAIL", "")
			t.Setenv("VULMAN_TEST_SCAN_EMPTY", "")
			testutil.WriteShellFixture(t, dir, "git", `
repository=''
destination=''
for arg in "$@"; do
  case "$arg" in https://*) repository="$arg";; esac
  destination="$arg"
done
case "$repository" in
  https://github.com/owner/selected) /bin/mkdir -p "$destination";;
  *) exit 2;;
esac`)
			testutil.WriteShellFixture(t, dir, "trivy", `
if [ "$VULMAN_TEST_SCAN_FAIL" = 1 ]; then exit 2; fi
if [ "$VULMAN_TEST_SCAN_EMPTY" = 1 ]; then
  echo '{"SchemaVersion":2,"Results":[]}'
else
  echo '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-new","PkgName":"demo","Severity":"HIGH"},{"VulnerabilityID":"CVE-downgraded","PkgName":"demo","Severity":"LOW"}]}]}'
fi`)
			s := testStore(t)
			lastSync := time.Now().Add(-time.Hour)
			nextRun := time.Now().Add(time.Hour)
			prior := []model.Finding{
				{ID: "CVE-inventory", AssetID: "a", Match: "cpe", Severity: "CRITICAL"},
				{ID: "CVE-other", AssetID: "code:" + scanner.RemoteTargetKey(other) + ":demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "HIGH"},
				{ID: "CVE-resolved", AssetID: "code:" + target + ":demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "HIGH"},
				{ID: "CVE-downgraded", AssetID: "code:" + target + ":demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "HIGH"},
				{ID: "CVE-low-kept", AssetID: "code:" + target + ":demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "LOW"},
			}
			if target != "local" {
				prior = append(prior, model.Finding{ID: "CVE-local", AssetID: "code:local:demo", Match: "scanner", Sources: []string{"Trivy"}, Severity: "HIGH"})
			}

			if err := s.Update(func(st *model.State) error {
				st.Settings.Sources = map[string]bool{"nvd": true, "osv": true, "cve": true}
				st.Settings.Scanners = map[string]bool{"trivy": true}
				st.Projects = []model.Project{{
					ID: "p", ScanCode: true, LocalPath: dir, RepositoryURLs: []string{repository, other},
					ScannerProfiles: map[string]model.ScannerProfile{scanner.RemoteTargetKey(repository): {Mode: "custom", Tools: []string{"trivy"}}},
					Assets:          []model.Asset{{ID: "a", Name: "demo", Version: "1", NeedsAssessment: true}},
					Findings:        prior, Schedule: "daily", NextRun: nextRun, LastSync: lastSync,
					DataCheckedAt: lastSync, Revision: 3, AssessedRevision: 1,
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
				t.Errorf("repository-only scan queried a vulnerability database: %s", r.URL)
				return nil, http.ErrNotSupported
			})
			if err := e.StartScoped("p", "manual", "", target, "auto", "HIGH"); err != nil {
				t.Fatal(err)
			}

			p := awaitRun(t, s)
			run := p.Runs[0]
			if run.Status != "complete" || run.Mode != codeScanMode || run.ScanTarget != target ||
				!slices.Equal(run.ScanTargets, []string{target}) || run.Count != 1 || len(run.Steps) != 2 {
				t.Fatalf("unexpected scoped run: %+v", run)
			}
			wantCounts := map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 0, "LOW": 1, "UNKNOWN": 0}
			if !maps.Equal(run.SeverityCounts, wantCounts) {
				t.Fatalf("severity totals include unrelated findings: %v", run.SeverityCounts)
			}
			if target != "local" && run.ScanRepository != scanner.RepositoryLabel(repository) {
				t.Fatalf("missing selected repository label: %+v", run)
			}

			selected := map[string]string{}
			for _, finding := range p.Findings {
				if findingInScanTarget(finding, p, target) {
					selected[finding.ID] = finding.Severity
				}
			}
			if !maps.Equal(selected, map[string]string{"CVE-new": "HIGH", "CVE-downgraded": "LOW", "CVE-low-kept": "LOW"}) {
				t.Fatalf("severity selection did not reconcile the selected repository: %v", selected)
			}
			if !p.LastSync.Equal(lastSync) || !p.DataCheckedAt.Equal(lastSync) || !p.NextRun.Equal(nextRun) ||
				p.AssessedRevision != 1 || !p.Assets[0].NeedsAssessment || len(p.Repositories()) != 2 || p.LocalPath != dir {
				t.Fatal("repository scan changed project configuration or inventory freshness")
			}

			t.Setenv("VULMAN_TEST_SCAN_FAIL", "1")
			if err := e.StartScoped("p", "manual", "", target, "auto", ""); err != nil {
				t.Fatal(err)
			}
			failed := awaitRun(t, s)
			if failed.Runs[0].Status != "failed" || len(failed.Findings) != len(p.Findings) {
				t.Fatal("failed repository scan discarded previous results")
			}

			t.Setenv("VULMAN_TEST_SCAN_FAIL", "")
			t.Setenv("VULMAN_TEST_SCAN_EMPTY", "1")
			if err := e.StartScoped("p", "manual", "", target, "auto", ""); err != nil {
				t.Fatal(err)
			}
			cleared := awaitRun(t, s)
			if cleared.Runs[0].Status != "complete" || cleared.Runs[0].Count != 0 {
				t.Fatalf("empty scan did not complete: %+v", cleared.Runs[0])
			}
			for _, finding := range cleared.Findings {
				if findingInScanTarget(finding, cleared, target) {
					t.Fatalf("resolved finding survived an all-severity scan: %+v", finding)
				}
			}
			for _, finding := range prior {
				if !findingInScanTarget(finding, p, target) && !slices.ContainsFunc(cleared.Findings, func(saved model.Finding) bool {
					return saved.ID == finding.ID && saved.AssetID == finding.AssetID && saved.Severity == finding.Severity
				}) {
					t.Fatalf("other target findings were lost: %+v", finding)
				}
			}
		})
	}
}

func TestRepositoryScanSelectionValidation(t *testing.T) {
	s := testStore(t)
	const repository = "https://github.com/owner/demo"
	target := scanner.RemoteTargetKey(repository)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"trivy": true}
		st.Projects = []model.Project{{ID: "p", ScanCode: true, RepositoryURLs: []string{repository}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	for _, input := range []struct{ asset, target, mode, severity string }{
		{"a", target, "auto", ""},
		{"", target, "local", ""},
		{"", target, "refresh", ""},
		{"", target, "auto", "invalid"},
		{"", "local", "auto", ""},
		{"", scanner.RemoteTargetKey("https://github.com/owner/unregistered"), "auto", ""},
		{"", repository, "auto", ""},
	} {
		if err := e.StartScoped("p", "manual", input.asset, input.target, input.mode, input.severity); err == nil {
			t.Fatalf("invalid scan scope accepted: %+v", input)
		}
	}

	for _, enabled := range []bool{false, true} {
		if err := s.Update(func(st *model.State) error {
			st.Projects[0].ScanCode = enabled
			st.Settings.Scanners = nil
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if err := e.StartScoped("p", "manual", "", target, "auto", ""); err == nil {
			t.Fatal("scan accepted without project consent or configured scanners")
		}
	}

	st, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if st.Projects[0].Syncing || len(st.Projects[0].Runs) != 0 {
		t.Fatal("invalid scan created a workflow or locked the project")
	}
}

func TestRepositoryScanLegacyScopeDoesNotRemoveAmbiguousFindings(t *testing.T) {
	const first = "https://github.com/owner/demo?ref=one"
	const second = "https://github.com/owner/demo?ref=two"
	p := model.Project{RepositoryURLs: []string{first, second}}
	target := scanner.RemoteTargetKey(first)
	finding := model.Finding{AssetID: "code:legacy", ScanRepository: scanner.RepositoryLabel(first), Match: "scanner"}
	if findingInScanTarget(finding, p, target) {
		t.Fatal("ambiguous legacy result attributed to one repository")
	}
	p.RepositoryURLs = p.RepositoryURLs[:1]
	if !findingInScanTarget(finding, p, target) {
		t.Fatal("unique legacy repository label was not recognized")
	}
	finding.AssetID = "code:" + scanner.RemoteTargetKey(second) + ":demo"
	if findingInScanTarget(finding, p, target) {
		t.Fatal("recorded repository identity was overridden by a legacy label")
	}
}
