package engine

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/testutil"
)

func TestMixedSelectionProcessesOnlyChosenComponentsAndRepositories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}

	dir := t.TempDir()
	t.Setenv("PATH", dir)
	t.Setenv("SNYK_TOKEN", "")
	const first = "https://github.com/owner/first"
	const second = "https://github.com/owner/second"
	const third = "https://github.com/owner/third"
	testutil.WriteShellFixture(t, dir, "git", `
repository=''
destination=''
for arg in "$@"; do
  case "$arg" in https://*) repository="$arg";; esac
  destination="$arg"
done
case "$repository" in
  https://github.com/owner/first|https://github.com/owner/second)
    /bin/mkdir -p "$destination" || exit 2
    printf 'fixture' > "$destination/selected-repository";;
  *) exit 2;;
esac`)
	testutil.WriteShellFixture(t, dir, "trivy", `
if [ ! -f selected-repository ]; then exit 2; fi
echo '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-new-code","PkgName":"dependency","Severity":"HIGH"}]}]}'`)

	s, e := controlEngine(t)
	lastSync, nextRun := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	var original model.Project
	if err := s.Update(func(st *model.State) error {
		st.Settings.OSVURL = "https://example.test/query"
		st.Settings.Scanners = map[string]bool{"trivy": true}
		p := &st.Projects[0]
		p.ScanCode, p.LocalPath = true, dir
		p.RepositoryURLs = []string{first, second, third}
		p.Assets = []model.Asset{
			{ID: "a", Name: "first", Version: "1", Ecosystem: "npm", NeedsAssessment: true},
			{ID: "b", Name: "second", Version: "2", Ecosystem: "npm", NeedsAssessment: true},
			{ID: "c", Name: "unselected", Version: "3", Ecosystem: "npm", NeedsAssessment: true},
		}
		p.Findings = []model.Finding{
			{ID: "old-a", AssetID: "a", Severity: "HIGH"},
			{ID: "old-b", AssetID: "b", Severity: "HIGH"},
			{ID: "keep-c", AssetID: "c", Severity: "CRITICAL"},
			{ID: "keep-local", AssetID: "code:local:dependency", Match: "scanner", Severity: "LOW"},
			{ID: "keep-repository", AssetID: "code:" + scanner.RemoteTargetKey(third) + ":dependency", Match: "scanner", Severity: "CRITICAL"},
			{ID: "resolved-repository", AssetID: "code:" + scanner.RemoteTargetKey(first) + ":dependency", Match: "scanner", Severity: "HIGH"},
		}
		p.LastSync, p.DataCheckedAt, p.NextRun = lastSync, lastSync, nextRun
		original = *p
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var apiCalls atomic.Int32
	var fail atomic.Bool
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		apiCalls.Add(1)
		var query struct {
			Package struct{ Name string } `json:"package"`
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			return nil, err
		}
		if query.Package.Name != "first" && query.Package.Name != "second" {
			t.Errorf("queried an unselected component: %q", query.Package.Name)
		}
		if fail.Load() {
			response := controlResponse(`{}`)
			response.StatusCode = http.StatusForbidden
			return response, nil
		}

		return controlResponse(fmt.Sprintf(`{"vulns":[{"id":%q,"database_specific":{"severity":"HIGH"}}]}`, "GHSA-"+query.Package.Name)), nil
	})
	assets := []string{"b", "a", "b"}
	targets := []string{scanner.RemoteTargetKey(second), scanner.RemoteTargetKey(first), scanner.RemoteTargetKey(first)}
	if err := e.StartSelected("p", "manual", assets, targets, "auto", ""); err != nil {
		t.Fatal(err)
	}
	assets[0], targets[0] = "invalid", "invalid"

	p := awaitRun(t, s)
	run := p.Runs[0]
	if run.Status != "complete" || run.Mode != "auto" || run.Count != 4 || len(run.Steps) != 4 || apiCalls.Load() != 2 {
		t.Fatalf("unexpected mixed assessment: %+v; API requests: %d", run, apiCalls.Load())
	}
	if run.Selection == nil || len(run.Selection.Assets) != 2 || len(run.Selection.Repositories) != 2 ||
		run.Selection.Assets[0].ID != "a" || !slices.Equal(run.ScanTargets, []string{scanner.RemoteTargetKey(first), scanner.RemoteTargetKey(second)}) {
		t.Fatalf("selection was lost, duplicated, reordered, or broadened: %+v", run)
	}
	if p.Assets[0].NeedsAssessment || p.Assets[1].NeedsAssessment || !p.Assets[2].NeedsAssessment ||
		!p.LastSync.Equal(lastSync) || !p.DataCheckedAt.Equal(lastSync) || !p.NextRun.Equal(nextRun) || p.AssessedRevision != original.AssessedRevision {
		t.Fatal("selected assessment changed unrelated freshness or scheduling")
	}
	if len(p.Findings) != 7 {
		t.Fatalf("unexpected results after mixed selection: %+v", p.Findings)
	}
	for _, finding := range original.Findings[2:5] {
		if !slices.ContainsFunc(p.Findings, func(saved model.Finding) bool { return reflect.DeepEqual(saved, finding) }) {
			t.Fatalf("unselected finding changed: %+v", finding)
		}
	}

	// Repository-only multi-selection leaves all component findings intact.
	if err := e.StartSelected("p", "manual", nil, []string{scanner.RemoteTargetKey(first), scanner.RemoteTargetKey(second)}, "auto", "HIGH"); err != nil {
		t.Fatal(err)
	}
	repositories := awaitRun(t, s)
	if repositories.Runs[0].Mode != codeScanMode || repositories.Runs[0].Count != 2 || apiCalls.Load() != 2 || !reflect.DeepEqual(repositories.Findings, p.Findings) {
		t.Fatal("repository-only multiple selection changed component results or contacted vulnerability APIs")
	}

	// A partial mixed run keeps previous selected findings as well as other data.
	if err := s.ClearAPIResponseCache(); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	if err := e.StartSelected("p", "manual", []string{"a", "b"}, []string{scanner.RemoteTargetKey(first)}, "auto", "HIGH"); err != nil {
		t.Fatal(err)
	}
	partial := awaitRun(t, s)
	if partial.Runs[0].Status != "partial" || !reflect.DeepEqual(partial.Findings, p.Findings) {
		t.Fatalf("partial selection discarded previous results: %+v", partial.Runs[0])
	}
}

func TestMultiSelectionValidation(t *testing.T) {
	s, e := controlEngine(t)
	for _, input := range []struct{ assets, repositories []string }{
		{assets: []string{}},
		{repositories: []string{}},
		{assets: []string{"a", "missing"}},
		{assets: []string{"a"}, repositories: []string{"local"}},
		{assets: []string{""}},
	} {
		if err := e.StartSelected("p", "manual", input.assets, input.repositories, "auto", ""); err == nil {
			t.Fatalf("invalid selection accepted: %+v", input)
		}
	}
	st, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	if st.Projects[0].Syncing || len(st.Projects[0].Runs) != 0 {
		t.Fatal("invalid selection created a workflow")
	}
}

func TestStoppingMultiSelectionPreservesAllFindings(t *testing.T) {
	s, e := controlEngine(t)
	if err := s.Update(func(st *model.State) error {
		st.Projects[0].Assets = append(st.Projects[0].Assets, model.Asset{ID: "b", Name: "other", Version: "1", Ecosystem: "npm"})
		st.Projects[0].Findings = append(st.Projects[0].Findings, model.Finding{ID: "keep-b", AssetID: "b", Severity: "LOW"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if err := e.StartSelected("p", "manual", []string{"a", "b"}, nil, "auto", ""); err != nil {
		t.Fatal(err)
	}
	signalControl(t, started)
	active := waitControlStatus(t, s, "running")
	if err := e.Control("p", active.Runs[0].ID, "stop"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if p.Runs[0].Status != "stopped" || !reflect.DeepEqual(p.Findings, st.Projects[0].Findings) || len(p.Runs[0].Selection.Assets) != 2 {
		t.Fatal("stopped multiple selection changed saved findings or lost its selection")
	}
}

func TestMultiSelectionSeverityScopeRetainsOtherLevels(t *testing.T) {
	s, e := controlEngine(t)
	if err := s.Update(func(st *model.State) error {
		st.Projects[0].Assets = []model.Asset{
			{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"},
			{ID: "b", Name: "demo", Version: "1", Ecosystem: "npm"},
			{ID: "c", Name: "unselected", Version: "1", Ecosystem: "npm"},
		}
		st.Projects[0].Findings = []model.Finding{
			{ID: "GHSA-down", AssetID: "a", Severity: "CRITICAL"},
			{ID: "GHSA-down", AssetID: "b", Severity: "CRITICAL"},
			{ID: "GHSA-low", AssetID: "b", Severity: "LOW"},
			{ID: "GHSA-outside", AssetID: "c", Severity: "CRITICAL"},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
		return controlResponse(`{"vulns":[{"id":"GHSA-down","database_specific":{"severity":"HIGH"}},{"id":"GHSA-new","database_specific":{"severity":"CRITICAL"}}]}`), nil
	})
	if err := e.StartSelected("p", "manual", []string{"a", "b"}, nil, "auto", "CRITICAL"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	got := map[string]string{}
	for _, finding := range p.Findings {
		got[finding.AssetID+":"+finding.ID] = finding.Severity
	}
	want := map[string]string{
		"a:GHSA-down": "HIGH", "b:GHSA-down": "HIGH", "b:GHSA-low": "LOW",
		"c:GHSA-outside": "CRITICAL", "a:GHSA-new": "CRITICAL", "b:GHSA-new": "CRITICAL",
	}
	if p.Runs[0].Status != "complete" || p.Runs[0].Count != 2 || !maps.Equal(got, want) {
		t.Fatalf("multi-selection lost severity reconciliation or other results: %v", got)
	}
}
