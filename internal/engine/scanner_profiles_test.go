package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/testutil"
)

func TestScannerProfilesPreserveUnassessedResultsAndClearCoverageWarning(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir := t.TempDir()
	testutil.WriteShellFixture(t, dir, "govulncheck", `echo '{"config":{"scanner_name":"govulncheck"}}'`)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	store := testStore(t)
	lastSync := time.Now().Add(-time.Hour)
	if err := store.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"govulncheck": true, "trivy": true}
		st.Projects = []model.Project{{ID: "p", LocalPath: dir, ScanCode: true, LastSync: lastSync,
			ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "auto", NeedsScan: true}},
			Findings: []model.Finding{
				{ID: "resolved", AssetID: "code:local:pkg", Severity: "HIGH", Match: "scanner", Sources: []string{"govulncheck"}},
				{ID: "unassessed", AssetID: "code:local:pkg", Severity: "HIGH", Match: "scanner", Sources: []string{"Trivy"}},
				{ID: "shared", AssetID: "code:local:pkg", Severity: "HIGH", Match: "scanner", Sources: []string{"Trivy", "govulncheck"}},
			},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	engine, err := New(store)
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	if err := engine.StartCodeScan("p"); err != nil {
		t.Fatal(err)
	}
	project := awaitRun(t, store)
	if len(project.Findings) != 2 || project.ScannerProfiles["local"].NeedsScan || !project.LastSync.Equal(lastSync) {
		t.Fatalf("wrong scanner coverage or freshness: %+v", project)
	}
	for _, finding := range project.Findings {
		if finding.ID == "resolved" || len(finding.Sources) != 1 || finding.Sources[0] != "Trivy" {
			t.Fatalf("unassessed source provenance changed: %+v", finding)
		}
	}
	run := project.Runs[0]
	if run.ScannersCompleted != 1 || run.RetainedScannerFindings != 2 || run.Count != 0 || len(run.ScannerJobs) == 0 {
		t.Fatalf("coverage was not recorded separately from fresh findings: %+v", run)
	}
}
