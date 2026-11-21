package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"vulman/internal/model"
	"vulman/internal/testutil"
)

func writeProjectFiles(t *testing.T, root string, names ...string) {
	t.Helper()
	for _, name := range names {
		filename := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAutomaticPlanFindsMixedProjectsAndSkipsDependencyFolders(t *testing.T) {
	dir := t.TempDir()
	writeProjectFiles(t, dir, "backend/composer.json", "backend/composer.lock", "web/package.json", "web/package-lock.json", "web/node_modules/example/go.mod", ".git/example/requirements.txt", "vendor/go.mod")
	enabled := map[string]bool{}
	for _, id := range Names() {
		enabled[id] = true
	}
	jobs, err := Plan(context.Background(), dir, model.ScannerProfile{Mode: "auto", AdditionalTools: []string{"trivy"}}, enabled)
	if err != nil {
		t.Fatal(err)
	}
	var planned []string
	for _, job := range jobs {
		if job.Status == "planned" {
			planned = append(planned, job.Tool+":"+job.Path)
		}
	}
	if !slices.Equal(planned, []string{"npm:web", "composer:backend", "trivy:"}) {
		t.Fatalf("wrong mixed-project plan: %+v", jobs)
	}
}

func TestPlanReportsMissingInputsAndGlobalPermissions(t *testing.T) {
	dir := t.TempDir()
	writeProjectFiles(t, dir, "package.json", "python/pyproject.toml")
	jobs, err := Plan(context.Background(), dir, model.ScannerProfile{Mode: "custom", Tools: []string{"npm", "pip-audit", "govulncheck"}}, map[string]bool{"npm": true, "pip-audit": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		switch job.Tool {
		case "npm", "pip-audit":
			if job.Status != "blocked" || job.Reason != "missing_input" {
				t.Fatalf("missing lockfile treated as clean: %+v", job)
			}
		case "govulncheck":
			if job.Status != "skipped" || job.Reason != "global_disabled" {
				t.Fatalf("profile bypassed global permission: %+v", job)
			}
		}
	}
}

func TestProfileValidationAndCanonicalOrder(t *testing.T) {
	profile, err := NormalizeProfile(model.ScannerProfile{Mode: "custom", Tools: []string{"npm", "govulncheck", "npm"}, NeedsScan: true})
	if err != nil || !slices.Equal(profile.Tools, []string{"govulncheck", "npm"}) || profile.NeedsScan {
		t.Fatalf("invalid normalization: %+v %v", profile, err)
	}
	for _, profile := range []model.ScannerProfile{{Mode: "unknown"}, {Mode: "custom"}, {Mode: "auto", Tools: []string{"shell"}}, {Mode: "auto", AdditionalTools: []string{"npm"}}} {
		if _, err := NormalizeProfile(profile); err == nil {
			t.Fatalf("accepted invalid profile: %+v", profile)
		}
	}
}

func TestDisabledRepositoryIsNeverClonedOrRead(t *testing.T) {
	p := model.Project{Repository: "https://github.com/owner/private", LocalPath: filepath.Join(t.TempDir(), "missing")}
	p.ScannerProfiles = map[string]model.ScannerProfile{}
	for _, key := range TargetKeys(p) {
		p.ScannerProfiles[key] = model.ScannerProfile{Mode: "disabled"}
	}
	var events []ScanEvent
	report := ScanWithReport(context.Background(), p, model.Settings{Scanners: map[string]bool{"trivy": true}}, "", func(event ScanEvent) { events = append(events, event) })
	if len(report.Problems) != 0 || len(report.Completed) != 0 || len(events) != 2 {
		t.Fatalf("disabled scan did work: %+v %+v", report, events)
	}
	for _, event := range events {
		if event.Phase != "scanner_planned" || len(event.Plan) != len(Names()) {
			t.Fatalf("unexpected disabled scan event: %+v", event)
		}
		for _, job := range event.Plan {
			if job.Status != "skipped" || job.Reason != "repository_disabled" {
				t.Fatalf("disabled scan planned work: %+v", job)
			}
		}
	}
}

func TestMonorepoScannersRunInDetectedFolders(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir, bin := t.TempDir(), t.TempDir()
	writeProjectFiles(t, dir, "php/composer.json", "php/composer.lock", "web/package.json", "web/package-lock.json")
	testutil.WriteShellFixture(t, bin, "npm", `case "$PWD" in */web) ;; *) exit 2;; esac
[ -f package-lock.json ] || exit 2
printf '%s' '{"vulnerabilities":{}}'`)
	testutil.WriteShellFixture(t, bin, "composer", `case "$PWD" in */php) ;; *) exit 2;; esac
[ -f composer.lock ] || exit 2
printf '%s' '{"advisories":[]}'`)
	t.Setenv("PATH", bin)
	p := model.Project{LocalPath: dir}
	p.ScannerProfiles = map[string]model.ScannerProfile{"local": {Mode: "auto"}}
	report := ScanWithReport(context.Background(), p, model.Settings{Scanners: map[string]bool{"npm": true, "composer": true, "govulncheck": true, "pip-audit": true}}, "", nil)
	if len(report.Problems) != 0 || len(report.Completed) != 2 || !slices.Equal(report.CompletedTargets, []string{"local"}) {
		t.Fatalf("wrong scan coverage: %+v", report)
	}
	if report.Completed[0].Path != "web" || report.Completed[1].Path != "php" {
		t.Fatalf("scanners used incorrect working directories: %+v", report.Completed)
	}
}

func TestUnassessedFindingsKeepOnlyUncoveredToolProvenance(t *testing.T) {
	p := model.Project{LocalPath: "/project"}
	prior := []model.Finding{
		{ID: "both", AssetID: "code:local:pkg", Match: "scanner", Sources: []string{"Trivy", "govulncheck"}},
		{ID: "other-path", AssetID: "code:local:pkg2", Match: "scanner", ScanPath: "other", Sources: []string{"govulncheck"}},
		{ID: "unknown", AssetID: "code:local:legacy", Match: "scanner"},
	}
	report := Report{Completed: []Coverage{{Target: "local", Tool: "govulncheck", Path: ""}}}
	kept := report.Unassessed(prior, p)
	if len(kept) != 3 || !slices.Equal(kept[0].Sources, []string{"Trivy"}) || !slices.Equal(kept[1].Sources, []string{"govulncheck"}) {
		t.Fatalf("unassessed results were cleared: %+v", kept)
	}
	report.Completed = append(report.Completed, Coverage{Target: "local", Tool: "trivy"})
	kept = report.Unassessed(prior, p)
	if len(kept) != 2 || kept[0].ID != "other-path" {
		t.Fatalf("covered findings did not resolve: %+v", kept)
	}
}

func TestBroadScannerPathsAreRelativeAndShareFolderIdentities(t *testing.T) {
	for _, filename := range []string{"../outside/go.mod", "/tmp/clone/go.mod", `C:\private\go.mod`, ""} {
		if got := reportDirectory(filename); got != "" {
			t.Fatalf("unsafe report path persisted: %q", got)
		}
	}
	items, err := Parse("trivy", []byte(`{"SchemaVersion":2,"Results":[{"Target":"backend/go.mod","Vulnerabilities":[{"VulnerabilityID":"CVE-demo","PkgName":"pkg"}]}]}`))
	if err != nil || len(items) != 1 || items[0].ScanPath != "backend" {
		t.Fatalf("report folder lost: %+v %v", items, err)
	}
	if FindingAssetID("local", "backend", "pkg") == FindingAssetID("local", "frontend", "pkg") {
		t.Fatal("separate subprojects merged")
	}
}

func TestPlanDoesNotFollowManifestSymlinksAndHonorsCancellation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions depend on Windows developer mode")
	}
	dir, outside := t.TempDir(), t.TempDir()
	writeProjectFiles(t, outside, "go.mod")
	if err := os.Symlink(filepath.Join(outside, "go.mod"), filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	jobs, err := Plan(context.Background(), dir, model.ScannerProfile{Mode: "auto"}, map[string]bool{"govulncheck": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.Status == "planned" {
			t.Fatalf("followed a manifest symlink: %+v", job)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Plan(ctx, dir, model.ScannerProfile{Mode: "auto"}, map[string]bool{"govulncheck": true}); err == nil {
		t.Fatal("discovery ignored cancellation")
	}
}

func TestGitHubLegacyAutomaticProfilesNeverClone(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		project := model.Project{Repository: "https://github.com/owner/project"}
		target := RemoteTargetKey(project.Repository)
		if explicit {
			project.ScannerProfiles = map[string]model.ScannerProfile{target: {Mode: "auto", AdditionalTools: []string{"trivy"}}}
		}
		settings := model.Settings{Scanners: map[string]bool{"trivy": true, "govulncheck": true}}
		var events []ScanEvent
		report := ScanWithReport(context.Background(), project, settings, "", func(event ScanEvent) { events = append(events, event) })
		if len(report.Problems) > 0 || len(report.Completed) > 0 || len(events) != 1 || events[0].Phase != "scanner_planned" {
			t.Fatalf("legacy GitHub profile attempted scanning: explicit=%v report=%+v events=%+v", explicit, report, events)
		}
		for _, job := range events[0].Plan {
			if job.Status != "skipped" || job.Reason != "repository_disabled" {
				t.Fatalf("legacy automatic profile planned work: %+v", job)
			}
		}
		if got := EffectiveProfile(model.Project{LocalPath: "/local"}, settings, "local"); got.Mode != "auto" || !slices.Equal(got.AdditionalTools, []string{"trivy"}) {
			t.Fatalf("local Automatic changed: %+v", got)
		}
	}
}

func TestGitHubCustomProfileRunsOnlyExplicitTools(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	testutil.WriteShellFixture(t, bin, "git", `for destination in "$@"; do :; done
/bin/mkdir -p "$destination" || exit 2
for name in package.json package-lock.json composer.json composer.lock go.mod; do printf '{}' > "$destination/$name"; done`)
	testutil.WriteShellFixture(t, bin, "npm", `echo '{"vulnerabilities":{}}'`)
	project := model.Project{Repository: "https://github.com/owner/project"}
	project.ScannerProfiles = map[string]model.ScannerProfile{RemoteTargetKey(project.Repository): {Mode: "custom", Tools: []string{"npm"}}}
	settings := model.Settings{Scanners: map[string]bool{"npm": true, "composer": true, "govulncheck": true, "trivy": true}}
	report := ScanWithReport(context.Background(), project, settings, "", nil)
	if len(report.Problems) != 0 || len(report.Completed) != 1 || report.Completed[0].Tool != "npm" {
		t.Fatalf("custom GitHub scan selected other tools: %+v", report)
	}
}
