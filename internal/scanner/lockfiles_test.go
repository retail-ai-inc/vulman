package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/testutil"
)

func TestLockfileGenerationUsesDisposableLocalCopyAndReportsProvenance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir, bin := t.TempDir(), t.TempDir()
	writeProjectFiles(t, dir, "web/package.json", "php/composer.json", "node_modules/ignored/package.json")
	log := filepath.Join(t.TempDir(), "commands")
	t.Setenv("VULMAN_GENERATION_LOG", log)
	t.Setenv("PATH", bin)
	t.Setenv("COMPOSER", filepath.Join(dir, "php", "composer.json"))
	testutil.WriteShellFixture(t, bin, "npm", `printf '%s|%s\n' "$PWD" "$*" >> "$VULMAN_GENERATION_LOG"
case "$1" in
install)
 for flag in --package-lock-only --ignore-scripts --no-audit --no-fund --package-lock=true --global=false; do
  case " $* " in *" $flag "*) ;; *) exit 9;; esac
 done
 printf '%s' '{"lockfileVersion":3,"packages":{}}' > package-lock.json;;
audit)
 [ -f package-lock.json ] || exit 8
 printf '%s' '{"vulnerabilities":{"demo":{"severity":"high","via":[{"source":1,"title":"Example"}]}}}';;
*) exit 7;;
esac`)
	testutil.WriteShellFixture(t, bin, "composer", `printf '%s|%s\n' "$PWD" "$*" >> "$VULMAN_GENERATION_LOG"
[ "$COMPOSER" = composer.json ] || exit 9
case " $* " in
*" update "*)
 for flag in --no-plugins --no-scripts --no-interaction --no-install --no-audit; do
  case " $* " in *" $flag "*) ;; *) exit 9;; esac
 done
 printf '%s' '{"packages":[]}' > composer.lock;;
*" audit "*) [ -f composer.lock ] || exit 8; printf '%s' '{"advisories":[]}';;
*) exit 7;;
esac`)
	testutil.WriteShellFixture(t, bin, "trivy", `printf '%s' '{"SchemaVersion":2,"Results":[]}'`)
	project := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{
		"local": {Mode: "custom", Tools: []string{"npm", "composer", "trivy"}, GenerateLockfiles: true},
	}}
	var events []ScanEvent
	report := ScanWithReport(context.Background(), project, model.Settings{Scanners: map[string]bool{"npm": true, "composer": true, "trivy": true}}, "", func(event ScanEvent) {
		events = append(events, event)
	})
	if len(report.Problems) != 0 || len(report.Completed) != 3 || len(report.Findings) != 1 || !report.Findings[0].GeneratedLockfile {
		t.Fatalf("generation did not lead to labeled scanner results: %+v", report)
	}
	for _, coverage := range report.Completed {
		if !coverage.GeneratedLockfile {
			t.Fatalf("scanner lost generated-lockfile provenance: %+v", coverage)
		}
	}
	logs, err := os.OpenRoot(filepath.Dir(log))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = logs.Close() }()
	commands, err := logs.ReadFile("commands")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
	if len(lines) != 4 {
		t.Fatalf("unexpected generation or audit commands: %s", commands)
	}
	root, err := openScratchRoot("", false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, line := range lines {
		working, _, _ := strings.Cut(line, "|")
		relative, err := filepath.Rel(root.Name(), working)
		if err != nil || !filepath.IsLocal(relative) || strings.Contains(working, dir) {
			t.Fatalf("generation or audit ran outside disposable storage: %s", line)
		}
		if _, err := root.Stat(relative); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("temporary repository survived cleanup: %v", err)
		}
	}
	original, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	for _, file := range []string{"web/package.json", "php/composer.json"} {
		data, err := original.ReadFile(filepath.FromSlash(file))
		if err != nil || string(data) != "{}" {
			t.Fatalf("original manifest changed: %s, %v", file, err)
		}
	}
	for _, file := range []string{"web/package-lock.json", "php/composer.lock"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(file))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("generated lockfile leaked into the original repository: %s", file)
		}
	}
	var phases []string
	for _, event := range events {
		phases = append(phases, event.Phase)
	}
	if !slices.Contains(phases, "scanner_copying") || !slices.Contains(phases, "scanner_lockfile_started") || !slices.Contains(phases, "scanner_lockfile_completed") || !slices.Contains(phases, "scanner_cleanup_completed") {
		t.Fatalf("generation or cleanup is absent from workflow events: %v", phases)
	}
}

func TestLockfileGenerationIsExplicitAndRequiresTheCorrectManifest(t *testing.T) {
	for _, tc := range []struct {
		tool  string
		files []string
		want  bool
	}{
		{"npm", []string{"package.json"}, true},
		{"composer", []string{"composer.json"}, true},
		{"npm", []string{"package.json", "package-lock.json"}, false},
		{"npm", []string{"package.json", "npm-shrinkwrap.json"}, false},
		{"npm", []string{"package.json", "yarn.lock"}, false},
		{"npm", []string{"package.json", "pnpm-lock.yaml"}, false},
		{"composer", []string{"composer.json", "composer.lock"}, false},
		{"composer", []string{"package.json"}, false},
		{"pip-audit", []string{"pyproject.toml"}, false},
	} {
		if got := canGenerateLockfile(tc.tool, tc.files); got != tc.want {
			t.Errorf("incorrect lockfile generation eligibility for %s %v", tc.tool, tc.files)
		}
	}

	dir := t.TempDir()
	writeProjectFiles(t, dir, "package.json")
	for _, enabled := range []bool{false, true} {
		jobs, err := Plan(context.Background(), dir, model.ScannerProfile{Mode: "custom", Tools: []string{"npm", "composer"}, GenerateLockfiles: enabled}, map[string]bool{"npm": true, "composer": true})
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if job.Tool == "composer" && job.Status != "blocked" || job.Tool == "npm" && (job.Status == "planned") != enabled {
				t.Fatalf("generation bypassed manifest or opt-in requirements: %+v", job)
			}
		}
	}
}

func TestComposerPlatformBypassAppliesOnlyToOptedInTemporaryGeneration(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	for _, tc := range []struct {
		name             string
		ignore, existing bool
	}{
		{name: "normal resolution"}, {name: "opted in", ignore: true}, {name: "existing lockfile", ignore: true, existing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, bin := t.TempDir(), t.TempDir()
			writeProjectFiles(t, dir, "composer.json")
			if tc.existing {
				if err := os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[]}`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			log := filepath.Join(t.TempDir(), "commands")
			t.Setenv("PATH", bin)
			t.Setenv("VULMAN_GENERATION_LOG", log)
			t.Setenv("COMPOSER_IGNORE_PLATFORM_REQS", "1")
			t.Setenv("COMPOSER_IGNORE_PLATFORM_REQ", "php,ext-*")
			testutil.WriteShellFixture(t, bin, "composer", `printf '%s\n' "$*" >> "$VULMAN_GENERATION_LOG"
case " $* " in
*" update "*) [ -z "$COMPOSER_IGNORE_PLATFORM_REQS" ] && [ -z "$COMPOSER_IGNORE_PLATFORM_REQ" ] || exit 9; printf '%s' '{"packages":[]}' > composer.lock;;
*" audit "*) case " $* " in *" --ignore-platform-reqs "*) exit 9;; esac; printf '%s' '{"advisories":[]}';;
*) exit 8;;
esac`)
			p := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"composer"}, GenerateLockfiles: true, IgnoreComposerPlatform: tc.ignore}}}
			var completed model.ScannerJob
			report := ScanWithReport(context.Background(), p, model.Settings{Scanners: map[string]bool{"composer": true}}, "", func(event ScanEvent) {
				if event.Phase == "scanner_completed" {
					completed = *event.Job
				}
			})
			logs, err := os.OpenRoot(filepath.Dir(log))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = logs.Close() }()
			data, err := logs.ReadFile("commands")
			if err != nil || len(report.Problems) != 0 || len(report.Completed) != 1 {
				t.Fatalf("Composer generation failed: %+v %v", report, err)
			}
			want := tc.ignore && !tc.existing
			if strings.Contains(string(data), "--ignore-platform-reqs") != want || completed.IgnoredComposerPlatform != want {
				t.Fatalf("platform bypass escaped its generation opt-in: %s %+v", data, completed)
			}
		})
	}
}

func TestGenerationFailureAndCancellationDoNotRecordCleanScans(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	for _, fixture := range []string{"exit 2", "printf 'not-json' > package-lock.json", `printf '%s' '{"lockfileVersion":3,"packages":null}' > package-lock.json`, "exit 0", "cancel"} {
		t.Run(fixture, func(t *testing.T) {
			dir, bin := t.TempDir(), t.TempDir()
			writeProjectFiles(t, dir, "package.json")
			t.Setenv("PATH", bin)
			testutil.WriteShellFixture(t, bin, "npm", fixture)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			project := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"npm"}, GenerateLockfiles: true}}}
			cleaned := false
			report := ScanWithReport(ctx, project, model.Settings{Scanners: map[string]bool{"npm": true}}, "", func(event ScanEvent) {
				if fixture == "cancel" && event.Phase == "scanner_lockfile_started" {
					cancel()
				}
				cleaned = cleaned || event.Phase == "scanner_cleanup_completed"
			})
			if len(report.Problems) == 0 || len(report.Completed) != 0 || len(report.Findings) != 0 || !cleaned {
				t.Fatalf("failed generation appeared clean or retained temporary code: %+v", report)
			}
			if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("failed generation changed the original repository")
			}
		})
	}
}

func TestGeneratedResolutionCannotClearFindingsFromSuppliedLockfiles(t *testing.T) {
	project := model.Project{LocalPath: "/repository"}
	prior := []model.Finding{
		{ID: "actual", Match: "scanner", AssetID: "code:local:pkg", Sources: []string{"npm audit"}},
		{ID: "resolved", Match: "scanner", AssetID: "code:local:pkg", Sources: []string{"npm audit"}, GeneratedLockfile: true},
	}
	report := Report{Completed: []Coverage{{Target: "local", Tool: "npm", GeneratedLockfile: true}}}
	kept := report.Unassessed(prior, project)
	if len(kept) != 1 || kept[0].ID != "actual" {
		t.Fatalf("generated versions resolved actual dependency evidence: %+v", kept)
	}
}

func TestGenerationRejectsOriginalDirectoriesAndExistingLockfiles(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	scratch, err := newScanScratch(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scratch.remove() }()

	original := t.TempDir()
	writeProjectFiles(t, original, "package.json")
	err = generateLockfile(context.Background(), original, scratch, "npm")
	if err == nil || apperror.Public(err).Code != "scanner_generation_workspace" {
		t.Fatalf("generation was allowed in an original folder: %v", err)
	}
	if err := root.WriteFile(filepath.Join(scratch.name, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		file := filepath.Join(scratch.name, name)
		if err := root.WriteFile(file, []byte("original lockfile"), 0o600); err != nil {
			t.Fatal(err)
		}
		err := generateLockfile(context.Background(), scratch.path(), scratch, "npm")
		if err == nil || apperror.Public(err).Code != "scanner_generation_existing_lockfile" {
			t.Fatalf("existing lockfile was not protected: %s, %v", name, err)
		}
		data, err := root.ReadFile(file)
		if err != nil || string(data) != "original lockfile" {
			t.Fatalf("existing lockfile was changed: %s, %v", name, err)
		}
		if err := root.Remove(file); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(filepath.Join(original, "package.json"), filepath.Join(scratch.path(), "package-lock.json")); err != nil {
			t.Fatal(err)
		}
		err = generateLockfile(context.Background(), scratch.path(), scratch, "npm")
		if err == nil || apperror.Public(err).Code != "scanner_generation_existing_lockfile" {
			t.Fatalf("existing lockfile symlink was followed or replaced: %v", err)
		}
	}
}

func TestTemporaryCopyDoesNotFollowLinksOrShareFileStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions depend on Windows developer mode")
	}
	dir, outside := t.TempDir(), t.TempDir()
	writeProjectFiles(t, dir, "package.json", "nested/source.js", "node_modules/ignored.js")
	writeProjectFiles(t, outside, "private.txt")
	if err := os.Symlink(filepath.Join(outside, "private.txt"), filepath.Join(dir, "linked-file")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "linked-directory")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	scratch, err := newScanScratch(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = scratch.remove() }()
	copy, err := copyRepository(context.Background(), dir, scratch)
	if err != nil {
		t.Fatal(err)
	}
	to, err := os.OpenRoot(copy)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = to.Close() }()
	for _, name := range []string{"linked-file", "linked-directory", "node_modules"} {
		if _, err := to.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("excluded or symlinked source was copied: %s, %v", name, err)
		}
	}
	if err := to.WriteFile("nested/source.js", []byte("changed copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	data, err := original.ReadFile(filepath.Join("nested", "source.js"))
	if err != nil || string(data) != "{}" {
		t.Fatal("temporary copy shared writable file storage with the original")
	}
}
