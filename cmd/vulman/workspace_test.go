package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/engine"
	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	db, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db
}

func TestStateSinceReturnsDataOnlyAfterACommittedChange(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	initial, err := desktop.State()
	if err != nil || initial.State == nil || initial.Version == "" {
		t.Fatalf("read initial state with a version: %v", err)
	}
	db.RecordCacheUse(true)
	unchanged, err := desktop.StateSince(initial.Version)
	if err != nil || unchanged.State != nil || unchanged.Version != initial.Version || unchanged.CacheStats.Hits != 1 {
		t.Fatalf("unchanged poll should only return version and cache stats: %+v, %v", unchanged, err)
	}
	body, err := json.Marshal(unchanged)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), `"projects"`) || strings.Contains(string(body), `"settings"`) {
		t.Fatalf("unchanged poll serialized workspace data: %s", body)
	}
	project, err := desktop.CreateProject(ProjectInput{Name: "New project", Schedule: "off"})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := desktop.StateSince(initial.Version)
	if err != nil || changed.State == nil || changed.Version == initial.Version || len(changed.Projects) != 1 || changed.Projects[0].ID != project.ID {
		t.Fatalf("committed project was missing from the changed poll: %v", err)
	}
	rejected := errors.New("discard test update")
	if err := db.Update(func(st *model.State) error {
		st.Projects = nil
		return rejected
	}); !errors.Is(err, rejected) {
		t.Fatalf("rollback: %v", err)
	}
	rolledBack, err := desktop.StateSince(changed.Version)
	if err != nil || rolledBack.State != nil || rolledBack.Version != changed.Version {
		t.Fatalf("rollback changed the snapshot version: %+v, %v", rolledBack, err)
	}
}

func TestProjectRepositoryURLsPersistThroughDesktopUpdate(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	urls := []string{"https://github.com/owner/first.git", "https://github.com/owner/second.git?tab=readme#overview"}
	project, err := desktop.CreateProject(ProjectInput{Name: "Demo", Schedule: "off", Repository: urls[0], ScanCode: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.UpdateProject(project.ID, ProjectInput{Name: project.Name, Schedule: project.Schedule, Revision: project.Revision, RepositoryURLs: urls, ScanCode: true}); err != nil {
		t.Fatal(err)
	}
	state, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if stored := state.Projects[0]; !reflect.DeepEqual(stored.Repositories(), urls) || stored.Repository != urls[0] {
		t.Fatalf("unexpected saved repository URLs: %+v", stored.Repositories())
	}
	want := []ScanRepository{
		{Key: scanner.RemoteTargetKey(urls[0]), Label: "github.com/owner/first.git", URL: urls[0]},
		{Key: scanner.RemoteTargetKey(urls[1]), Label: "github.com/owner/second.git", URL: urls[1]},
	}
	if got := state.ScanRepositories[project.ID]; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected scan repository identifiers in the workspace: %+v", got)
	}
}

func TestDesktopSyncValidatesMultipleSelectionFields(t *testing.T) {
	db := newTestStore(t)
	if err := db.Update(func(st *model.State) error {
		st.Settings.Sources = nil
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	desktop := &Desktop{store: db, engine: eng}
	for _, tc := range []struct{ json, code string }{
		{`{"asset_ids":[],"scan_targets":[]}`, "assessment_selection_empty"},
		{`{"asset_ids":["a","missing"]}`, "tech_stack_component_not_found"},
		{`{"asset_ids":["a"],"scan_targets":["local"]}`, "scan_repository_not_registered"},
		{`{"asset_id":"a","asset_ids":["a"]}`, "assessment_selection_conflict"},
	} {
		var input SyncInput
		if err := json.Unmarshal([]byte(tc.json), &input); err != nil {
			t.Fatal(err)
		}
		err := desktop.Sync("p", input)
		if message := apperror.Public(err); message == nil || message.Code != tc.code {
			t.Fatalf("multiple-selection request was ignored or returned the wrong error: %s, %v", tc.json, err)
		}
	}
	st, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	if st.Projects[0].Syncing || len(st.Projects[0].Runs) != 0 {
		t.Fatal("invalid desktop selection started a full-project assessment")
	}
}

func TestDesktopWorkspaceAndCredentialRedaction(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	db := newTestStore(t)
	if err := addSample(db); err != nil {
		t.Fatal(err)
	}
	if err := addSample(db); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(eng.Close)
	desktop := &Desktop{store: db, engine: eng}
	const key = "secret-desktop-test-key"
	githubToken := rand.Text()
	cfg := model.Defaults().Settings
	cfg.Language = "ja"
	cfg.Tokens = map[string]string{"openai": key, "github": githubToken}
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}
	state, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Projects) != 1 || len(state.Projects[0].Assets) != 1 || state.Settings.Language != "ja" {
		t.Fatalf("unexpected desktop state: %+v", state)
	}
	if !state.TokenStatus["openai"] || !state.TokenStatus["github"] || state.StoragePaths != db.Paths() || state.CacheStats.MaxEntries == 0 {
		t.Fatal("desktop configuration status is incomplete")
	}
	encoded, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), key) || strings.Contains(string(encoded), githubToken) || state.Settings.Tokens != nil {
		t.Fatal("desktop state included an API credential")
	}
	if err := desktop.Sync(state.Projects[0].ID, SyncInput{AssetID: "missing-component", Severity: "HIGH"}); err == nil {
		t.Fatal("desktop bridge accepted an unknown component")
	}
	blank := state.Settings
	blank.Tokens = map[string]string{"openai": "", "github": ""}
	if err := desktop.SaveSettings(SettingsInput{Settings: blank}); err != nil {
		t.Fatal(err)
	}
	preserved, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	if preserved.Settings.Tokens["openai"] != key || preserved.Settings.Tokens["github"] != githubToken {
		t.Fatal("blank settings input removed the stored key")
	}
	if err := desktop.SaveSettings(SettingsInput{Settings: state.Settings, ClearTokens: []string{"openai", "github"}}); err != nil {
		t.Fatal(err)
	}
	project, err := desktop.CreateProject(ProjectInput{Name: "Desktop project", Schedule: "weekly"})
	if err != nil {
		t.Fatal(err)
	}
	if project.NextRun.IsZero() {
		t.Fatal("desktop project schedule has no next run")
	}
	update := ProjectInput{
		Name: project.Name, Schedule: project.Schedule, Revision: project.Revision,
		Assets: []model.Asset{{Kind: "library", Name: "example", Version: "1.0.0"}},
	}
	project, err = desktop.UpdateProject(project.ID, update)
	if err != nil {
		t.Fatal(err)
	}
	if len(project.Assets) != 1 || project.Assets[0].ID == "" {
		t.Fatal("desktop component edit did not save")
	}
	if _, err := desktop.UpdateProject(project.ID, update); err == nil {
		t.Fatal("desktop accepted an outdated project revision")
	}
	const finding = "CVE-2024-0001"
	if err := db.Update(func(state *model.State) error {
		state.Projects[1].Findings = []model.Finding{{ID: finding, AssetID: project.Assets[0].ID, FixedVersions: []string{"1.1.0"}}}
		state.Projects[1].Runs = []model.Run{{ID: "partial-run", Status: "partial"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	advice, err := desktop.Advice(context.Background(), project.ID, AdviceInput{
		FindingID: finding, AssetID: project.Assets[0].ID, Provider: "public",
	})
	if err != nil {
		t.Fatal(err)
	}
	if advice.Provider != "public" || !strings.Contains(advice.Text, "1.1.0") {
		t.Fatalf("unexpected desktop advice: %+v", advice)
	}
	if err := desktop.DeleteRun(project.ID, "partial-run"); err != nil {
		t.Fatal(err)
	}
	if err := desktop.DeleteProject(project.ID, project.Name); err != nil {
		t.Fatal(err)
	}
	saved, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Projects) != 1 || saved.Settings.Tokens["openai"] != "" || saved.Settings.Tokens["github"] != "" {
		t.Fatal("desktop project or credential removal did not persist")
	}
}

func TestDeleteProjectRequiresCurrentNameAndRemovesOnlyThatProject(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	target := model.Project{
		ID: "target", Name: "Project 型", Schedule: "weekly", NextRun: time.Now().Add(time.Hour),
		Assets:   []model.Asset{{ID: "component", Name: "example"}},
		Findings: []model.Finding{{ID: "CVE-2024-0001"}},
		Runs:     []model.Run{{ID: "run", Logs: []model.SyncLog{{Event: "run_started"}}}},
	}
	other := model.Project{ID: "other", Name: target.Name, Findings: []model.Finding{{ID: "CVE-2024-0002"}}}
	if err := db.Update(func(st *model.State) error {
		st.Projects = []model.Project{target, other}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "project 型", target.Name + " ", "Old project name"} {
		if err := desktop.DeleteProject(target.ID, name); err == nil {
			t.Fatalf("accepted confirmation %q", name)
		}
	}
	after, err := desktop.StateSince(before.Version)
	if err != nil || after.State != nil || after.Version != before.Version {
		t.Fatalf("invalid confirmation changed workspace data: %+v, %v", after, err)
	}
	setSyncing := func(syncing bool) {
		t.Helper()
		if err := db.Update(func(st *model.State) error {
			st.Projects[0].Syncing = syncing
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	setSyncing(true)
	if err := desktop.DeleteProject(target.ID, target.Name); err == nil {
		t.Fatal("deleted a project during an active assessment")
	}
	setSyncing(false)
	if err := desktop.DeleteProject(target.ID, target.Name); err != nil {
		t.Fatal(err)
	}
	saved, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(saved.Projects, []model.Project{other}) {
		t.Fatalf("unexpected projects after deletion: %+v", saved.Projects)
	}
	if err := desktop.DeleteProject(target.ID, target.Name); err == nil {
		t.Fatal("deleted a missing project")
	}
}

func TestSavedCredentialPreview(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", rand.Text())
	t.Setenv("SNYK_TOKEN", rand.Text())
	desktop := &Desktop{store: newTestStore(t)}
	stored := rand.Text()
	unicodePrefix := "日本語鍵日本語鍵日本"
	cfg := model.Defaults().Settings
	cfg.Tokens = map[string]string{"github": stored, "nvd": "abc", "claude": unicodePrefix + stored[:6] + "テスト鍵", "openai": stored[:14]}
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}
	state, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if !state.SavedTokenStatus["github"] || !state.TokenStatus["snyk"] || state.SavedTokenStatus["snyk"] {
		t.Fatal("configuration did not distinguish saved and environment-only credentials")
	}
	for name, want := range map[string]string{
		"github": stored[:10] + strings.Repeat("x", len(stored)-14) + stored[len(stored)-4:],
		"nvd":    "xxx",
		"claude": unicodePrefix + "xxxxxxテスト鍵",
		"snyk":   "",
		"openai": "xxxxxxxxxxxxxx",
	} {
		preview, err := desktop.SavedCredentialPreview(name)
		if err != nil || preview != want {
			t.Fatalf("unexpected preview for %s: %v", name, err)
		}
	}
	if preview, err := desktop.SavedCredentialPreview("unknown"); err == nil || preview != "" {
		t.Fatal("preview accepted an unsupported credential")
	}
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg, ClearTokens: []string{"github"}}); err != nil {
		t.Fatal(err)
	}
	if preview, err := desktop.SavedCredentialPreview("github"); err != nil || preview != "" {
		t.Fatalf("removed credential still has a preview: %v", err)
	}
}

func TestDesktopDeletesOnlyIncompleteActivity(t *testing.T) {
	for _, status := range []string{"interrupted", "partial", "failed", "stopped"} {
		t.Run(status, func(t *testing.T) {
			db := newTestStore(t)
			desktop := &Desktop{store: db}
			now := time.Now().UTC()
			if err := db.Update(func(st *model.State) error {
				st.Projects = []model.Project{{
					ID: "p", Name: "Keep project", Syncing: true, Revision: 3, AssessedRevision: 2,
					Schedule: "daily", NextRun: now.Add(time.Hour), LastSync: now.Add(-time.Hour),
					DataCheckedAt: now.Add(-2 * time.Hour),
					Assets:        []model.Asset{{ID: "a", Name: "demo", Version: "1"}},
					Findings:      []model.Finding{{ID: "CVE-keep", AssetID: "a", Severity: "HIGH"}},
					Runs: []model.Run{
						{ID: "active", Status: "running"},
						{ID: "remove", Status: status, Logs: []model.SyncLog{{Event: "failed"}}},
						{ID: "keep", Status: "complete"},
					},
				}, {ID: "other", Runs: []model.Run{{ID: "remove", Status: status}}}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			expected, err := db.Read()
			if err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"active", "keep", "missing"} {
				if err := desktop.DeleteRun("p", id); err == nil {
					t.Fatalf("deleted protected or missing run %q", id)
				}
			}
			if err := desktop.DeleteRun("p", "remove"); err != nil {
				t.Fatal(err)
			}
			expected.Projects[0].Runs = append(expected.Projects[0].Runs[:1], expected.Projects[0].Runs[2:]...)
			after, err := db.Read()
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(after, expected) {
				t.Fatal("deleting an incomplete run changed other workspace data")
			}
		})
	}
}

func TestDesktopCacheConfiguration(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	cfg := model.Defaults().Settings
	cfg.CacheHours, cfg.CacheMaxEntries, cfg.CacheMaxMiB = 12, 25000, 1024
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}
	for _, limits := range [][3]int{{-1, 25000, 1024}, {169, 25000, 1024}, {12, 99, 1024}, {12, 1000001, 1024}, {12, 25000, 15}, {12, 25000, 4097}} {
		invalid := cfg
		invalid.CacheHours, invalid.CacheMaxEntries, invalid.CacheMaxMiB = limits[0], limits[1], limits[2]
		if err := desktop.SaveSettings(SettingsInput{Settings: invalid}); err == nil {
			t.Errorf("accepted invalid cache settings %v", limits)
		}
	}
	cfg.CacheMaxEntries, cfg.CacheMaxMiB = 0, 0
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}
	state, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if state.Settings.CacheHours != 12 || state.CacheStats.MaxEntries != 25000 || state.CacheStats.MaxBytes != 1024<<20 {
		t.Fatalf("unexpected cache settings: %+v", state.CacheStats)
	}
}

func TestDesktopOSVConfigurationNormalizesAndPreservesExplicitSelections(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	cfg := model.Defaults().Settings
	cfg.OSVEcosystems = []string{"Go", "Debian:12", "Go"}
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}

	state, err := desktop.State()
	if err != nil || !reflect.DeepEqual(state.Settings.OSVEcosystems, []string{"Debian", "Go"}) || state.Settings.OSVUpdateSchedule != "daily" {
		t.Fatalf("unexpected OSV configuration: %+v %v", state.Settings, err)
	}

	for _, values := range [][]string{{"../Go"}, {"https://host"}, {"Go/../../"}} {
		invalid := cfg
		invalid.OSVEcosystems = values
		if err := desktop.SaveSettings(SettingsInput{Settings: invalid}); err == nil {
			t.Fatalf("invalid ecosystem accepted: %v", values)
		}
	}

	cfg.OSVEcosystems = []string{}
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err != nil {
		t.Fatal(err)
	}

	stored, err := desktop.store.Read()
	if err != nil || stored.Settings.OSVEcosystems == nil || len(stored.Settings.OSVEcosystems) != 0 {
		t.Fatal("an explicit empty selection was replaced by automatic project suggestions")
	}

	cfg.OSVUpdateSchedule = "weekly"
	if err := desktop.SaveSettings(SettingsInput{Settings: cfg}); err == nil {
		t.Fatal("unsupported OSV schedule accepted")
	}
}

func TestDesktopRejectsUnsafeExternalLinks(t *testing.T) {
	var opened []string
	desktop := &Desktop{openBrowser: func(raw string) error {
		opened = append(opened, raw)
		return nil
	}}
	for _, raw := range []string{"javascript:alert(1)", "file:///etc/passwd", "https://", "//example.org", "https://user:pass@example.org"} {
		if err := desktop.OpenExternal(raw); err == nil {
			t.Errorf("accepted unsafe link %q", raw)
		}
	}
	const publicLink = "https://example.org/advisory"
	if err := desktop.OpenExternal(publicLink); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 1 || opened[0] != publicLink {
		t.Fatalf("unexpected external links: %v", opened)
	}
}
