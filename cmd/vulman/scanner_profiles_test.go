package main

import (
	"testing"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/scanner"
)

func TestRepositoryProfilesSaveWithProjectAndRejectStaleEditors(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	repository := "https://github.com/owner/php-web"
	project, err := desktop.CreateProject(ProjectInput{
		Name: "Mixed", RepositoryURLs: []string{repository}, Schedule: "off",
		RepositoryScanners: []RepositoryScannerInput{{Repository: repository, Profile: model.ScannerProfile{Mode: "custom", Tools: []string{"composer", "npm"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := scanner.RemoteTargetKey(repository)
	profile := project.ScannerProfiles[key]
	if profile.Mode != "custom" || len(profile.Tools) != 2 || !profile.NeedsScan {
		t.Fatalf("profile not created with project: %+v", project)
	}

	input := ProjectInput{
		Name: "Edited", RepositoryURLs: []string{repository}, Schedule: "off", Revision: project.Revision,
		RepositoryScanners: []RepositoryScannerInput{{Repository: repository, Profile: model.ScannerProfile{Mode: "disabled"}}},
	}
	updated, err := desktop.UpdateProject(project.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Edited" || updated.ScannerProfiles[key].Mode != "disabled" || updated.ScannerProfiles[key].NeedsScan {
		t.Fatalf("profile did not save with project: %+v", updated)
	}
	if _, err := desktop.UpdateProject(project.ID, input); err == nil || apperror.Public(err).Code != "project_changed_reload_before_saving" {
		t.Fatalf("stale editor accepted: %v", err)
	}

	reopened, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Projects[0].ScannerProfiles[key].Mode != "disabled" || reopened.ScanRepositories[project.ID][0].URL != repository {
		t.Fatal("saved profile could not be reloaded and associated with its URL")
	}
}

func TestInvalidProjectProfilesDoNotPartiallyCommit(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	repository := "https://github.com/owner/project"
	project, err := desktop.CreateProject(ProjectInput{Name: "Original", RepositoryURLs: []string{repository}, Schedule: "off"})
	if err != nil {
		t.Fatal(err)
	}
	for _, profiles := range [][]RepositoryScannerInput{
		{{Repository: "https://github.com/owner/unregistered", Profile: model.ScannerProfile{Mode: "disabled"}}},
		{{Local: true, Profile: model.ScannerProfile{Mode: "disabled"}}},
		{{Repository: repository, Profile: model.ScannerProfile{Mode: "custom", Tools: []string{"shell"}}}},
		{{Repository: repository, Profile: model.ScannerProfile{Mode: "custom"}}},
		{{Repository: repository, Profile: model.ScannerProfile{Mode: "custom", Tools: []string{"trivy"}}}, {Repository: repository, Profile: model.ScannerProfile{Mode: "disabled"}}},
	} {
		_, err := desktop.UpdateProject(project.ID, ProjectInput{Name: "Must not save", RepositoryURLs: []string{repository}, Schedule: "off", Revision: project.Revision, RepositoryScanners: profiles})
		if err == nil {
			t.Fatalf("invalid profiles accepted: %+v", profiles)
		}
		saved, err := desktop.store.Read()
		if err != nil {
			t.Fatal(err)
		}
		if saved.Projects[0].Name != project.Name || saved.Projects[0].Revision != project.Revision {
			t.Fatal("invalid profile caused a partial project save")
		}
	}
}

func TestProfilesRemainIndependentAndSurviveUnrelatedUpdates(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	first, second := "https://github.com/owner/one", "https://github.com/owner/two"
	project, err := desktop.CreateProject(ProjectInput{
		Name: "Independent", RepositoryURLs: []string{first, second}, LocalPath: "/project", Schedule: "off",
		RepositoryScanners: []RepositoryScannerInput{
			{Repository: first, Profile: model.ScannerProfile{Mode: "custom", Tools: []string{"composer", "npm"}}},
			{Repository: second, Profile: model.ScannerProfile{Mode: "disabled"}},
			{Local: true, Profile: model.ScannerProfile{Mode: "auto"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	updated, err := desktop.UpdateProject(project.ID, ProjectInput{Name: "Rename", RepositoryURLs: []string{first, second}, LocalPath: "/project", Schedule: "off", Revision: project.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.ScannerProfiles) != 3 || updated.ScannerProfiles[scanner.RemoteTargetKey(first)].Mode != "custom" || updated.ScannerProfiles[scanner.RemoteTargetKey(second)].Mode != "disabled" {
		t.Fatalf("unrelated update changed scanner choices: %+v", updated.ScannerProfiles)
	}
	updated, err = desktop.UpdateProject(updated.ID, ProjectInput{Name: updated.Name, RepositoryURLs: []string{first}, Schedule: "off", Revision: updated.Revision})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.ScannerProfiles) != 1 || updated.ScannerProfiles[scanner.RemoteTargetKey(first)].Mode != "custom" {
		t.Fatalf("removed target profiles were not pruned: %+v", updated.ScannerProfiles)
	}
}

func TestProfileChangesKeepFindingsAndAssessmentDateUntilRescan(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	lastSync := time.Now().Add(-time.Hour)
	if err := desktop.store.Update(func(st *model.State) error {
		st.Projects = []model.Project{{ID: "p", Name: "Code", LocalPath: "/project", Schedule: "off", Revision: 1, LastSync: lastSync,
			Findings:        []model.Finding{{ID: "CVE-prior", AssetID: "code:local:demo", Match: "scanner", Severity: "HIGH"}},
			ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "auto"}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := desktop.UpdateProject("p", ProjectInput{Name: "Code", LocalPath: "/project", Schedule: "off", Revision: 1,
		RepositoryScanners: []RepositoryScannerInput{{Local: true, Profile: model.ScannerProfile{Mode: "custom", Tools: []string{"pip-audit"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.ScannerProfiles["local"].NeedsScan || len(updated.Findings) != 1 || !updated.LastSync.Equal(lastSync) {
		t.Fatalf("profile edit altered assessment results: %+v", updated)
	}
}

func TestActiveProfilesCannotChangeAndGlobalSettingsKeepProjectChoices(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	if err := desktop.store.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"npm": true}
		st.Projects = []model.Project{{ID: "p", LocalPath: "/project", Syncing: true,
			ScannerProfiles: map[string]model.ScannerProfile{"local": {Mode: "custom", Tools: []string{"npm"}}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := desktop.UpdateProject("p", ProjectInput{}); err == nil || apperror.Public(err).Code != "wait_for_the_active_assessment_before_editing" {
		t.Fatalf("changed an active profile: %v", err)
	}
	state, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	input := SettingsInput{Settings: state.Settings}
	input.Language = "ja"
	if err := desktop.SaveSettings(input); err != nil {
		t.Fatalf("language save blocked: %v", err)
	}
	input.Scanners = map[string]bool{"npm": true, "trivy": true}
	if err := desktop.SaveSettings(input); err == nil || apperror.Public(err).Code != "scanner_settings_active" {
		t.Fatalf("changed global tools during an assessment: %v", err)
	}
	if err := desktop.store.Update(func(st *model.State) error { st.Projects[0].Syncing = false; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := desktop.SaveSettings(input); err != nil {
		t.Fatal(err)
	}
	saved, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	profile := saved.Projects[0].ScannerProfiles["local"]
	if profile.Mode != "custom" || len(profile.Tools) != 1 || profile.Tools[0] != "npm" || !profile.NeedsScan {
		t.Fatalf("global permissions overwrote project choices: %+v", profile)
	}
	input.Scanners = map[string]bool{"npm": true}
	if err := desktop.SaveSettings(input); err == nil || apperror.Public(err).Code != "scanner_settings_changed" {
		t.Fatalf("stale Configuration permissions accepted: %v", err)
	}
}

func TestGitHubProfilesRejectAutomaticAndKeepLocalAutomatic(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	repository := "https://github.com/owner/project"
	_, err := desktop.CreateProject(ProjectInput{Name: "Invalid", RepositoryURLs: []string{repository}, Schedule: "off",
		RepositoryScanners: []RepositoryScannerInput{{Repository: repository, Profile: model.ScannerProfile{Mode: "auto"}}},
	})
	if err == nil || apperror.Public(err).Code != "scanner_github_mode_invalid" {
		t.Fatalf("GitHub Automatic accepted: %v", err)
	}
	state, err := desktop.State()
	if err != nil || len(state.Projects) != 0 {
		t.Fatalf("invalid mode partially saved: %+v %v", state, err)
	}

	project, err := desktop.CreateProject(ProjectInput{Name: "Local", LocalPath: "/local", Schedule: "off",
		RepositoryScanners: []RepositoryScannerInput{{Local: true, Profile: model.ScannerProfile{Mode: "auto", AdditionalTools: []string{"trivy"}}}},
	})
	if err != nil || project.ScannerProfiles["local"].Mode != "auto" {
		t.Fatalf("local Automatic rejected: %+v %v", project, err)
	}
}

func TestLegacyGitHubAutomaticIsDisabledWithoutDeletingResults(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	repository := "https://github.com/owner/project"
	target := scanner.RemoteTargetKey(repository)
	if err := desktop.store.Update(func(st *model.State) error {
		st.Settings.Scanners = map[string]bool{"trivy": true}
		st.Projects = []model.Project{{ID: "p", Name: "Legacy", Revision: 1, Schedule: "off", RepositoryURLs: []string{repository}, LocalPath: "/local",
			ScannerProfiles: map[string]model.ScannerProfile{target: {Mode: "auto", AdditionalTools: []string{"trivy"}}, "local": {Mode: "auto"}},
			Findings:        []model.Finding{{ID: "CVE-prior", AssetID: "code:" + target + ":demo", Match: "scanner"}},
		}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	project, err := desktop.UpdateProject("p", ProjectInput{Name: "Legacy", Revision: 1, Schedule: "off", RepositoryURLs: []string{repository}, LocalPath: "/local"})
	if err != nil || project.ScannerProfiles[target].Mode != "disabled" || project.ScannerProfiles["local"].Mode != "auto" || len(project.Findings) != 1 {
		t.Fatalf("legacy mode conversion changed results or local mode: %+v %v", project, err)
	}
}
