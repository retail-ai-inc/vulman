package main

import (
	"reflect"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
)

func TestProjectUpdateRemovesFindingsAndAffectedRuns(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	removedURL := "https://github.com/owner/demo.git?view=first"
	keptURL := "https://github.com/owner/demo.git?view=second"
	removedKey, keptKey := scanner.RemoteTargetKey(removedURL), scanner.RemoteTargetKey(keptURL)
	urlLabel := scanner.RepositoryLabel(removedURL)
	project, err := desktop.CreateProject(ProjectInput{
		Name: "Demo", Schedule: "weekly", ScanCode: true, RepositoryURLs: []string{removedURL, keptURL}, LocalPath: "/local",
		Assets: []model.Asset{
			{ID: "removed", Name: "same-package", Version: "1", Kind: "library"},
			{ID: "kept", Name: "same-package", Version: "1", Kind: "library"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	findings := []model.Finding{
		{ID: "CVE-shared", AssetID: "removed", Severity: "CRITICAL"},
		{ID: "CVE-shared", AssetID: "kept", Severity: "HIGH"},
		{ID: "CVE-shared", AssetID: "code:" + removedKey + ":same-package", Match: "scanner", ScanTarget: "remote", ScanRepository: urlLabel},
		{ID: "CVE-shared", AssetID: "code:" + keptKey + ":same-package", Match: "scanner", ScanTarget: "remote", ScanRepository: urlLabel},
		{ID: "CVE-shared", AssetID: "code:local:same-package", Match: "scanner", ScanTarget: "local"},
		{ID: "CVE-legacy", AssetID: "code:legacy", Match: "scanner", ScanTarget: "remote", ScanRepository: urlLabel},
		{ID: "CVE-unscoped", AssetID: "code:old", Match: "scanner"},
	}
	keptRuns := []model.Run{
		{ID: "kept-component", AssetID: "kept", Status: "complete", Count: 1},
		{ID: "kept-scan", Mode: "code", ScanTargets: []string{keptKey, "local"}, Count: 2},
		{ID: "older-local-scan", Mode: "code", Logs: []model.SyncLog{{Event: "run_started"}, {ScanTarget: "local"}}},
	}
	other := model.Project{ID: "other", Name: "Other", Repository: removedURL, Findings: []model.Finding{findings[2]}}
	if err := db.Update(func(st *model.State) error {
		p := &st.Projects[0]
		p.Findings = findings
		p.Runs = append([]model.Run{
			{ID: "removed-component", AssetID: "removed"},
			{ID: "mixed-assessment", Count: 4, Steps: []model.SyncStep{{ID: "nvd:kept"}, {ID: "osv:removed"}, {ID: "save"}}},
			{ID: "removed-scan", Mode: "code", ScanTargets: []string{removedKey, keptKey}, Count: 2},
			{ID: "older-remote-scan", Mode: "auto", Logs: []model.SyncLog{{StepID: "scanner", ScanTarget: "remote", ScanRepository: urlLabel}}},
			{ID: "unscoped-older-scan", Mode: "code", Count: 3},
		}, keptRuns...)
		p.LastSync, p.DataCheckedAt, p.AssessedRevision = time.Now(), time.Now(), p.Revision
		st.Projects = append(st.Projects, other)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	input := ProjectInput{
		Name: project.Name, Schedule: project.Schedule, Revision: project.Revision,
		ScanCode: true, RepositoryURLs: []string{keptURL}, LocalPath: project.LocalPath, Assets: project.Assets[1:],
	}
	stale := input
	stale.Revision--
	if _, err := desktop.UpdateProject(project.ID, stale); err == nil {
		t.Fatal("stale edit was accepted")
	}
	before, err := db.Read()
	if err != nil || len(before.Projects[0].Findings) != len(findings) {
		t.Fatalf("failed edit changed saved findings: %v", err)
	}

	updated, err := desktop.UpdateProject(project.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := db.Read()
	if err != nil {
		t.Fatal(err)
	}
	wantFindings := []model.Finding{findings[1], findings[3], findings[4]}
	for _, p := range []model.Project{updated, saved.Projects[0]} {
		if !reflect.DeepEqual(p.Findings, wantFindings) || !reflect.DeepEqual(p.Runs, keptRuns) {
			t.Fatalf("unexpected findings or history: %+v", p)
		}
		if !reflect.DeepEqual(p.Repositories(), []string{keptURL}) || len(p.Assets) != 1 || p.Assets[0].ID != "kept" ||
			!p.LastSync.IsZero() || !p.DataCheckedAt.IsZero() || p.AssessedRevision != 0 || !p.NextRun.Equal(project.NextRun) {
			t.Fatalf("unexpected project inventory or assessment summary: %+v", p)
		}
	}
	if !reflect.DeepEqual(saved.Projects[1], other) {
		t.Fatalf("another project changed: %+v", saved.Projects[1])
	}
}

func TestProjectUpdateCleansReplacedLocalFolderAndDisablesScanningAfterFinalRemoval(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	project, err := desktop.CreateProject(ProjectInput{Name: "Demo", Schedule: "off", ScanCode: true, LocalPath: "/original"})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Update(func(st *model.State) error {
		p := &st.Projects[0]
		p.Findings = []model.Finding{{ID: "CVE-old", AssetID: "code:local:demo", Match: "scanner"}}
		p.Runs = []model.Run{{ID: "local-run", ScanTargets: []string{"local"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	input := ProjectInput{Name: project.Name, Schedule: project.Schedule, Revision: project.Revision, ScanCode: true, LocalPath: "/replacement"}
	replaced, err := desktop.UpdateProject(project.ID, input)
	if err != nil || !replaced.ScanCode || replaced.LocalPath != input.LocalPath || len(replaced.Findings) != 0 || len(replaced.Runs) != 0 {
		t.Fatalf("unexpected project after replacing local folder: %+v, %v", replaced, err)
	}
	legacyKey := scanner.RemoteTargetKey("https://github.com/owner/previous")
	inventory := model.Finding{ID: "CVE-inventory", AssetID: "component"}
	inventoryRun := model.Run{ID: "inventory-run", Steps: []model.SyncStep{{ID: "nvd:component"}}}
	if err := db.Update(func(st *model.State) error {
		p := &st.Projects[0]
		p.Findings = []model.Finding{inventory, {ID: "CVE-legacy", AssetID: "code:" + legacyKey + ":demo", Match: "scanner"}}
		p.Runs = []model.Run{inventoryRun, {ID: "legacy-remote-run", ScanTargets: []string{legacyKey}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	input.Revision, input.LocalPath = replaced.Revision, ""
	removed, err := desktop.UpdateProject(project.ID, input)
	if err != nil || removed.ScanCode || removed.LocalPath != "" ||
		!reflect.DeepEqual(removed.Findings, []model.Finding{inventory}) || !reflect.DeepEqual(removed.Runs, []model.Run{inventoryRun}) {
		t.Fatalf("unexpected project after removing final location: %+v, %v", removed, err)
	}
}

func TestVersionEditRequiresReassessmentAndPreservesPreviousResults(t *testing.T) {
	db := newTestStore(t)
	desktop := &Desktop{store: db}
	project, err := desktop.CreateProject(ProjectInput{Name: "Demo", Schedule: "off", Assets: []model.Asset{
		{ID: "changed", Name: "demo", Version: "1.0.0", Kind: "library"},
		{ID: "kept", Name: "other", Version: "1.0.0", Kind: "library"},
	}})
	if err != nil {
		t.Fatal(err)
	}

	findings := []model.Finding{{ID: "CVE-old", AssetID: "changed", Component: "demo", Version: "1.0.0", Severity: "CRITICAL"}}
	if err := db.Update(func(st *model.State) error {
		p := &st.Projects[0]
		for i := range p.Assets {
			p.Assets[i].NeedsAssessment = false
		}

		p.Findings = findings
		p.Runs = []model.Run{{ID: "prior", Status: "complete", Count: 1}}
		p.AssessedRevision = p.Revision
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	assets := append([]model.Asset(nil), project.Assets...)
	assets[0].Version = "2.0.0"
	assets[0].NeedsAssessment = false
	assets[1].NeedsAssessment = true // Incoming flags cannot override saved status.
	input := ProjectInput{Name: project.Name, Schedule: project.Schedule, Revision: project.Revision, Assets: assets}
	updated, err := desktop.UpdateProject(project.ID, input)
	if err != nil {
		t.Fatal(err)
	}

	if !updated.Assets[0].NeedsAssessment || updated.Assets[1].NeedsAssessment || !reflect.DeepEqual(updated.Findings, findings) || len(updated.Runs) != 1 {
		t.Fatal("version edit retained a current count, changed unrelated assessment status, or discarded previous results")
	}

	input.Revision = updated.Revision
	input.Name = "Renamed project"
	input.Assets[0].NeedsAssessment = false
	if _, err := desktop.UpdateProject(updated.ID, input); err != nil {
		t.Fatal(err)
	}

	state, err := db.Read()
	if err != nil || !state.Projects[0].Assets[0].NeedsAssessment || state.Projects[0].Assets[1].NeedsAssessment {
		t.Fatal("metadata-only save cleared the pending reassessment or marked an unchanged component")
	}
}
