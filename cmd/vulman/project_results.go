package main

import (
	"slices"
	"strings"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
)

func removeProjectResults(project *model.Project, next model.Project) {
	removedAssets := make(map[string]bool)
	for _, asset := range project.Assets {
		if !slices.ContainsFunc(next.Assets, func(a model.Asset) bool { return a.ID == asset.ID }) {
			removedAssets[asset.ID] = true
		}
	}
	removedTargets := make(map[string]bool)
	removedLabels := make(map[string]bool)

	if project.LocalPath != "" && project.LocalPath != next.LocalPath {
		removedTargets["local"] = true
	}

	retainedRepositories := next.Repositories()

	for _, repository := range project.Repositories() {
		if !slices.Contains(retainedRepositories, repository) {
			removedTargets[scanner.RemoteTargetKey(repository)] = true
			removedLabels[scanner.RepositoryLabel(repository)] = true
		}
	}

	if len(removedAssets) == 0 && len(removedTargets) == 0 {
		return
	}

	allLocationsRemoved := len(removedTargets) != 0 && next.LocalPath == "" && len(retainedRepositories) == 0

	project.Findings = slices.DeleteFunc(project.Findings, func(f model.Finding) bool {
		if f.Match != "scanner" {
			return removedAssets[f.AssetID]
		}

		if len(removedTargets) == 0 {
			return false
		}

		if allLocationsRemoved {
			return true
		}

		if strings.HasPrefix(f.AssetID, "code:local:") {
			return removedTargets["local"]
		}

		if remote, ok := strings.CutPrefix(f.AssetID, "code:remote:"); ok {
			key, _, _ := strings.Cut(remote, ":")
			return removedTargets["remote:"+key]
		}

		if f.ScanRepository != "" {
			return removedLabels[f.ScanRepository]
		}

		switch f.ScanTarget {
		case "local":
			return removedTargets["local"]
		case "remote":
			return len(removedLabels) != 0
		default:
			// Older scan findings have no location attribution.
			return true
		}
	})

	// Removing an affected run also removes its aggregated severity counts,
	// combined warnings, and workflow logs in the same state transaction.
	project.Runs = slices.DeleteFunc(project.Runs, func(run model.Run) bool {
		return len(removedAssets) != 0 && runUsesRemovedComponent(run, removedAssets) ||
			len(removedTargets) != 0 && runUsesRemovedLocation(run, removedTargets, removedLabels, allLocationsRemoved)
	})

	project.LastSync = time.Time{}
	project.DataCheckedAt = time.Time{}
	project.AssessedRevision = 0
}

func runUsesRemovedComponent(run model.Run, removed map[string]bool) bool {
	if run.AssetID != "" {
		return removed[run.AssetID]
	}

	if run.Mode == "code" {
		return false
	}

	usesRemovedStep := func(id string) bool {
		kind, assetID, ok := strings.Cut(id, ":")
		return ok && (kind == "nvd" || kind == "osv") && removed[assetID]
	}

	return len(run.Steps) == 0 ||
		slices.ContainsFunc(run.Steps, func(s model.SyncStep) bool { return usesRemovedStep(s.ID) }) ||
		slices.ContainsFunc(run.Logs, func(l model.SyncLog) bool { return usesRemovedStep(l.StepID) })
}

func runUsesRemovedLocation(run model.Run, removed, labels map[string]bool, allLocationsRemoved bool) bool {
	if len(run.ScanTargets) != 0 {
		return allLocationsRemoved || slices.ContainsFunc(run.ScanTargets, func(target string) bool { return removed[target] })
	}

	if run.AssetID != "" || run.Mode == "local" {
		return false
	}

	// Older runs recorded labels in workflow events, with a fixed log limit.
	hasLocation := false
	for _, event := range run.Logs {
		if event.ScanTarget == "local" && (allLocationsRemoved || removed["local"]) ||
			event.ScanTarget == "remote" && (allLocationsRemoved || labels[event.ScanRepository]) {
			return true
		}
		hasLocation = hasLocation || event.ScanTarget == "local" || event.ScanRepository != ""
	}

	if hasLocation && len(run.Logs) < model.MaxSyncLogs && run.Logs[0].Event == "run_started" {
		return false
	}

	return run.Mode == "code" || len(run.Steps) == 0 || slices.ContainsFunc(run.Steps, func(step model.SyncStep) bool {
		return step.Kind == "scanner" && step.Status != "pending" && step.Status != "skipped"
	})
}
