package engine

import (
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/sources"
)

type assessmentScope struct {
	all          bool
	assets       map[string]bool
	repositories map[string]bool
}

func newAssessmentScope(assetIDs, scanTargets []string) (assessmentScope, error) {
	scope := assessmentScope{all: assetIDs == nil && scanTargets == nil}
	if scope.all {
		return scope, nil
	}

	scope.assets = make(map[string]bool, len(assetIDs))
	for _, id := range assetIDs {
		scope.assets[id] = true
	}

	scope.repositories = make(map[string]bool, len(scanTargets))
	for _, target := range scanTargets {
		scope.repositories[target] = true
	}

	if len(scope.assets)+len(scope.repositories) == 0 {
		return scope, apperror.New("assessment_selection_empty", "Select at least one tech stack component or repository, or choose Everything.")
	}

	return scope, nil
}

func (scope assessmentScope) hasAsset(id string) bool {
	return scope.all || scope.assets[id]
}

func (scope assessmentScope) validate(p model.Project) error {
	if scope.all {
		return nil
	}

	assets := make(map[string]bool, len(p.Assets))
	for _, asset := range p.Assets {
		assets[asset.ID] = true
	}
	for id := range scope.assets {
		if id == "" || !assets[id] {
			return ErrAssetNotFound
		}
	}

	repositories := make(map[string]bool)
	if p.LocalPath != "" {
		repositories["local"] = true
	}
	for _, repository := range p.Repositories() {
		repositories[scanner.RemoteTargetKey(repository)] = true
	}
	for target := range scope.repositories {
		if !repositories[target] {
			return apperror.New("scan_repository_not_registered", "The selected repository is no longer registered in this project.")
		}
	}

	return nil
}

func (scope assessmentScope) project(p model.Project) model.Project {
	if scope.all {
		return p
	}

	selected := p
	selected.Assets = nil
	for _, asset := range p.Assets {
		if scope.assets[asset.ID] {
			selected.Assets = append(selected.Assets, asset)
		}
	}

	selected.Repository = ""
	selected.RepositoryURLs = nil
	selected.LocalPath = ""
	selected.ScanCode = p.ScanCode && len(scope.repositories) > 0
	if scope.repositories["local"] {
		selected.LocalPath = p.LocalPath
	}
	for _, repository := range p.Repositories() {
		if scope.repositories[scanner.RemoteTargetKey(repository)] {
			selected.RepositoryURLs = append(selected.RepositoryURLs, repository)
		}
	}

	return selected
}

func (scope assessmentScope) selection(p model.Project) *model.AssessmentSelection {
	if scope.all {
		return nil
	}

	selected := scope.project(p)
	selection := &model.AssessmentSelection{}
	for _, asset := range selected.Assets {
		selection.Assets = append(selection.Assets, model.AssessmentItem{ID: asset.ID, Label: asset.Name + " " + asset.Version})
	}
	if selected.LocalPath != "" {
		selection.Repositories = append(selection.Repositories, model.AssessmentItem{ID: "local"})
	}
	for _, repository := range selected.Repositories() {
		selection.Repositories = append(selection.Repositories, model.AssessmentItem{ID: scanner.RemoteTargetKey(repository), Label: scanner.RepositoryLabel(repository)})
	}

	return selection
}

func (scope assessmentScope) findings(p model.Project, mode string) (selected, preserved []model.Finding) {
	for _, finding := range p.Findings {
		included := scope.hasAsset(finding.AssetID)
		if finding.Match == "scanner" {
			included = scope.all
			if !scope.all {
				switch {
				case strings.HasPrefix(finding.AssetID, "code:remote:"):
					key, _, _ := strings.Cut(strings.TrimPrefix(finding.AssetID, "code:remote:"), ":")
					included = scope.repositories["remote:"+key]
				case strings.HasPrefix(finding.AssetID, "code:local:"):
					included = scope.repositories["local"]
				default:
					for target := range scope.repositories {
						if findingInScanTarget(finding, p, target) {
							included = true
							break
						}
					}
				}
			}
		} else if mode == codeScanMode {
			included = false
		}

		if included {
			selected = append(selected, finding)
		} else {
			preserved = append(preserved, finding)
		}
	}

	return selected, preserved
}

func findingInScanTarget(f model.Finding, p model.Project, target string) bool {
	if strings.HasPrefix(f.AssetID, "code:remote:") || strings.HasPrefix(f.AssetID, "code:local:") {
		return strings.HasPrefix(f.AssetID, "code:"+target+":")
	}

	if target == "local" {
		return f.ScanTarget == "local"
	}

	// Older findings only recorded a display label. Preserve ambiguous records.
	labelMatches := 0
	selected := false
	for _, repository := range p.Repositories() {
		if scanner.RepositoryLabel(repository) == f.ScanRepository && f.ScanRepository != "" {
			labelMatches++
			selected = selected || scanner.RemoteTargetKey(repository) == target
		}
	}

	return selected && labelMatches == 1
}

func matchesSeverity(f model.Finding, severity string) bool {
	return severity == "" || model.NormalizeSeverity(f.Severity) == severity
}

func inScope(f model.Finding, assetID, severity string) bool {
	return (assetID == "" || f.AssetID == assetID) && matchesSeverity(f, severity)
}

func findingKey(f model.Finding) struct{ asset, id string } {
	return struct{ asset, id string }{f.AssetID, f.ID}
}

func severityCount(findings []model.Finding, severity string) int {
	count := 0
	for _, f := range findings {
		if matchesSeverity(f, severity) {
			count++
		}
	}

	return count
}

func findingSeverityCounts(findings []model.Finding) map[string]int {
	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
	for _, finding := range findings {
		counts[model.NormalizeSeverity(finding.Severity)]++
	}

	return counts
}

// Also reconcile previously selected advisories whose severity has changed.
// A downgrade must update its rating rather than make the advisory disappear.
func severityCandidates(fetched, prior []model.Finding, assetID, severity string) []model.Finding {
	oldScope := map[struct{ asset, id string }]bool{}
	for _, f := range prior {
		if inScope(f, assetID, severity) {
			oldScope[findingKey(f)] = true
		}
	}

	selected := []model.Finding{}
	for _, f := range fetched {
		if (assetID == "" || f.AssetID == assetID) && (matchesSeverity(f, severity) || oldScope[findingKey(f)]) {
			selected = append(selected, f)
		}
	}

	return selected
}

func retainOutsideScope(updates, prior []model.Finding, assetID, severity string) []model.Finding {
	updated := map[struct{ asset, id string }]bool{}
	for _, f := range updates {
		updated[findingKey(f)] = true
	}

	for _, f := range prior {
		if !inScope(f, assetID, severity) && !updated[findingKey(f)] {
			updates = append(updates, f)
		}
	}

	return sources.Merge(updates)
}
