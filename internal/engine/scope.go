package engine

import (
	"vulman/internal/model"
	"vulman/internal/sources"
)

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
