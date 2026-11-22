package scanner

import (
	"context"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/workflow"
)

func TargetKeys(p model.Project) []string {
	var keys []string
	if p.LocalPath != "" {
		keys = append(keys, "local")
	}

	for _, repository := range p.Repositories() {
		keys = append(keys, RemoteTargetKey(repository))
	}

	return keys
}

// GitHub checkouts require an explicit custom tool selection. Legacy Automatic
// GitHub profiles remain inactive until the user chooses tools in the editor.
// Local folders retain file detection and their existing repository-wide opt-ins.
func EffectiveProfile(p model.Project, s model.Settings, target string) model.ScannerProfile {
	remote := strings.HasPrefix(target, "remote:")
	if profile, ok := p.ScannerProfiles[target]; ok {
		if remote && profile.Mode != "custom" && profile.Mode != "disabled" {
			return model.ScannerProfile{Mode: "disabled"}
		}
		if profile.Mode == "" {
			profile.Mode = "auto"
		}
		return profile
	}

	if remote {
		return model.ScannerProfile{Mode: "disabled"}
	}

	profile := model.ScannerProfile{Mode: "auto"}

	for _, tool := range registry {
		if tool.Scope == "repository" && s.Scanners[tool.ID] {
			profile.AdditionalTools = append(profile.AdditionalTools, tool.ID)
		}
	}

	return profile
}

func NormalizeProfile(profile model.ScannerProfile) (model.ScannerProfile, error) {
	if profile.Mode != "auto" && profile.Mode != "custom" && profile.Mode != "disabled" {
		return profile, apperror.New("scanner_profile_mode_invalid", "Choose Automatic, Custom selection, or Disabled for repository scanning.")
	}

	for _, name := range append(slices.Clone(profile.Tools), profile.AdditionalTools...) {
		if !Supported(name) {
			return profile, apperror.New("unsupported_scanner", "unsupported scanner")
		}
	}

	for _, name := range profile.AdditionalTools {
		item, _ := definition(name)
		if item.Scope != "repository" {
			return profile, apperror.New("scanner_additional_invalid", "Additional scanners must support repository-wide scanning.")
		}
	}

	profile.Tools = orderedNames(profile.Tools)
	profile.AdditionalTools = orderedNames(profile.AdditionalTools)
	if profile.Mode == "custom" && len(profile.Tools) == 0 {
		return profile, apperror.New("scanner_profile_empty", "Select at least one scanner, or set the repository mode to Disabled.")
	}
	profile.NeedsScan = false
	return profile, nil
}

func orderedNames(names []string) []string {
	var result []string
	for _, tool := range registry {
		if slices.Contains(names, tool.ID) {
			result = append(result, tool.ID)
		}
	}

	return result
}

func SameProfile(a, b model.ScannerProfile) bool {
	return a.Mode == b.Mode && a.GenerateLockfiles == b.GenerateLockfiles && a.IgnoreComposerPlatform == b.IgnoreComposerPlatform && slices.Equal(orderedNames(a.Tools), orderedNames(b.Tools)) && slices.Equal(orderedNames(a.AdditionalTools), orderedNames(b.AdditionalTools))
}

func UsesLocalPackagist(p model.Project, s model.Settings) bool {
	if !p.ScanCode || !s.Scanners["composer-lock"] {
		return false
	}
	tool, _ := definition("composer-lock")
	for _, target := range TargetKeys(p) {
		if profileSelects(EffectiveProfile(p, s, target), tool) {
			return true
		}
	}
	return false
}

func profileSelects(profile model.ScannerProfile, tool Definition) bool {
	if profile.Mode == "disabled" {
		return false
	}

	if profile.Mode == "custom" {
		return slices.Contains(profile.Tools, tool.ID)
	}

	return tool.Scope != "repository" || slices.Contains(profile.AdditionalTools, tool.ID)
}

func patternMatches(patterns []string, names []string) bool {
	for _, pattern := range patterns {
		for _, name := range names {
			matched, _ := path.Match(pattern, name)
			if matched {
				return true
			}
		}
	}

	return false
}

func discoverInputs(ctx context.Context, directory string) (map[string][]string, error) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}

	defer func() { _ = root.Close() }()
	inputs := map[string][]string{}
	entries := 0
	err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := workflow.Wait(ctx); err != nil {
			return err
		}
		entries++
		if entries > 100000 {
			return apperror.New("scanner_discovery_limit", "Repository discovery exceeded 100,000 entries. Excluded dependency and generated folders are not scanned.")
		}
		if entry.IsDir() {
			if excludedScannerDirectory(entry.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		// Do not traverse or use symlinked manifests, including links outside a checkout.
		if !entry.Type().IsRegular() {
			return nil
		}
		for _, tool := range registry {
			if patternMatches(tool.Detect, []string{entry.Name()}) {
				dir := path.Dir(name)
				inputs[dir] = append(inputs[dir], entry.Name())
				break
			}
		}
		return nil
	})
	return inputs, err
}

func Plan(ctx context.Context, directory string, profile model.ScannerProfile, enabled map[string]bool) ([]model.ScannerJob, error) {
	inputs, err := discoverInputs(ctx, directory)
	if err != nil {
		return nil, apperror.Newf("scanner_discovery_failed", "Could not inspect repository project files: %w", err)
	}
	directories := make([]string, 0, len(inputs))
	for directory := range inputs {
		directories = append(directories, directory)
	}
	slices.Sort(directories)
	var jobs []model.ScannerJob
	for _, tool := range registry {
		var applicable []string
		if tool.Scope == "repository" {
			applicable = []string{"."}
		} else {
			for _, directory := range directories {
				if patternMatches(tool.Detect, inputs[directory]) {
					applicable = append(applicable, directory)
				}
			}
		}
		if len(applicable) == 0 {
			applicable = []string{""}
		}
		for _, directory := range applicable {
			job := model.ScannerJob{Tool: tool.ID, Path: directory, Status: "planned"}
			if job.Path == "." {
				job.Path = ""
			}
			switch {
			case profile.Mode == "disabled":
				job.Status, job.Reason = "skipped", "repository_disabled"
			case !enabled[tool.ID]:
				job.Status, job.Reason = "skipped", "global_disabled"
			case !profileSelects(profile, tool):
				job.Status, job.Reason = "skipped", "not_selected"
			case directory == "" && profile.Mode == "custom":
				job.Status, job.Reason = "blocked", "missing_input"
			case directory == "":
				job.Status, job.Reason = "skipped", "not_applicable"
			default:
				for _, alternatives := range tool.Inputs {
					if !patternMatches(alternatives, inputs[directory]) {
						job.Status, job.Reason = "blocked", "missing_input"
						if profile.GenerateLockfiles && canGenerateLockfile(tool.ID, inputs[directory]) {
							job.Status, job.Reason = "planned", "lockfile_required"
						}
						break
					}
				}
			}
			jobs = append(jobs, job)
			if len(jobs) > model.MaxScannerJobs {
				return nil, apperror.New("scanner_plan_limit", "Repository contains too many project directories to scan in one run.")
			}
		}
	}

	return jobs, nil
}

type Coverage struct {
	GeneratedLockfile bool
	Target            string
	Tool              string
	Path              string
}

type Report struct {
	Findings         []model.Finding
	Problems         []error
	Completed        []Coverage
	CompletedTargets []string
}

func findingTarget(p model.Project, f model.Finding) string {
	if strings.HasPrefix(f.AssetID, "code:local:") || f.ScanTarget == "local" {
		return "local"
	}

	if rest, ok := strings.CutPrefix(f.AssetID, "code:remote:"); ok {
		key, _, _ := strings.Cut(rest, ":")
		if len(key) == 64 {
			return "remote:" + key
		}
	}
	var targets []string
	for _, repository := range p.Repositories() {
		if f.ScanRepository != "" && RepositoryLabel(repository) == f.ScanRepository {
			targets = append(targets, RemoteTargetKey(repository))
		}
	}

	if len(targets) == 1 {
		return targets[0]
	}

	if f.ScanRepository == "" && len(TargetKeys(p)) == 1 {
		return TargetKeys(p)[0]
	}

	return ""
}

// Keep source provenance for tools and working directories which were not
// successfully checked. A skipped scanner must never resolve an old advisory.
func (report Report) Unassessed(prior []model.Finding, project model.Project) []model.Finding {
	var kept []model.Finding
	for _, finding := range prior {
		if finding.Match != "scanner" {
			continue
		}
		target := findingTarget(project, finding)
		var uncovered []string
		for _, source := range finding.Sources {
			covered := false
			for _, coverage := range report.Completed {
				tool, ok := definition(coverage.Tool)
				if ok && (!coverage.GeneratedLockfile || finding.GeneratedLockfile) && target == coverage.Target && strings.EqualFold(source, tool.Label) && (tool.Scope == "repository" || coverage.Path == finding.ScanPath) {
					covered = true
					break
				}
			}
			if !covered {
				uncovered = append(uncovered, source)
			}
		}
		if len(uncovered) > 0 || len(finding.Sources) == 0 {
			finding.Sources = uncovered
			kept = append(kept, finding)
		}
	}

	return kept
}
