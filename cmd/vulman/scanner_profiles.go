package main

import (
	"slices"
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/scanner"
)

// Repository profiles share the project's validation, revision check, and commit.
// A nil input preserves valid profiles and retires legacy GitHub Automatic modes.
func saveProjectScannerProfiles(old model.Project, next *model.Project, settings model.Settings, inputs []RepositoryScannerInput) error {
	targets := scanner.TargetKeys(*next)
	next.ScannerProfiles = make(map[string]model.ScannerProfile)
	for key := range old.ScannerProfiles {
		if slices.Contains(targets, key) && (key != "local" || old.LocalPath == next.LocalPath) {
			next.ScannerProfiles[key] = scanner.EffectiveProfile(old, settings, key)
		}
	}

	seen := map[string]bool{}
	for _, input := range inputs {
		repository := strings.TrimSpace(input.Repository)
		key := "local"
		if input.Local {
			if repository != "" || next.LocalPath == "" {
				return apperror.New("scanner_profile_target_invalid", "Scanner profiles must refer to a repository or local folder in this project.")
			}
		} else {
			if !slices.Contains(next.Repositories(), repository) {
				return apperror.New("scanner_profile_target_invalid", "Scanner profiles must refer to a repository or local folder in this project.")
			}
			key = scanner.RemoteTargetKey(repository)
		}

		if seen[key] {
			return apperror.New("scanner_profile_target_duplicate", "Only one scanner profile can be saved for each repository or local folder.")
		}
		seen[key] = true

		if !input.Local && input.Profile.Mode != "custom" && input.Profile.Mode != "disabled" {
			return apperror.New("scanner_github_mode_invalid", "GitHub repositories support only Custom selection or Disabled scanning modes.")
		}

		profile, err := scanner.NormalizeProfile(input.Profile)
		if err != nil {
			return err
		}

		if !input.Local {
			profile.AdditionalTools = nil
		}

		previous := scanner.EffectiveProfile(old, settings, key)
		profile.NeedsScan = previous.NeedsScan
		newTarget := !slices.Contains(scanner.TargetKeys(old), key) || key == "local" && old.LocalPath != next.LocalPath
		if newTarget || !scanner.SameProfile(previous, profile) {
			profile.NeedsScan = profile.Mode != "disabled"
		}

		next.ScannerProfiles[key] = profile
	}

	return nil
}

// Configuration controls the globally allowed tools. Per-repository choices
// belong to projects and cannot be overwritten by a stale Configuration form.
func saveGlobalScannerSettings(st *model.State, cfg *model.Settings) error {
	changed := !slices.Equal(scanner.EnabledTools(cfg.Scanners), scanner.EnabledTools(st.Settings.Scanners))
	if changed && cfg.ScannerConfigRevision != st.Settings.ScannerConfigRevision {
		return apperror.New("scanner_settings_changed", "Scanner settings changed. Reload Configuration before saving.")
	}

	cfg.ScannerConfigRevision = st.Settings.ScannerConfigRevision
	if !changed {
		return nil
	}

	for i := range st.Projects {
		project := &st.Projects[i]
		if project.Syncing && len(scanner.TargetKeys(*project)) > 0 {
			return apperror.New("scanner_settings_active", "Wait for the active assessment before changing scanner settings.")
		}

		// Materialize effective policies before the new permissions take effect.
		// Local Automatic opt-ins stay intact; GitHub Automatic remains inactive.
		for _, target := range scanner.TargetKeys(*project) {
			profile := scanner.EffectiveProfile(*project, st.Settings, target)
			profile.NeedsScan = profile.Mode != "disabled"
			if project.ScannerProfiles == nil {
				project.ScannerProfiles = map[string]model.ScannerProfile{}
			}
			project.ScannerProfiles[target] = profile
		}
	}

	cfg.ScannerConfigRevision = model.NewID()
	return nil
}
