package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"vulman/internal/apperror"
)

func canGenerateLockfile(tool string, files []string) bool {
	switch tool {
	case "npm":
		return slices.Contains(files, "package.json") && !patternMatches([]string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}, files)
	case "composer":
		return slices.Contains(files, "composer.json") && !slices.Contains(files, "composer.lock")
	}

	return false
}

// Generation is called only inside the private scan workspace. It never creates
// manifests, replaces an existing lockfile, or enables scripts or plugins.
func generateLockfile(ctx context.Context, dir string, scratch *scanScratch, tool string, ignoreComposerPlatform ...bool) (resultErr error) {
	absolute, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	workspace, err := filepath.EvalSymlinks(scratch.path())
	if err != nil {
		return err
	}
	if relative, err := filepath.Rel(workspace, absolute); err != nil || !filepath.IsLocal(relative) {
		return apperror.New("scanner_generation_workspace", "Lockfiles can only be generated inside Vulman's temporary scan workspace.")
	}

	item, ok := definition(tool)
	if !ok || tool != "npm" && tool != "composer" {
		return apperror.New("unsupported_scanner", "unsupported scanner")
	}

	root, err := os.OpenRoot(absolute)
	if err != nil {
		return err
	}
	defer func() {
		if err := root.Close(); err != nil {
			resultErr = errors.Join(resultErr, err)
		}
	}()

	manifest, lockfile := "package.json", "package-lock.json"
	locks := []string{lockfile, "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}
	if tool == "composer" {
		manifest, lockfile = "composer.json", "composer.lock"
		locks = []string{lockfile}
	}
	info, err := root.Lstat(manifest)
	if err != nil || !info.Mode().IsRegular() {
		return apperror.Newf("scanner_generation_manifest_required", "%s lockfile generation requires a regular manifest file: %s", item.Label, manifest)
	}
	for _, name := range locks {
		if _, err := root.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
			return apperror.Newf("scanner_generation_existing_lockfile", "%s will not generate over an existing lockfile or link. Use the repository's package manager and lockfile.", item.Label)
		}
	}

	succeeded := false
	defer func() {
		if !succeeded {
			_ = root.Remove(lockfile)
		}
	}()

	generateCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	var cmd *exec.Cmd
	if tool == "composer" {
		args := []string{"--no-plugins", "--no-scripts", "--no-interaction", "update", "--no-install", "--no-audit", "--no-progress"}
		if len(ignoreComposerPlatform) > 0 && ignoreComposerPlatform[0] {
			args = append(args, "--ignore-platform-reqs")
		}
		cmd, err = newComposerCommand(generateCtx, args...)
	} else {
		cmd, err = newNPMCommand(generateCtx, "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--package-lock=true", "--global=false", "--prefix", ".")
	}
	if err != nil {
		return err
	}

	scratch.configure(cmd)
	if tool == "composer" {
		// A launch-environment override must not bypass this repository's opt-in.
		cmd.Env = slices.DeleteFunc(cmd.Env, func(entry string) bool {
			name, _, _ := strings.Cut(entry, "=")
			return strings.EqualFold(name, "COMPOSER_IGNORE_PLATFORM_REQS") || strings.EqualFold(name, "COMPOSER_IGNORE_PLATFORM_REQ")
		})
	}
	_, diagnostic, code, err := runWithStderr(generateCtx, dir, cmd, "")
	if err != nil {
		return apperror.Newf("scanner_generation_failed", "%s lockfile generation failed: %w", item.Label, err)
	}
	if code != 0 {
		// Composer maps TransportException to exit 100. Keep its policy and TLS
		// protections intact and explain the transport failure without raw output.
		if tool == "composer" && code == 100 {
			return apperror.Newf("scanner_generation_failed", "%s lockfile generation failed: %w", item.Label, composerTransportError(diagnostic))
		}
		return apperror.Newf("scanner_generation_exit", "%s lockfile generation exited with code %d. Check manifest constraints, runtime requirements, registry access, and package-manager policy.", item.Label, code)
	}

	info, err = root.Lstat(lockfile)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 32<<20 {
		return apperror.Newf("scanner_generation_invalid", "%s did not produce a valid lockfile; the scan was not recorded as clean.", item.Label)
	}
	f, err := root.Open(lockfile)
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, (32<<20)+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return err
	}
	var document struct {
		LockfileVersion int             `json:"lockfileVersion"`
		Packages        json.RawMessage `json:"packages"`
		Dependencies    json.RawMessage `json:"dependencies"`
	}
	valid := len(data) <= 32<<20 && json.Unmarshal(data, &document) == nil
	if tool == "npm" {
		graph := len(document.Packages) > 0 && document.Packages[0] == '{' || len(document.Dependencies) > 0 && document.Dependencies[0] == '{'
		valid = valid && document.LockfileVersion > 0 && graph
	} else {
		valid = valid && len(document.Packages) > 0 && document.Packages[0] == '['
	}
	if !valid {
		return apperror.Newf("scanner_generation_invalid", "%s did not produce a valid lockfile; the scan was not recorded as clean.", item.Label)
	}

	succeeded = true
	return nil
}
