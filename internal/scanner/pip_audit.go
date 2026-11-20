package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
)

var pipRequirementInclude = regexp.MustCompile(`(?m)^[ \t]*(?:-[rc]|--(?:requirement|constraint)(?:[\s=]|$))`)

func newPipAuditCommand(ctx context.Context, repository string, scratch *scanScratch) (*exec.Cmd, string, error) {
	source, err := os.OpenRoot(repository)
	if err != nil {
		return nil, "", err
	}
	defer func() { _ = source.Close() }()
	entries, err := fs.ReadDir(source.FS(), ".")
	if err != nil {
		return nil, "", err
	}
	var locks []string
	for _, entry := range entries {
		name := entry.Name()
		if name == "pylock.toml" || strings.HasPrefix(name, "pylock.") && strings.HasSuffix(name, ".toml") {
			locks = append(locks, name)
		}
	}
	inputs := locks
	mode := []string{"--locked", "."}
	if len(locks) == 0 {
		inputs = []string{"requirements.txt"}
		mode = []string{"--disable-pip", "--no-deps", "--requirement", "requirements.txt"}
	}

	stage := filepath.Join(scratch.name, "python")
	if err := scratch.root.Mkdir(stage, 0o700); err != nil {
		return nil, "", err
	}
	// Only give the auditor staged manifests. Its working directory and HTTP
	// cache are both inside the disposable scan workspace.
	for _, name := range inputs {
		data, err := readPipManifest(source, name)
		if name == "requirements.txt" && errors.Is(err, fs.ErrNotExist) {
			return nil, "", apperror.New("pip_audit_manifest_required", "add a pinned requirements.txt or a pylock.toml lockfile at the repository root")
		}
		if err != nil {
			return nil, "", err
		}
		if name == "requirements.txt" && pipRequirementInclude.Match(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))) {
			return nil, "", apperror.New("pip_audit_manifest_includes", "use a pinned requirements.txt that lists all dependencies directly, without requirements or constraints includes")
		}
		if err := scratch.root.WriteFile(filepath.Join(stage, name), data, 0o600); err != nil {
			return nil, "", err
		}
	}

	args := []string{"--format", "json", "--output", "-", "--strict", "--progress-spinner", "off",
		"--vulnerability-service", "pypi", "--aliases=on", "--desc=on",
		"--cache-dir", filepath.Join(scratch.path(), "pip-audit-cache")}
	args = append(args, mode...)
	// #nosec G204 -- Arguments are fixed options and an application-owned temporary cache path.
	cmd := exec.CommandContext(ctx, "pip-audit", args...)
	return cmd, filepath.Join(scratch.root.Name(), stage), nil
}

func readPipManifest(source *os.Root, name string) ([]byte, error) {
	info, err := source.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, apperror.Newf("regular_file_required", "%s must be a regular file", name)
	}
	file, err := source.Open(name)
	if err != nil {
		return nil, err
	}
	const maxManifestBytes = 16 << 20
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err := errors.Join(err, file.Close()); err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, apperror.Newf("file_too_large", "%s exceeds 16 MiB", name)
	}
	return data, nil
}

type pipAuditDependency struct {
	Name, Version string
	Skipped       string `json:"skip_reason"`
	Vulns         []struct {
		ID, Description string
		Aliases         []string
		FixedVersions   []string `json:"fix_versions"`
	}
}

func parsePipAudit(data []byte) ([]model.Finding, error) {
	var report struct {
		Dependencies []pipAuditDependency
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, apperror.New("pip_audit_report_missing", "no audit report was produced. Check the pip-audit version, network access, and whether the manifest pins all dependency versions")
	}
	if data[0] == '[' {
		if err := json.Unmarshal(data, &report.Dependencies); err != nil {
			return nil, err
		}
	} else if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	if report.Dependencies == nil {
		return nil, apperror.New("the_pip_audit_report_has_no_dependencies_list", "the pip-audit report has no dependencies list")
	}

	out := []model.Finding{}
	for _, dep := range report.Dependencies {
		if dep.Skipped != "" || dep.Name == "" || dep.Version == "" || dep.Vulns == nil {
			return nil, apperror.New("the_pip_audit_report_contains_an_unaudited_dependency", "the pip-audit report contains an unaudited dependency")
		}
		for _, vuln := range dep.Vulns {
			if vuln.ID == "" {
				return nil, apperror.New("the_pip_audit_report_contains_a_vulnerability_without_an_id", "the pip-audit report contains a vulnerability without an ID")
			}
			id := vuln.ID
			for _, alias := range vuln.Aliases {
				if strings.HasPrefix(alias, "CVE-") && !strings.HasPrefix(id, "CVE-") {
					id = alias
					break
				}
			}
			ref := "https://osv.dev/vulnerability/" + url.PathEscape(vuln.ID)
			item := finding("pip-audit", id, dep.Name, dep.Version, "Python advisory "+vuln.ID, "UNKNOWN", "", ref)
			if id != vuln.ID {
				item.Aliases = append(item.Aliases, vuln.ID)
			}
			for _, alias := range vuln.Aliases {
				if alias != id {
					item.Aliases = append(item.Aliases, alias)
				}
			}
			if vuln.Description != "" {
				item.Description = vuln.Description
			}
			item.FixedVersions = append(item.FixedVersions, vuln.FixedVersions...)
			out = append(out, item)
		}
	}
	return out, nil
}
