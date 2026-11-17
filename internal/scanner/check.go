package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type CheckResult struct {
	Status   string `json:"status"`
	Platform string `json:"platform"`
	Path     string `json:"path,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// Check runs an informational command with the same executable resolution and
// OS account used by assessments. It does not enter a project directory.
func Check(ctx context.Context, name string) (CheckResult, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd, err := newScannerProbe(ctx, name)
	result := CheckResult{Platform: scannerPlatform()}
	if err == nil {
		if filepath.IsAbs(cmd.Path) {
			result.Path = cmd.Path
		}
		err = prepareCommand(os.TempDir(), cmd, "")
	}
	if err != nil {
		return checkFailure(result, err), nil
	}
	cmd.Env = append(cmd.Env, "NO_UPDATE_NOTIFIER=1", "NPM_CONFIG_UPDATE_NOTIFIER=false", "COMPOSER_DISABLE_NETWORK=1")
	var stdout, stderr cappedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if ctx.Err() != nil {
		result.Status = "timeout"
		return result, nil
	}
	if err == nil {
		result.Status = "ready"
		return result, nil
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return checkFailure(result, err), nil
	}
	output := strings.ToLower(stderr.String())
	if name == "govulncheck" && exit.ExitCode() > 0 &&
		(strings.Contains(output, "usage:") || strings.Contains(strings.ToLower(stdout.String()), "usage:")) {
		result.Status = "ready" // Some govulncheck versions return a nonzero help status.
		return result, nil
	}
	if strings.Contains(output, "permission denied") || strings.Contains(output, "access is denied") ||
		strings.Contains(output, "operation not permitted") {
		result.Status = "permission"
		return result, nil
	}
	result.Status = "failed"
	result.Detail = err.Error()
	return result, nil
}

func newScannerProbe(ctx context.Context, name string) (*exec.Cmd, error) {
	switch name {
	case "govulncheck":
		return exec.CommandContext(ctx, "govulncheck", "-help"), nil
	case "npm":
		return newNPMCommand(ctx, "--version")
	case "composer":
		return newComposerCommand(ctx, "--no-plugins", "--no-scripts", "--no-interaction", "--version")
	case "pip-audit":
		return exec.CommandContext(ctx, "pip-audit", "--version"), nil
	case "trivy":
		return exec.CommandContext(ctx, "trivy", "--version"), nil
	case "snyk":
		return exec.CommandContext(ctx, "snyk", "--version"), nil
	default:
		return nil, fmt.Errorf("scanner availability check is unsupported for %q", name)
	}
}

func checkFailure(result CheckResult, err error) CheckResult {
	result.Detail = err.Error()
	switch {
	case errors.Is(err, os.ErrPermission) || blockedByPolicy(err):
		result.Status = "permission"
	case errors.Is(err, exec.ErrDot):
		result.Status = "path"
	case errors.Is(err, exec.ErrNotFound):
		result.Status = "missing"
		var lookup *exec.Error
		if errors.As(err, &lookup) {
			if path := deniedExecutableOnPath(lookup.Name); path != "" {
				result.Status, result.Path, result.Detail = "permission", path, ""
			}
		}
	default:
		result.Status = "failed"
	}
	return result
}

func scannerPlatform() string {
	if runtime.GOOS != "linux" {
		return runtime.GOOS
	}
	data, err := os.ReadFile("/etc/os-release")
	if errors.Is(err, os.ErrNotExist) {
		data, _ = os.ReadFile("/usr/lib/os-release")
	}
	return linuxScannerPlatform(string(data))
}

func linuxScannerPlatform(release string) string {
	var id, like string
	for _, line := range strings.Split(release, "\n") {
		key, value, _ := strings.Cut(line, "=")
		value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), "\"'")
		switch key {
		case "ID":
			id = value
		case "ID_LIKE":
			like = value
		}
	}
	for _, name := range append([]string{id}, strings.Fields(like)...) {
		switch name {
		case "debian", "ubuntu":
			return "debian"
		case "fedora", "rhel", "centos", "rocky", "almalinux":
			return "fedora"
		case "arch", "manjaro":
			return "arch"
		case "alpine":
			return "alpine"
		}
	}
	return "linux"
}
