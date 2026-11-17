package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func newNPMCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	return newWindowsPackageCommand(ctx, "npm", "node.exe", filepath.Join("node_modules", "npm", "bin", "npm-cli.js"), args...)
}

func newComposerCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	return newWindowsPackageCommand(ctx, "composer", "php.exe", "composer.phar", args...)
}

// Resolve standard batch shims without executing or parsing them. All names,
// entry points and audit options come from the two fixed invocations above.
func newWindowsPackageCommand(ctx context.Context, name, runtimeName, entry string, args ...string) (*exec.Cmd, error) {
	program, err := absoluteLookPath(name)
	if err != nil {
		return nil, err
	}
	switch strings.ToLower(filepath.Ext(program)) {
	case ".exe":
		// Some package manager installations provide a native launcher.
	case ".cmd", ".bat":
		dir := filepath.Dir(program)
		script := filepath.Join(dir, entry)
		if !regularFile(script) {
			return nil, fmt.Errorf("%s requires %s next to its launcher", name, entry)
		}
		// The npm launcher prefers its own Node interpreter when available.
		if name == "npm" && regularFile(filepath.Join(dir, runtimeName)) {
			program = filepath.Join(dir, runtimeName)
		} else {
			program, err = absoluteLookPath(runtimeName)
			if err != nil {
				return nil, err
			}
		}
		args = append([]string{script}, args...)
	default:
		return nil, fmt.Errorf("unsupported %s launcher type: %s", name, filepath.Ext(program))
	}
	// #nosec G204 -- Absolute installed executable and, for a standard shim, its installed script with fixed arguments.
	return exec.CommandContext(ctx, program, args...), nil
}

func absoluteLookPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must resolve to an absolute path", name)
	}
	return path, nil
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func blockedByPolicy(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DISABLED_BY_POLICY) ||
		errors.Is(err, windows.ERROR_ELEVATION_REQUIRED) || errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}

func deniedExecutableOnPath(string) string { return "" }
