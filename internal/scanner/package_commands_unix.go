//go:build !windows

package scanner

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func newNPMCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	// #nosec G204 -- Only fixed audit, lockfile-generation, and version arguments are passed by the scanner package.
	return exec.CommandContext(ctx, "npm", args...), nil
}

func newComposerCommand(ctx context.Context, args ...string) (*exec.Cmd, error) {
	// #nosec G204 -- Only fixed audit, lockfile-generation, and version arguments are passed by the scanner package.
	return exec.CommandContext(ctx, "composer", args...), nil
}

func blockedByPolicy(error) bool { return false }

// LookPath can report ErrNotFound when the named file exists but lacks execute access.
func deniedExecutableOnPath(name string) string {
	if !Supported(name) {
		return ""
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if !filepath.IsAbs(dir) {
			continue
		}
		// Like exec.LookPath, follow symlinks for installed tools.
		info, err := fs.Stat(os.DirFS(dir), name)
		path := filepath.Join(dir, name)
		if err == nil && info.Mode().IsRegular() && errors.Is(unix.Access(path, unix.X_OK), os.ErrPermission) {
			return path
		}
	}
	return ""
}
