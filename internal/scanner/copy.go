package scanner

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"vulman/internal/apperror"
	"vulman/internal/workflow"
)

func excludedScannerDirectory(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".venv", "venv", "__pycache__":
		return true
	}
	return false
}

type scanCopyReader struct {
	ctx context.Context
	io.Reader
}

func (r scanCopyReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// Copy regular files, never symlinks or hard links to the user's files. Rooted
// filesystem operations keep all writes inside private, disposable storage.
func copyRepository(ctx context.Context, source string, scratch *scanScratch) (string, error) {
	from, err := os.OpenRoot(source)
	if err != nil {
		return "", err
	}
	defer func() { _ = from.Close() }()

	absolute, err := filepath.Abs(source)
	if err != nil {
		return "", err
	}
	absolute, err = filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	workspace, err := filepath.EvalSymlinks(scratch.path())
	if err != nil {
		return "", err
	}
	if relative, err := filepath.Rel(absolute, workspace); err == nil && filepath.IsLocal(relative) {
		return "", apperror.New("scanner_copy_nested", "Choose a repository folder that does not contain Vulman's temporary scan directory.")
	}
	name := filepath.Join(scratch.name, "repository-copy")
	if err := scratch.root.Mkdir(name, 0o700); err != nil {
		return "", err
	}
	to, err := scratch.root.OpenRoot(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = to.Close() }()

	remaining, entries := int64(512<<20), 0
	err = fs.WalkDir(from.FS(), ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := workflow.Wait(ctx); err != nil {
			return err
		}
		entries++
		if entries > 100000 {
			return apperror.New("scanner_copy_limit", "The temporary repository copy exceeds 100,000 entries or 512 MiB. Create lockfiles in the repository yourself or choose a smaller folder.")
		}
		if name == "." {
			return nil
		}
		if entry.IsDir() {
			if excludedScannerDirectory(entry.Name()) {
				return fs.SkipDir
			}
			return to.Mkdir(name, 0o700)
		}
		if !entry.Type().IsRegular() {
			return nil
		}

		input, err := from.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = input.Close() }()
		info, err := input.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return apperror.New("scanner_copy_changed", "A repository file changed while preparing its temporary copy. Retry the scan.")
		}
		output, err := to.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(output, io.LimitReader(scanCopyReader{ctx, input}, remaining+1))
		if err := errors.Join(copyErr, output.Close()); err != nil {
			return err
		}
		remaining -= n
		if remaining < 0 {
			return apperror.New("scanner_copy_limit", "The temporary repository copy exceeds 100,000 entries or 512 MiB. Create lockfiles in the repository yourself or choose a smaller folder.")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return to.Name(), nil
}
