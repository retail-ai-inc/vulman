package scanner

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
)

// CleanScanScratch clears abandoned workspaces without touching running scans.
func CleanScanScratch(dataDir string) error {
	root, err := openScratchRoot(dataDir, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return errors.Join(cleanAbandonedScans(root), root.Close())
}

func openScratchRoot(dataDir string, create bool) (*os.Root, error) {
	temp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return nil, err
	}
	temp, err = filepath.EvalSymlinks(temp)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(temp, fmt.Sprintf("vulman-scans-%d", os.Getuid()))
	if dataDir != "" {
		dataDir, err = filepath.EvalSymlinks(dataDir)
		if err != nil {
			return nil, err
		}
		if relative, err := filepath.Rel(dataDir, path); err == nil && filepath.IsLocal(relative) {
			return nil, apperror.New("scan_storage_location_invalid", "the temporary scan directory must be outside the Vulman data directory")
		}
	}
	if create {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, apperror.New("temporary_scan_storage_must_be_a_private_directory", "temporary scan storage must be a private directory")
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil && !os.SameFile(info, opened) {
		err = apperror.New("temporary_scan_storage_changed_while_opening_it", "temporary scan storage changed while opening it")
	}
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return root, nil
}

type scanScratch struct {
	root  *os.Root
	name  string
	lease *os.File
}

func newScanScratch(root *os.Root) (*scanScratch, error) {
	name := model.NewID()
	// Publish the directory only after taking its lease, so another instance
	// cannot mistake a scan that is starting for an abandoned scan.
	lease, err := root.OpenFile(name+".lease", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	locked, err := tryScratchLock(lease)
	if err == nil && !locked {
		err = apperror.New("temporary_scan_directory_is_already_in_use", "temporary scan directory is already in use")
	}
	if err == nil {
		err = root.Mkdir(name, 0o700)
	}
	if err != nil {
		return nil, errors.Join(err, lease.Close(), root.Remove(name+".lease"))
	}
	scratch := &scanScratch{root: root, name: name, lease: lease}
	if err := root.Mkdir(filepath.Join(name, "tmp"), 0o700); err != nil {
		return nil, errors.Join(err, scratch.remove())
	}
	return scratch, nil
}

func cleanAbandonedScans(root *os.Root) error {
	entries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return err
	}
	var problems error
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || len(name) != 24 {
			continue
		}
		if _, err := hex.DecodeString(name); err != nil {
			continue
		}
		lease, err := root.OpenFile(name+".lease", os.O_RDWR, 0)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			problems = errors.Join(problems, err)
			continue
		}
		locked, err := tryScratchLock(lease)
		if locked {
			scratch := scanScratch{root: root, name: name, lease: lease}
			problems = errors.Join(problems, scratch.remove())
		} else {
			problems = errors.Join(problems, err, lease.Close())
		}
	}
	return problems
}

func (s *scanScratch) remove() error {
	err := s.root.RemoveAll(s.name)
	if errors.Is(err, fs.ErrPermission) {
		// Some scanners create read-only cache directories. Change only directory
		// permissions within this scratch tree and never follow symbolic links.
		if walkErr := fs.WalkDir(s.root.FS(), s.name, func(path string, entry fs.DirEntry, err error) error {
			if err == nil && entry.IsDir() {
				return s.root.Chmod(path, 0o700)
			}
			return err
		}); walkErr == nil || errors.Is(walkErr, fs.ErrNotExist) {
			err = s.root.RemoveAll(s.name)
		}
	}
	closeErr := s.lease.Close()
	if err != nil {
		return errors.Join(err, closeErr) // Retain the lease file so cleanup can retry.
	}
	err = s.root.Remove(s.name + ".lease")
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	return errors.Join(err, closeErr)
}

func (s *scanScratch) path() string { return filepath.Join(s.root.Name(), s.name) }

func (s *scanScratch) configure(cmd *exec.Cmd) {
	dir := s.path()
	temp := filepath.Join(dir, "tmp")
	if cmd.Env == nil {
		cmd.Env = scannerEnvironment()
	}
	cmd.Env = slices.DeleteFunc(cmd.Env, func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		return strings.EqualFold(name, "npm_config_cache") || strings.EqualFold(name, "COMPOSER")
	})
	cmd.Env = append(cmd.Env,
		"TMPDIR="+temp, "TMP="+temp, "TEMP="+temp, "GOTMPDIR="+temp,
		"GOCACHE="+filepath.Join(dir, "go-build"), "GOMODCACHE="+filepath.Join(dir, "go-mod"), "GOCACHEPROG=",
		"npm_config_cache="+filepath.Join(dir, "npm"), "COMPOSER_CACHE_DIR="+filepath.Join(dir, "composer"),
		"COMPOSER=composer.json",
		"TRIVY_CACHE_DIR="+filepath.Join(dir, "trivy"), "SNYK_CACHE_PATH="+filepath.Join(dir, "snyk"),
	)
}
