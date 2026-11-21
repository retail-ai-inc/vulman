package main

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// Finder launches do not load shell profiles. Use the same PATH for scanner
// lookups and their child processes, including npm's Node and Composer's PHP.
func configureScannerPath() error {
	if runtime.GOOS != "darwin" {
		return nil
	}

	path := filepath.SplitList(os.Getenv("PATH"))
	dirs := []string{"/opt/homebrew/bin", "/usr/local/bin", "/usr/local/go/bin"}

	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		dirs = append(dirs, filepath.Join(home, "go", "bin"))
	}

	for _, dir := range dirs {
		if !slices.Contains(path, dir) {
			path = append(path, dir)
		}
	}

	return os.Setenv("PATH", strings.Join(path, string(os.PathListSeparator)))
}
