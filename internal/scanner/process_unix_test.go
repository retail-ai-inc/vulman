//go:build !windows

package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestScannerAvailabilityUsesLocalPermissionsAndInformationalCommands(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for _, tc := range []struct {
		name, shell, want string
		mode              os.FileMode
	}{
		{"govulncheck", "[ \"$1\" = '-help' ] || exit 9\nprintf 'Usage:\\n' >&2\nexit 2", "ready", 0700},
		{"trivy", "[ \"$1\" = '--version' ]", "ready", 0700},
		{"snyk", "[ \"$#\" -eq 1 ] && [ \"$1\" = '--version' ]", "ready", 0700},
		{"npm", "exit 0", "permission", 0600},
		{"composer", "", "missing", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name)
			if tc.mode != 0 {
				if err := os.WriteFile(path, []byte("#!/bin/sh\n"+tc.shell+"\n"), tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			result, err := Check(context.Background(), tc.name)
			if err != nil || result.Status != tc.want || tc.mode != 0 && result.Path != path {
				t.Fatalf("check = %+v, %v, want %s", result, err, tc.want)
			}
		})
	}
}

func TestDeniedExecutableOnPathOnlyLooksUpScannerNames(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "bin")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "trivy"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "trivy")
	if err := os.Symlink("../trivy", linked); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if got := deniedExecutableOnPath("trivy"); got != linked {
		t.Fatalf("permission check returned %q, want %q", got, linked)
	}
	if got := deniedExecutableOnPath("../trivy"); got != "" {
		t.Fatalf("permission check accepted path components: %q", got)
	}
}

func TestCancellationKillsScannerChildProcesses(t *testing.T) {
	dir := t.TempDir()
	ready, escaped := filepath.Join(dir, "ready"), filepath.Join(dir, "escaped")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		cmd := exec.CommandContext(ctx, "sh", "-c", `(sleep 1; printf leaked > escaped) & printf ready > ready; wait`)
		_, _, err := run(ctx, dir, cmd, "")
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scanner process did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("scanner cancellation blocked on descendants")
	}
	time.Sleep(1100 * time.Millisecond)
	if _, err := os.Stat(escaped); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scanner child survived cancellation: %v", err)
	}
}

func TestScannerRejectsExecutableFoundInCurrentDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink("/bin/sh", filepath.Join(dir, "npm")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	t.Setenv("PATH", ".")
	t.Setenv("GODEBUG", "execerrdot=0")
	ctx := context.Background()
	cmd, err := newScannerCommand(ctx, "npm")
	if err != nil || cmd.Err != nil {
		t.Fatalf("prepare relative-path test command: %v", err)
	}
	if _, _, err := run(ctx, dir, cmd, ""); err == nil {
		t.Fatal("scanner executed a program from a relative PATH entry")
	}
}
