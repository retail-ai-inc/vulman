package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestWindowsPackageManagersBypassBatchShims(t *testing.T) {
	installDir := filepath.Join(t.TempDir(), "tools & runtimes")
	t.Setenv("PATH", installDir)
	t.Setenv("PATHEXT", ".EXE;.COM;.BAT;.CMD")
	t.Setenv("NoDefaultCurrentDirectoryInExePath", "1")
	for _, tc := range []struct {
		name, shim, interpreter, script string
		args                            []string
	}{
		{"npm", "npm.cmd", "node.exe", filepath.Join("node_modules", "npm", "bin", "npm-cli.js"), []string{"audit", "--json", "--ignore-scripts"}},
		{"composer", "composer.bat", "php.exe", "composer.phar", []string{"--no-plugins", "--no-scripts", "--no-interaction", "audit", "--locked", "--format=json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, file := range []string{tc.shim, tc.interpreter, tc.script} {
				path := filepath.Join(installDir, file)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cmd, err := newScannerCommand(context.Background(), tc.name)
			if err != nil {
				t.Fatal(err)
			}
			wantPath := filepath.Join(installDir, tc.interpreter)
			wantArgs := append([]string{wantPath, filepath.Join(installDir, tc.script)}, tc.args...)
			if cmd.Err != nil || cmd.Path != wantPath || !slices.Equal(cmd.Args, wantArgs) {
				t.Fatalf("expected direct interpreter invocation, got %q %q, error %v", cmd.Path, cmd.Args, cmd.Err)
			}
			probe, err := newScannerProbe(context.Background(), tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if probe.Err != nil || probe.Path != wantPath || len(probe.Args) < 3 || probe.Args[1] != wantArgs[1] || probe.Args[len(probe.Args)-1] != "--version" {
				t.Fatalf("expected direct interpreter version check, got %q %q, error %v", probe.Path, probe.Args, probe.Err)
			}
		})
	}
}

func TestWindowsRunnerRejectsBatchExecutable(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "scanner.cmd")
	cmd := &exec.Cmd{Path: path, Args: []string{path}}
	if _, _, err := run(ctx, t.TempDir(), cmd, ""); err == nil || err.Error() != "scanner requires a Windows executable" {
		t.Fatalf("expected batch script rejection before launch, got %v", err)
	}
}
