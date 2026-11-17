package testutil

import (
	"os"
	"testing"
)

// WriteShellFixture creates an owner-only executable in a test directory.
func WriteShellFixture(t *testing.T, dir, name, script string) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := file.WriteString("#!/bin/sh\n" + script + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Chmod(0o500); err != nil {
		t.Fatal(err)
	}
}
