package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vulman/internal/testutil"
)

func TestRunScannerReportsStatusAndExitCode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	t.Setenv("SNYK_TOKEN", "")
	for _, tc := range []struct {
		name, tools, script, status string
		exit, findings              int
	}{
		{"clean", "trivy", `echo '{"SchemaVersion":2}'`, "complete", 0, 0},
		{"findings", "trivy", `echo '{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-demo","PkgName":"demo","Severity":"HIGH"}]}]}'`, "complete", 1, 1},
		{"partial", "trivy,snyk", `echo '{"SchemaVersion":2}'`, "partial", 2, 0},
		{"failed", "trivy", "exit 2", "failed", 2, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir)
			testutil.WriteShellFixture(t, dir, "trivy", tc.script)
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"--scanners", tc.tools, "--dir", dir}, &stdout, &stderr)
			if code != tc.exit || stderr.Len() != 0 {
				t.Fatalf("exit %d, stderr=%q, stdout=%q", code, &stderr, &stdout)
			}
			var report scanReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != tc.status || len(report.Findings) != tc.findings || len(report.Scanners) == 0 || report.Scanners[0].Name != "trivy" {
				t.Fatalf("unexpected report: %+v", report)
			}
			if tc.status == "complete" && (report.Scanners[0].Findings == nil || *report.Scanners[0].Findings != tc.findings) {
				t.Fatalf("missing scanner finding count: %+v", report.Scanners[0])
			}
		})
	}
}

func TestRunLockfileGenerationIsOptInAndLabelsJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir, bin := t.TempDir(), t.TempDir()
	t.Setenv("PATH", bin)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	testutil.WriteShellFixture(t, bin, "npm", `case "$1" in
install) printf '%s' '{"lockfileVersion":3,"packages":{}}' > package-lock.json;;
audit) printf '%s' '{"vulnerabilities":{}}';;
*) exit 9;;
esac`)
	for _, generate := range []bool{false, true} {
		args := []string{"--scanners", "npm", "--dir", dir}
		if generate {
			args = append(args, "--generate-lockfiles")
		}
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), args, &stdout, &stderr)
		var report scanReport
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatal(err)
		}
		if generate {
			if code != 0 || report.Status != "complete" || len(report.Scanners) != 1 || !report.Scanners[0].GeneratedLockfile {
				t.Fatalf("generated resolution was not labeled in CLI output: %s, %s", &stdout, &stderr)
			}
		} else if code != 2 || report.Status != "failed" {
			t.Fatalf("default CLI generated a missing lockfile: %s", &stdout)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); !os.IsNotExist(err) {
		t.Fatal("CLI lockfile generation changed the original repository")
	}
}

func TestRunPipAuditUsesProjectManifests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	testutil.WriteShellFixture(t, bin, "pip-audit", `
case "$*" in
  *"--disable-pip --no-deps --requirement requirements.txt")
    [ -f requirements.txt ] && [ ! -e pylock.toml ] || exit 2 ;;
  *"--locked .")
    [ -f pylock.toml ] && [ -f pylock.dev.toml ] && [ ! -e requirements.txt ] || exit 2 ;;
  *) exit 2 ;;
esac
[ ! -e source.py ] || exit 2
printf '%s' '{"dependencies":[{"name":"demo","version":"1.0","vulns":[{"id":"PYSEC-2024-1","aliases":["CVE-2024-0001"],"description":"Example advisory","fix_versions":["1.0.1","1.1"]}]}],"fixes":[]}'
exit 1`)
	for _, tc := range []struct {
		name, requirements string
		locked             bool
		exit               int
	}{
		{name: "requirements", requirements: "demo==1.0\n", exit: 1},
		{name: "lockfiles", requirements: "demo>=1.0\n", locked: true, exit: 1},
		{name: "missing input", exit: 2},
		{name: "nested requirements", requirements: "-r another.txt\n", exit: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string]string{"source.py": "# repository file"}
			if tc.requirements != "" {
				files["requirements.txt"] = tc.requirements
			}
			if tc.locked {
				files["pylock.toml"] = "lock-version = '1.0'\n"
				files["pylock.dev.toml"] = "lock-version = '1.0'\n"
			}
			for name, content := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stdout, stderr bytes.Buffer
			code := run(context.Background(), []string{"--scanners", "pip-audit", "--dir", dir}, &stdout, &stderr)
			if code != tc.exit || stderr.Len() > 0 {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, &stdout, &stderr)
			}
			var report scanReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if code == 2 {
				if report.Status != "failed" || len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "requirements.txt") {
					t.Fatalf("expected a manifest warning: %+v", report)
				}
				return
			}
			if report.Status != "complete" || len(report.Findings) != 1 || len(report.Scanners) != 1 ||
				report.Scanners[0].Name != "pip-audit" || report.Scanners[0].Findings == nil || *report.Scanners[0].Findings != 1 {
				t.Fatalf("unexpected scan report: %+v", report)
			}
			item := report.Findings[0]
			if item.ID != "CVE-2024-0001" || item.Version != "1.0" || item.Severity != "UNKNOWN" || item.Description != "Example advisory" ||
				strings.Join(item.FixedVersions, ",") != "1.0.1,1.1" || strings.Join(item.Aliases, ",") != "PYSEC-2024-1" {
				t.Fatalf("unexpected finding: %+v", item)
			}
		})
	}
}

func TestRunScansPrivateGitHubRepositoryWithoutExposingTokenToScanner(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("scanner fixtures use shell executables")
	}
	dir := t.TempDir()
	const token = "fixture-private-read-token"
	t.Setenv("PATH", dir)
	t.Setenv("GITHUB_TOKEN", token)
	t.Setenv("VULMAN_GITHUB_AUTH_HEADER", "inherited value")
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	for name, script := range map[string]string{
		"git": `for arg in "$@"; do
  case "$arg" in https://*) repository="$arg";; esac
  destination="$arg"
done
[ -z "${GITHUB_TOKEN+x}" ] || exit 2
case "$repository" in
  */public.git) [ -z "${VULMAN_GITHUB_AUTH_HEADER+x}" ] || exit 2;;
  */private.git)
    if [ -z "${VULMAN_GITHUB_AUTH_HEADER+x}" ]; then
      /bin/mkdir -p "$destination"
      exit 128
    fi
    [ "$VULMAN_GITHUB_AUTH_HEADER" = "Authorization: Basic ` + encoded + `" ] || exit 2
    [ ! -e "$destination" ] || exit 2;;
  *) exit 2;;
esac
/bin/mkdir -p "$destination"`,
		"trivy": `[ -z "${GITHUB_TOKEN+x}${VULMAN_GITHUB_AUTH_HEADER+x}" ] || exit 2
printf '%s' '{"SchemaVersion":2}'`,
	} {
		testutil.WriteShellFixture(t, dir, name, script)
	}
	for _, repository := range []string{"public", "private"} {
		var stdout, stderr bytes.Buffer
		code := run(context.Background(), []string{"--scanners", "trivy", "--repo", "https://github.com/owner/" + repository + ".git"}, &stdout, &stderr)
		if code != 0 || !strings.Contains(stdout.String(), `"status":"complete"`) || stderr.Len() != 0 {
			t.Fatalf("%s scan failed with exit %d, stdout=%q, stderr=%q", repository, code, &stdout, &stderr)
		}
	}
	t.Setenv("GITHUB_TOKEN", "")
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"--scanners", "trivy", "--repo", "https://github.com/owner/private.git"}, &stdout, &stderr)
	if code != 2 || !strings.Contains(stdout.String(), "configure a GitHub token with read access") {
		t.Fatalf("missing token error not reported, exit %d, stdout=%q, stderr=%q", code, &stdout, &stderr)
	}
}

func TestRunRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"--scanners", "unknown"},
		{"--scanners", "trivy", "--dir", ".", "--repo", "https://github.com/owner/repo"},
		{"--scanners", "trivy", "--repo", "https://gitlab.com/owner/repo"},
		{"--scanners", "trivy", "--repo", "file:///tmp/repo"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("arguments %q returned %d, stdout=%q, stderr=%q", args, code, &stdout, &stderr)
		}
	}
}
