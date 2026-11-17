package scanner

import (
	"context"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

func TestScannerReports(t *testing.T) {
	cases := []struct {
		name, report, id string
		count            int
	}{
		{"npm", `{"vulnerabilities":{"demo":{"name":"demo","severity":"high","range":"<1.2.3","via":[{"source":123,"title":"Vulnerable package","severity":"high","url":"https://example.com"}],"fixAvailable":{"version":"1.2.3"}}}}`, "NPM-123", 1},
		{"npm", `{"vulnerabilities":{"indirect":{"severity":"moderate","range":"*","via":["demo"]}}}`, "NPM-DEPENDENCY-indirect", 1},
		{"npm", `{"vulnerabilities":{}}`, "", 0},
		{"composer", `{"advisories":{"vendor/package":[{"advisoryId":"PKSA-1","cve":"CVE-2024-0001","title":"Issue","severity":"high","affectedVersions":"<1.2"}]}}`, "CVE-2024-0001", 1},
		{"composer", `{"advisories":[]}`, "", 0},
		{"pip-audit", `{"dependencies":[{"name":"demo","version":"1.0","vulns":[]}],"fixes":[]}`, "", 0},
		{"pip-audit", `[{"name":"demo","version":"1.0","vulns":[{"id":"PYSEC-2024-1","fix_versions":["1.1"]}]}]`, "PYSEC-2024-1", 1},
		{"trivy", `{"SchemaVersion":2,"Results":[{"Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"openssl","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"CRITICAL"}]}]}`, "CVE-2024-0001", 1},
		{"snyk", `{"ok":false,"vulnerabilities":[{"id":"SNYK-1","packageName":"demo","severity":"high","identifiers":{"CVE":["CVE-2024-0001"]}}]}`, "CVE-2024-0001", 1},
		{"govulncheck", `{"config":{"scanner_name":"govulncheck"}}` + "\n" + `{"osv":{"id":"GO-2024-1","summary":"Issue","aliases":["CVE-2024-0001"]}}` + "\n" + `{"finding":{"osv":"GO-2024-1","fixed_version":"v1.2.3","trace":[{"module":"example.com/demo","version":"v1.0.0"}]}}`, "CVE-2024-0001", 1},
		{"govulncheck", `{"config":{"scanner_name":"govulncheck"}}` + "\n" + `{"osv":{"id":"GO-2024-1","summary":"Unused advisory"}}`, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name+tc.id, func(t *testing.T) {
			out, err := Parse(tc.name, []byte(tc.report))
			if err != nil {
				t.Fatal(err)
			}
			if len(out) != tc.count || (tc.count > 0 && out[0].ID != tc.id) {
				t.Fatalf("unexpected results: %+v", out)
			}
		})
	}
}

func TestMalformedReportsAreNotCleanScans(t *testing.T) {
	for _, name := range scannerNames {
		if _, err := Parse(name, []byte(`{"error":"failed"}`)); err == nil {
			t.Errorf("%s accepted an error as a clean scan", name)
		}
	}
	for _, report := range []string{`[{`, `[]`} {
		if _, err := Parse("snyk", []byte(report)); err == nil {
			t.Errorf("Snyk accepted %q as a clean scan", report)
		}
	}
	if _, err := Parse("pip-audit", []byte(`{"dependencies":[{"name":"demo","skip_reason":"not on PyPI"}]}`)); err == nil {
		t.Error("pip-audit accepted an unaudited dependency as a clean scan")
	}
}

func TestScannerCommandRejectsUnsupportedNames(t *testing.T) {
	if cmd, err := newScannerCommand(context.Background(), "cmd.exe"); err == nil || cmd != nil {
		t.Fatal("unsupported scanner produced a command")
	}
}

func TestCloneCommandKeepsRepositoryAsPositionalArgument(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GIT_OBJECT_DIRECTORY", t.TempDir())
	for _, repo := range []string{"--upload-pack=malicious", "ext::malicious", "https://user:password@github.com/owner/repo", "https://gitlab.com/owner/repo"} {
		if cmd, err := newCloneCommand(ctx, repo, "checkout", "fixture-token"); err == nil || cmd != nil {
			t.Fatalf("invalid repository produced a command: %q", repo)
		}
	}
	repo := "https://github.com/owner/repo.git?tab=readme#overview"
	cmd, err := newCloneCommand(ctx, repo, "checkout with spaces", "")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(cmd.Args[len(cmd.Args)-3:], []string{"--", "https://github.com/owner/repo.git", "checkout with spaces"}) {
		t.Fatalf("unexpected clone arguments: %q", cmd.Args)
	}
	for _, entry := range cmd.Env {
		if strings.HasPrefix(entry, "GIT_OBJECT_DIRECTORY=") {
			t.Fatal("clone inherited an external object directory")
		}
	}
}

func TestAuthenticatedCloneScopesTokenToGitHubChildProcess(t *testing.T) {
	const token = "fixture-token"
	t.Setenv("GITHUB_TOKEN", token)
	for _, key := range []string{"GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_SSL_NO_VERIFY", "GIT_CONFIG_COUNT"} {
		t.Setenv(key, "1")
	}
	cmd, err := newCloneCommand(context.Background(), "https://github.com/owner/repo", "checkout", token)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
	if strings.Contains(strings.Join(cmd.Args, " "), token) || strings.Contains(strings.Join(cmd.Args, " "), encoded) {
		t.Fatal("credentials were passed as command-line arguments")
	}
	if !slices.Contains(cmd.Args, "--config-env=http.https://github.com/.extraHeader="+githubAuthHeaderEnv) ||
		!slices.Contains(cmd.Args, "http.https://github.com/.followRedirects=false") ||
		!slices.Contains(cmd.Env, githubAuthHeaderEnv+"=Authorization: Basic "+encoded) {
		t.Fatal("authentication is not scoped to the GitHub clone")
	}
	for _, entry := range cmd.Env {
		key, _, _ := strings.Cut(entry, "=")
		switch key {
		case "GITHUB_TOKEN", "GIT_TRACE_CURL", "GIT_CURL_VERBOSE", "GIT_SSL_NO_VERIFY", "GIT_CONFIG_COUNT":
			t.Errorf("clone inherited %s", key)
		}
	}
}
