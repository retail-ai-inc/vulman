package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/testutil"
)

func TestComposerTransportDiagnosticsAreSpecificAndNeverExposeOutput(t *testing.T) {
	for _, tc := range []struct {
		output string
		code   string
	}{
		{"Network disabled by COMPOSER_DISABLE_NETWORK", "composer_network_disabled"},
		{"curl error 5 while downloading: Could not resolve proxy", "composer_network_proxy"},
		{"curl error 6 while downloading: Could not resolve host", "composer_network_dns"},
		{"curl error 60 while downloading: SSL certificate problem", "composer_network_certificate"},
		{"curl error 35 while downloading: SSL connect error", "composer_network_tls"},
		{"The file could not be downloaded (HTTP/2 429): Too Many Requests", "composer_network_rate_limit"},
		{"The file could not be downloaded (HTTP/2 401): Unauthorized", "composer_network_access"},
		{"The file could not be downloaded (HTTP/1.1 403): Forbidden", "composer_network_access"},
		{"curl error 28 while downloading: Operation timed out", "composer_network_timeout"},
		{"curl error 7 while downloading: Failed to connect", "composer_network_connection"},
		{"The file could not be downloaded (HTTP/2 503)", "composer_network_failure"},
		{"", "composer_network_failure"},
	} {
		t.Run(tc.code+tc.output, func(t *testing.T) {
			marker := model.NewID()
			output := tc.output + " https://fixture:" + marker + "@private.invalid/packages.json?credential=" + marker
			message := apperror.Public(composerTransportError([]byte(output)))
			data, err := json.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			if message.Code != tc.code || strings.Contains(string(data), marker) || strings.Contains(string(data), "private.invalid") {
				t.Fatalf("missing safe transport classification: %+v", message)
			}
		})
	}
}

func TestComposerExit100SurfacesSafeNetworkCauseAndKeepsGenerationFailed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir, bin := t.TempDir(), t.TempDir()
	writeProjectFiles(t, dir, "composer.json")
	t.Setenv("PATH", bin)
	marker := model.NewID()
	t.Setenv("VULMAN_COMPOSER_DIAGNOSTIC", "curl error 60 while downloading https://fixture:"+marker+"@private.invalid/packages.json: SSL certificate problem")
	testutil.WriteShellFixture(t, bin, "composer", `printf '%s' "$VULMAN_COMPOSER_DIAGNOSTIC" >&2
printf '%s' '{"packages":[]}' > composer.lock
exit 100`)
	project := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{
		"local": {Mode: "custom", Tools: []string{"composer"}, GenerateLockfiles: true},
	}}
	var failed, cleaned bool
	report := ScanWithReport(context.Background(), project, model.Settings{Scanners: map[string]bool{"composer": true}}, "", func(event ScanEvent) {
		failed = failed || event.Phase == "scanner_lockfile_failed" && event.Job != nil && event.Job.Status == "failed"
		cleaned = cleaned || event.Phase == "scanner_cleanup_completed"
	})
	if len(report.Problems) != 1 || len(report.Completed) != 0 || len(report.Findings) != 0 || !failed || !cleaned {
		t.Fatalf("failed transport produced scan coverage or lost cleanup: %+v", report)
	}
	message := apperror.Public(report.Problems[0])
	data, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "composer_network_certificate") || strings.Contains(string(data), marker) || strings.Contains(string(data), "private.invalid") {
		t.Fatalf("transport cause was hidden or raw diagnostics leaked: %s", data)
	}
	if _, err := os.Stat(filepath.Join(dir, "composer.lock")); !os.IsNotExist(err) {
		t.Fatal("failed generation changed the original repository")
	}
}

func TestComposerDependencyFailureIsNotMisclassifiedAsNetworkFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixtures")
	}
	dir, bin := t.TempDir(), t.TempDir()
	writeProjectFiles(t, dir, "composer.json")
	t.Setenv("PATH", bin)
	testutil.WriteShellFixture(t, bin, "composer", `printf 'dependency resolution failed; advisory text mentions curl error 60 ' >&2
exit 2`)
	project := model.Project{LocalPath: dir, ScannerProfiles: map[string]model.ScannerProfile{
		"local": {Mode: "custom", Tools: []string{"composer"}, GenerateLockfiles: true},
	}}
	report := ScanWithReport(context.Background(), project, model.Settings{Scanners: map[string]bool{"composer": true}}, "", nil)
	if len(report.Problems) != 1 || !strings.Contains(apperror.Public(report.Problems[0]).English(), "exited with code 2") {
		t.Fatalf("dependency resolution was not kept distinct from transport failures: %+v", report)
	}
}
