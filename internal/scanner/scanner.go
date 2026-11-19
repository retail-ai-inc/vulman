package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"vulman/internal/model"
	"vulman/internal/workflow"
)

// cappedBuffer keeps subprocess output bounded without stopping pipe consumption.
type cappedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	room := (16 << 20) - b.Len()

	if room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		_, _ = b.Buffer.Write(p)
	}

	if n > room {
		b.exceeded = true
	}

	return n, nil
}

func scannerEnvironment() []string {
	return slices.DeleteFunc(os.Environ(), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		return strings.EqualFold(key, "GITHUB_TOKEN") || strings.EqualFold(key, githubAuthHeaderEnv)
	})
}

func prepareCommand(dir string, cmd *exec.Cmd, token string) error {
	if cmd.Err != nil {
		return cmd.Err
	}
	// Require a resolved executable before switching into the project directory.
	if !filepath.IsAbs(cmd.Path) {
		return fmt.Errorf("scanner executable must resolve to an absolute path")
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(cmd.Path), ".exe") {
		return fmt.Errorf("scanner requires a Windows executable")
	}

	configureProcess(cmd)
	cmd.WaitDelay = 2 * time.Second
	cmd.Dir = dir
	if cmd.Env == nil {
		cmd.Env = scannerEnvironment()
	}
	cmd.Env = append(cmd.Env, "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_ALLOW_PROTOCOL=https", "GIT_LFS_SKIP_SMUDGE=1")

	if token != "" {
		cmd.Env = append(cmd.Env, "SNYK_TOKEN="+token)
	}
	return nil
}

func run(ctx context.Context, dir string, cmd *exec.Cmd, token string) ([]byte, int, error) {
	if err := prepareCommand(dir, cmd, token); err != nil {
		return nil, -1, err
	}
	var output, stderr cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0

	if ctx.Err() != nil {
		return nil, -1, ctx.Err()
	}

	if output.exceeded {
		return nil, -1, fmt.Errorf("scanner output exceeded 16 MiB")
	}

	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else {
			return nil, -1, err
		}
	}

	return output.Bytes(), code, nil
}

type ScanEvent struct {
	Phase, Tool string
	Target      string
	Repository  string
	Found       int
	Err         error
}

func EnabledTools(scanners map[string]bool) []string {
	var tools []string
	for _, name := range scannerNames {
		if scanners[name] {
			tools = append(tools, name)
		}
	}
	return tools
}

func Scan(ctx context.Context, p model.Project, s model.Settings, dataDir string, report func(ScanEvent)) (findings []model.Finding, warnings []string) {
	findings = []model.Finding{}
	warnings = []string{}
	enabled := EnabledTools(s.Scanners)
	if len(enabled) == 0 {
		return findings, []string{"Code scanning enabled on project, but no scanner is enabled in settings."}
	}

	type scanTarget struct{ kind, location, key, repository string }
	var targets []scanTarget
	if p.LocalPath != "" {
		targets = append(targets, scanTarget{kind: "local", location: p.LocalPath, key: "local"})
	}
	for _, repository := range p.Repositories() {
		targets = append(targets, scanTarget{kind: "remote", location: repository, key: RemoteTargetKey(repository), repository: RepositoryLabel(repository)})
	}
	if len(targets) == 0 {
		return findings, []string{"Code scanning requires a local folder or repository URL."}
	}
	root, err := openScratchRoot(dataDir, true)
	if err != nil {
		return findings, []string{fmt.Sprintf("Could not create temporary scan storage: %v", err)}
	}
	defer func() {
		if err := root.Close(); err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not close temporary scan storage: %v", err))
		}
	}()
	if err := cleanAbandonedScans(root); err != nil {
		warnings = append(warnings, fmt.Sprintf("Could not remove abandoned scan files: %v", err))
	}

	for _, target := range targets {
		if err := workflow.Wait(ctx); err != nil {
			warnings = append(warnings, err.Error())
			break
		}
		items, problems := scanRepository(ctx, root, target.kind, target.location, enabled, s.Tokens, func(event ScanEvent) {
			event.Target = target.kind
			event.Repository = target.repository
			report(event)
		})
		for i := range items {
			// A package and advisory can occur independently in different checkouts.
			items[i].AssetID = "code:" + target.key + ":" + items[i].Component
			items[i].ScanTarget = target.kind
			items[i].ScanRepository = target.repository
		}
		findings = append(findings, items...)
		label := "Local folder"
		if target.kind == "remote" {
			label = "Remote repository"
			if target.repository != "" {
				label = target.repository
			}
		}
		for _, problem := range problems {
			warnings = append(warnings, label+": "+problem)
		}
	}
	return findings, warnings
}

// RemoteTargetKey identifies the configured URL in findings and assessment history.
func RemoteTargetKey(repository string) string {
	return fmt.Sprintf("remote:%x", sha256.Sum256([]byte(repository)))
}

func RepositoryLabel(repository string) string {
	parsed, err := url.Parse(repository)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return parsed.Host + parsed.EscapedPath()
}

func scanRepository(ctx context.Context, root *os.Root, kind, location string, enabled []string, tokens map[string]string, report func(ScanEvent)) (findings []model.Finding, warnings []string) {
	targetFailed := func(err error) ([]model.Finding, []string) {
		report(ScanEvent{Phase: "scanner_target_failed", Err: err})
		return nil, []string{err.Error()}
	}
	scratch, err := newScanScratch(root)
	if err != nil {
		return targetFailed(err)
	}
	defer func() {
		if err := scratch.remove(); err != nil {
			warnings = append(warnings, fmt.Sprintf("Could not remove temporary scan files: %v", err))
			report(ScanEvent{Phase: "scanner_cleanup_failed", Err: err})
			return
		}
		report(ScanEvent{Phase: "scanner_cleanup_completed"})
	}()
	dir := location
	if kind == "remote" {
		dir, err = cloneRepository(ctx, location, scratch, tokens["github"], report)
		if err != nil {
			return targetFailed(err)
		}
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return targetFailed(fmt.Errorf("repository folder is unavailable"))
	}

	for _, name := range enabled {
		if err := workflow.Wait(ctx); err != nil {
			warnings = append(warnings, err.Error())
			break
		}
		var token string
		if name == "snyk" {
			token = tokens["snyk"]
		}
		if name == "snyk" && token == "" {
			report(ScanEvent{Phase: "scanner_missing_token", Tool: name})
			warnings = append(warnings, "Snyk skipped: configure a Snyk token.")
			continue
		}

		items, err := scanTool(ctx, dir, scratch, name, token, func() {
			report(ScanEvent{Phase: "scanning", Tool: name})
		})
		if err != nil {
			phase := "scanner_failed"
			if ctx.Err() != nil {
				phase = "scanner_interrupted"
			}
			report(ScanEvent{Phase: phase, Tool: name, Err: err})
			warnings = append(warnings, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		findings = append(findings, items...)
		report(ScanEvent{Phase: "scanner_completed", Tool: name, Found: len(items)})
	}

	return findings, warnings
}

func cloneRepository(ctx context.Context, location string, scratch *scanScratch, token string, report func(ScanEvent)) (string, error) {
	cloneCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	temporaryDir := scratch.path()
	dir := filepath.Join(temporaryDir, "repository")
	cmd, err := newCloneCommand(cloneCtx, location, dir, "")
	if err != nil {
		return "", err
	}
	scratch.configure(cmd)
	report(ScanEvent{Phase: "clone", Tool: "Git"})
	_, code, err := run(cloneCtx, temporaryDir, cmd, "")
	if err == nil && code == 0 {
		return dir, nil
	}
	if err == nil && token != "" && workflow.Wait(cloneCtx) == nil {
		// A failed clone can leave files behind. Use a fresh destination for the retry.
		dir = filepath.Join(temporaryDir, "authenticated-repository")
		cmd, err := newCloneCommand(cloneCtx, location, dir, token)
		if err != nil {
			return "", err
		}
		scratch.configure(cmd)
		report(ScanEvent{Phase: "clone_auth", Tool: "Git"})
		_, code, err := run(cloneCtx, temporaryDir, cmd, "")
		if err == nil && code == 0 {
			return dir, nil
		}
		return "", fmt.Errorf("repository clone failed. Check HTTPS access and whether the GitHub token has read access to this repository")
	}
	return "", fmt.Errorf("repository clone failed. Check Git and HTTPS access. For private repositories, configure a GitHub token with read access")
}

func scanTool(ctx context.Context, dir string, scratch *scanScratch, name, token string, started func()) ([]model.Finding, error) {
	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	var err error
	if name == "pip-audit" {
		cmd, dir, err = newPipAuditCommand(scanCtx, dir, scratch)
	} else {
		cmd, err = newScannerCommand(scanCtx, name)
	}
	if err != nil {
		return nil, err
	}
	if cmd.Err != nil {
		return nil, cmd.Err
	}
	scratch.configure(cmd)
	started()
	data, code, err := run(scanCtx, dir, cmd, token)
	if err != nil {
		return nil, err
	}
	allowed := code == 0 || (name != "trivy" && code == 1) || (name == "govulncheck" && code == 3)
	if !allowed {
		return nil, fmt.Errorf("exit %d; no clean scan was recorded", code)
	}
	return Parse(name, data)
}

func finding(source, id, pkg, version, title, sev, fixed, ref string) model.Finding {
	sev = strings.ToUpper(sev)
	if sev == "MODERATE" {
		sev = "MEDIUM"
	}

	if model.Rank(sev) == 1 {
		sev = "UNKNOWN"
	}

	f := model.Finding{ID: id, AssetID: "code:" + pkg, Component: pkg, Version: version, Title: title, Description: title, Severity: sev, Sources: []string{source}, References: []string{}, FixedVersions: []string{}, Match: "scanner"}
	if fixed != "" {
		f.FixedVersions = append(f.FixedVersions, fixed)
	}

	if ref != "" {
		f.References = append(f.References, ref)
	}

	return f
}

func Parse(name string, data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
	switch name {
	case "pip-audit":
		return parsePipAudit(data)
	case "npm":
		var doc struct {
			Error           any `json:"error"`
			Vulnerabilities map[string]struct {
				Name, Severity, Range string
				Via                   []json.RawMessage
				FixAvailable          json.RawMessage `json:"fixAvailable"`
			} `json:"vulnerabilities"`
		}

		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}

		if doc.Error != nil || doc.Vulnerabilities == nil {
			return nil, fmt.Errorf("npm audit returned an error or unsupported report (requires npm 7+)")
		}

		for pkg, v := range doc.Vulnerabilities {
			before := len(out)
			for _, via := range v.Via {
				var a struct {
					Source                     any
					Title, URL, Severity, Name string
				}

				if json.Unmarshal(via, &a) != nil || a.Title == "" {
					continue
				}

				var fix struct{ Version string }
				_ = json.Unmarshal(v.FixAvailable, &fix)
				id := fmt.Sprint(a.Source)

				if id == "<nil>" {
					id = a.URL
				}

				out = append(out, finding("npm audit", "NPM-"+id, pkg, v.Range, a.Title, a.Severity, fix.Version, a.URL))
			}

			if before == len(out) {
				out = append(out, finding("npm audit", "NPM-DEPENDENCY-"+pkg, pkg, v.Range, "Vulnerable dependency reported by npm audit", v.Severity, "", ""))
			}
		}
	case "composer":
		var doc struct {
			Advisories json.RawMessage `json:"advisories"`
		}

		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}

		if len(doc.Advisories) == 0 || string(doc.Advisories) == "null" {
			return nil, fmt.Errorf("composer report has no advisories field")
		}

		if string(bytes.TrimSpace(doc.Advisories)) == "[]" {
			return out, nil
		}

		var advisories map[string][]struct {
			AdvisoryID                                   string `json:"advisoryId"`
			CVE, Title, Link, Severity, AffectedVersions string
		}

		if err := json.Unmarshal(doc.Advisories, &advisories); err != nil {
			return nil, err
		}

		for pkg, items := range advisories {
			for _, a := range items {
				id := a.CVE
				if id == "" {
					id = a.AdvisoryID
				}
				out = append(out, finding("composer audit", id, pkg, a.AffectedVersions, a.Title, a.Severity, "", a.Link))
			}
		}
	case "trivy":
		var doc struct {
			SchemaVersion int
			Results       []struct {
				Vulnerabilities []struct{ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title, Description, Severity, PrimaryURL string }
			}
		}

		if err := json.Unmarshal(data, &doc); err != nil {
			return nil, err
		}

		if doc.SchemaVersion == 0 {
			return nil, fmt.Errorf("unsupported Trivy report")
		}

		for _, r := range doc.Results {
			for _, v := range r.Vulnerabilities {
				f := finding("Trivy", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.Title, v.Severity, v.FixedVersion, v.PrimaryURL)
				f.Description = v.Description
				out = append(out, f)
			}
		}
	case "snyk":
		var docs []json.RawMessage
		data = bytes.TrimSpace(data)
		if len(data) > 0 && data[0] == '[' {
			if err := json.Unmarshal(data, &docs); err != nil {
				return nil, err
			}
			if len(docs) == 0 {
				return nil, fmt.Errorf("empty Snyk report")
			}
		} else {
			docs = []json.RawMessage{data}
		}

		for _, raw := range docs {
			var doc struct {
				OK              *bool `json:"ok"`
				Error           any
				Vulnerabilities []struct {
					ID, PackageName, Version, Title, Severity string
					FixedIn                                   []string
					Identifiers                               struct{ CVE []string }
				}
			}

			if err := json.Unmarshal(raw, &doc); err != nil {
				return nil, err
			}

			if doc.Error != nil || doc.OK == nil {
				return nil, fmt.Errorf("Snyk returned an error or unsupported report") //nolint:staticcheck
			}

			for _, v := range doc.Vulnerabilities {
				id := v.ID
				if len(v.Identifiers.CVE) > 0 {
					id = v.Identifiers.CVE[0]
				}

				f := finding("Snyk", id, v.PackageName, v.Version, v.Title, v.Severity, "", "https://security.snyk.io/vuln/"+v.ID)
				f.FixedVersions = v.FixedIn
				out = append(out, f)
			}
		}
	case "govulncheck":
		dec := json.NewDecoder(bytes.NewReader(data))
		advisories := map[string]struct {
			Summary, Details string
			Aliases          []string
		}{}

		count := 0
		for {
			var msg struct {
				Config   json.RawMessage
				Progress json.RawMessage
				SBOM     json.RawMessage
				OSV      *struct {
					ID, Summary, Details string
					Aliases              []string
				}
				Finding *struct {
					OSV          string
					FixedVersion string `json:"fixed_version"`
					Trace        []struct{ Module, Version, Package, Function string }
				}
			}

			err := dec.Decode(&msg)
			if err == io.EOF {
				break
			}

			if err != nil {
				return nil, err
			}

			if msg.Config == nil && msg.Progress == nil && msg.SBOM == nil && msg.OSV == nil && msg.Finding == nil {
				return nil, fmt.Errorf("unrecognized govulncheck message")
			}

			count++

			if msg.OSV != nil {
				v := msg.OSV
				advisories[v.ID] = struct {
					Summary, Details string
					Aliases          []string
				}{v.Summary, v.Details, v.Aliases}
			}

			if msg.Finding != nil {
				v := msg.Finding
				pkg, version := "Go code", ""

				if len(v.Trace) > 0 {
					pkg = v.Trace[0].Module
					version = v.Trace[0].Version
				}

				a := advisories[v.OSV]
				id := v.OSV

				for _, alias := range a.Aliases {
					if strings.HasPrefix(alias, "CVE-") {
						id = alias
						break
					}
				}

				f := finding("govulncheck", id, pkg, version, a.Summary, "UNKNOWN", v.FixedVersion, "https://pkg.go.dev/vuln/"+v.OSV)
				f.Description = a.Details
				out = append(out, f)
			}
		}

		if count == 0 {
			return nil, fmt.Errorf("empty govulncheck report")
		}
	default:
		return nil, fmt.Errorf("unsupported scanner")
	}
	return out, nil
}
