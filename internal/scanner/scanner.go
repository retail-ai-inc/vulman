package scanner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"vulman/internal/apperror"
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
		return apperror.New("scanner_executable_must_resolve_to_an_absolute_path", "scanner executable must resolve to an absolute path")
	}

	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.Ext(cmd.Path), ".exe") {
		return apperror.New("scanner_requires_a_windows_executable", "scanner requires a Windows executable")
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
	output, _, code, err := runWithStderr(ctx, dir, cmd, token)
	return output, code, err
}

// stderr stays inside the scanner package. Only fixed diagnostic messages may
// reach workflow logs; external output can contain credentials or private URLs.
func runWithStderr(ctx context.Context, dir string, cmd *exec.Cmd, token string) ([]byte, []byte, int, error) {
	if err := prepareCommand(dir, cmd, token); err != nil {
		return nil, nil, -1, err
	}
	var output, stderr cappedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &stderr
	err := cmd.Run()
	code := 0

	if ctx.Err() != nil {
		return nil, nil, -1, ctx.Err()
	}

	if output.exceeded {
		return nil, nil, -1, apperror.New("scanner_output_exceeded_16_mib", "scanner output exceeded 16 MiB")
	}

	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			code = e.ExitCode()
		} else {
			return nil, nil, -1, err
		}
	}

	return output.Bytes(), stderr.Bytes(), code, nil
}

type ScanEvent struct {
	Phase, Tool     string
	Path, TargetKey string
	Job             *model.ScannerJob
	Plan            []model.ScannerJob
	Target          string
	Repository      string
	Found           int
	Err             error
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

// Scan preserves the English CLI report format. Desktop assessments use the
// structured causes from ScanDetailed so saved warnings follow the UI language.
func Scan(ctx context.Context, p model.Project, s model.Settings, dataDir string, report func(ScanEvent), catalogues ...LocalOSV) ([]model.Finding, []string) {
	findings, problems := ScanDetailed(ctx, p, s, dataDir, report, catalogues...)
	warnings := make([]string, 0, len(problems))
	for _, problem := range problems {
		warnings = append(warnings, apperror.Public(problem).English())
	}

	return findings, warnings
}

func ScanDetailed(ctx context.Context, p model.Project, s model.Settings, dataDir string, report func(ScanEvent), catalogues ...LocalOSV) ([]model.Finding, []error) {
	result := ScanWithReport(ctx, p, s, dataDir, report, catalogues...)
	return result.Findings, result.Problems
}

func ScanWithReport(ctx context.Context, p model.Project, s model.Settings, dataDir string, report func(ScanEvent), catalogues ...LocalOSV) (result Report) {
	result.Findings = []model.Finding{}
	result.Problems = []error{}

	if report == nil {
		report = func(ScanEvent) {}
	}

	if len(EnabledTools(s.Scanners)) == 0 {
		result.Problems = append(result.Problems, apperror.New("scan_no_tools", "Code scanning enabled on project, but no scanner is enabled in settings."))
		return result
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
		result.Problems = append(result.Problems, apperror.New("scan_no_repository", "Code scanning requires a local folder or repository URL."))
		return result
	}

	root, err := openScratchRoot(dataDir, true)
	if err != nil {
		result.Problems = append(result.Problems, apperror.Newf("scan_storage_create", "Could not create temporary scan storage: %w", err))
		return result
	}

	defer func() {
		if err := root.Close(); err != nil {
			result.Problems = append(result.Problems, apperror.Newf("scan_storage_close", "Could not close temporary scan storage: %w", err))
		}
	}()
	if err := cleanAbandonedScans(root); err != nil {
		result.Problems = append(result.Problems, apperror.Newf("scan_abandoned_cleanup", "Could not remove abandoned scan files: %w", err))
	}

	remainingJobs := model.MaxScannerJobs
	for _, target := range targets {
		if err := workflow.Wait(ctx); err != nil {
			result.Problems = append(result.Problems, err)
			break
		}

		completedBefore := len(result.Completed)
		items, problems := scanRepository(ctx, root, target.kind, target.location, EffectiveProfile(p, s, target.key), s.Scanners, s.Tokens, remainingJobs, func(event ScanEvent) {
			event.Target, event.TargetKey, event.Repository = target.kind, target.key, target.repository
			remainingJobs -= len(event.Plan)
			for i := range event.Plan {
				event.Plan[i].Target, event.Plan[i].Repository = target.key, target.repository
			}
			if event.Job != nil {
				event.Job.Target, event.Job.Repository = target.key, target.repository
			}
			if event.Phase == "scanner_completed" {
				result.Completed = append(result.Completed, Coverage{Target: target.key, Tool: event.Tool, Path: event.Path, GeneratedLockfile: event.Job != nil && event.Job.GeneratedLockfile})
			}
			report(event)
		}, catalogues...)
		for i := range items {
			items[i].AssetID = FindingAssetID(target.key, items[i].ScanPath, items[i].Component)
			items[i].ScanTarget = target.kind
			items[i].ScanRepository = target.repository
		}
		result.Findings = append(result.Findings, items...)
		if len(problems) == 0 && len(result.Completed) > completedBefore {
			result.CompletedTargets = append(result.CompletedTargets, target.key)
		}
		for _, problem := range problems {
			switch {
			case target.kind == "local":
				result.Problems = append(result.Problems, apperror.Newf("scan_local_target", "Local folder: %w", problem))
			case target.repository != "":
				result.Problems = append(result.Problems, apperror.Newf("context", "%s: %w", target.repository, problem))
			default:
				result.Problems = append(result.Problems, apperror.Newf("scan_remote_target", "Remote repository: %w", problem))
			}
		}
	}

	if len(result.Completed) == 0 && len(result.Problems) == 0 {
		for _, target := range targets {
			if EffectiveProfile(p, s, target.key).Mode != "disabled" {
				result.Problems = append(result.Problems, apperror.New("scanner_no_applicable_tools", "No scanner completed. No enabled scanner matched the repository project files. Review the scanner plan and repository profile."))
				break
			}
		}
	}

	return result
}

// FindingAssetID keeps separate monorepo projects distinct while retaining
// the existing root-level identities and repository filter prefixes.
func FindingAssetID(target, directory, component string) string {
	prefix := "code:"
	if target != "" {
		prefix += target + ":"
	}

	if directory != "" {
		prefix += fmt.Sprintf("path:%x:", sha256.Sum256([]byte(directory)))
	}

	return prefix + component
}

func reportDirectory(filename string) string {
	filename = strings.TrimPrefix(strings.ReplaceAll(filename, "\\", "/"), "./")
	if filename == "" || strings.Contains(filename, ":") || !fs.ValidPath(filename) {
		return ""
	}

	directory := path.Dir(filename)
	if directory == "." {
		return ""
	}

	return directory
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

func scanRepository(ctx context.Context, root *os.Root, kind, location string, profile model.ScannerProfile, enabled map[string]bool, tokens map[string]string, maxJobs int, report func(ScanEvent), catalogues ...LocalOSV) (findings []model.Finding, warnings []error) {
	targetFailed := func(err error) ([]model.Finding, []error) {
		report(ScanEvent{Phase: "scanner_target_failed", Err: err})
		return nil, []error{err}
	}
	if maxJobs < len(registry) {
		return targetFailed(apperror.New("scanner_plan_limit", "Repository contains too many project directories to scan in one run."))
	}

	// A disabled repository requires neither filesystem access nor a network clone.
	if profile.Mode == "disabled" {
		var jobs []model.ScannerJob
		for _, tool := range registry {
			jobs = append(jobs, model.ScannerJob{Tool: tool.ID, Status: "skipped", Reason: "repository_disabled"})
		}
		report(ScanEvent{Phase: "scanner_planned", Plan: jobs})
		return nil, nil
	}

	scratch, err := newScanScratch(root)
	if err != nil {
		return targetFailed(err)
	}

	defer func() {
		if err := scratch.remove(); err != nil {
			warnings = append(warnings, apperror.Newf("scan_cleanup", "Could not remove temporary scan files: %w", err))
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

	jobs, err := Plan(ctx, dir, profile, enabled)
	if err != nil {
		return targetFailed(err)
	}
	if kind == "local" && slices.ContainsFunc(jobs, func(job model.ScannerJob) bool { return job.Reason == "lockfile_required" }) {
		report(ScanEvent{Phase: "scanner_copying"})
		dir, err = copyRepository(ctx, dir, scratch)
		if err != nil {
			return targetFailed(err)
		}
		jobs, err = Plan(ctx, dir, profile, enabled)
		if err != nil {
			return targetFailed(err)
		}
	}

	if len(jobs) > maxJobs {
		return targetFailed(apperror.New("scanner_plan_limit", "Repository contains too many project directories to scan in one run."))
	}

	report(ScanEvent{Phase: "scanner_planned", Plan: jobs})
	generated, ignoredPlatform := false, false

	for _, job := range jobs {
		emit := func(phase, status string, found int, err error) {
			job.Status = status
			report(ScanEvent{Phase: phase, Tool: job.Tool, Path: job.Path, Job: &job, Found: found, Err: err})
		}
		if job.Status == "skipped" {
			emit("scanner_skipped", "skipped", 0, nil)
			continue
		}

		tool, _ := definition(job.Tool)
		if job.Status == "blocked" {
			err := apperror.Newf("scanner_input_missing", "%s requires these project files: %s. Add the missing files, or enable temporary lockfile generation for npm/Composer when the manifest exists.", tool.Label, inputDescription(tool))
			warnings = append(warnings, err)
			emit("scanner_blocked", "blocked", 0, err)
			continue
		}
		if err := workflow.Wait(ctx); err != nil {
			job.Reason = "interrupted"
			emit("scanner_interrupted", "interrupted", 0, err)
			warnings = append(warnings, err)
			break
		}
		if job.Reason == "lockfile_required" {
			job.Reason = "generating_lockfile"
			emit("scanner_lockfile_started", "running", 0, nil)
			err := generateLockfile(ctx, filepath.Join(dir, filepath.FromSlash(job.Path)), scratch, job.Tool, profile.IgnoreComposerPlatform)
			if err != nil {
				job.Reason = "lockfile_generation_failed"
				phase, status := "scanner_lockfile_failed", "failed"
				if ctx.Err() != nil {
					phase, status, job.Reason = "scanner_interrupted", "interrupted", "interrupted"
				}
				emit(phase, status, 0, err)
				warnings = append(warnings, err)
				continue
			}
			generated, job.GeneratedLockfile, job.Reason = true, true, "generated_lockfile"
			job.IgnoredComposerPlatform = job.Tool == "composer" && profile.IgnoreComposerPlatform
			ignoredPlatform = ignoredPlatform || job.IgnoredComposerPlatform
			emit("scanner_lockfile_completed", "running", 0, nil)
		}
		if tool.Scope == "repository" && generated {
			job.GeneratedLockfile, job.Reason = true, "generated_lockfile"
			job.IgnoredComposerPlatform = ignoredPlatform
		}

		token := tokens[tool.Token]
		if tool.Token != "" && token == "" {
			err := apperror.Newf("scanner_token_missing", "%s requires a configured API token.", tool.Label)
			job.Reason = "missing_token"
			warnings = append(warnings, err)
			emit("scanner_missing_token", "blocked", 0, err)
			continue
		}

		var items []model.Finding
		var err error
		if tool.Native {
			var catalogue LocalOSV
			if len(catalogues) > 0 {
				catalogue = catalogues[0]
			}
			emit("scanning", "running", 0, nil)
			items, err = scanComposerLock(ctx, filepath.Join(dir, filepath.FromSlash(job.Path)), catalogue)
		} else {
			items, err = scanTool(ctx, filepath.Join(dir, filepath.FromSlash(job.Path)), scratch, job.Tool, token, func() {
				emit("scanning", "running", 0, nil)
			})
		}
		for i := range items {
			items[i].GeneratedLockfile = job.GeneratedLockfile
			if tool.Scope != "repository" {
				items[i].ScanPath = job.Path
			}
		}
		if err == nil || tool.Native {
			findings = append(findings, items...)
		}
		if err != nil {
			phase, status := "scanner_failed", "failed"
			job.Reason = "execution_failed"
			if ctx.Err() != nil {
				phase, status, job.Reason = "scanner_interrupted", "interrupted", "interrupted"
			}
			emit(phase, status, 0, err)
			warnings = append(warnings, apperror.Newf("scanner_tool_failed", "%s: %w", job.Tool, err))
			continue
		}

		emit("scanner_completed", "complete", len(items), nil)
	}

	return findings, warnings
}

func inputDescription(tool Definition) string {
	var groups []string
	for _, alternatives := range tool.Inputs {
		groups = append(groups, strings.Join(alternatives, " / "))
	}

	return strings.Join(groups, " + ")
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
		return "", apperror.New("repository_clone_access_failed", "repository clone failed. Check HTTPS access and whether the GitHub token has read access to this repository")
	}

	return "", apperror.New("repository_clone_failed", "repository clone failed. Check Git and HTTPS access. For private repositories, configure a GitHub token with read access")
}

func scanTool(ctx context.Context, dir string, scratch *scanScratch, name, token string, started func()) ([]model.Finding, error) {
	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	item, ok := definition(name)
	if !ok || item.build == nil {
		return nil, apperror.New("unsupported_scanner", "unsupported scanner")
	}
	cmd, dir, err := item.build(scanCtx, dir, scratch)
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
	allowed := slices.Contains(item.exitCodes, code)
	if !allowed {
		return nil, apperror.Newf("scanner_exit", "exit %d; no clean scan was recorded", code)
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
	definition, ok := definition(name)
	if !ok || definition.parse == nil {
		return nil, apperror.New("unsupported_scanner", "unsupported scanner")
	}

	return definition.parse(data)
}

func parseNPM(data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
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
		return nil, apperror.New("npm_report_invalid", "npm audit returned an error or unsupported report (requires npm 7+)")
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

	return out, nil
}

func parseComposer(data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
	var doc struct {
		Advisories json.RawMessage `json:"advisories"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if len(doc.Advisories) == 0 || string(doc.Advisories) == "null" {
		return nil, apperror.New("composer_report_has_no_advisories_field", "composer report has no advisories field")
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

	return out, nil
}

func parseTrivy(data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
	var doc struct {
		SchemaVersion int
		Results       []struct {
			Target          string
			Vulnerabilities []struct{ VulnerabilityID, PkgName, InstalledVersion, FixedVersion, Title, Description, Severity, PrimaryURL string }
		}
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	if doc.SchemaVersion == 0 {
		return nil, apperror.New("unsupported_trivy_report", "unsupported Trivy report")
	}

	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			f := finding("Trivy", v.VulnerabilityID, v.PkgName, v.InstalledVersion, v.Title, v.Severity, v.FixedVersion, v.PrimaryURL)
			f.Description = v.Description
			f.ScanPath = reportDirectory(r.Target)
			out = append(out, f)
		}
	}

	return out, nil
}

func parseSnyk(data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
	var docs []json.RawMessage
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		if err := json.Unmarshal(data, &docs); err != nil {
			return nil, err
		}
		if len(docs) == 0 {
			return nil, apperror.New("empty_snyk_report", "empty Snyk report")
		}
	} else {
		docs = []json.RawMessage{data}
	}

	for _, raw := range docs {
		var doc struct {
			OK              *bool  `json:"ok"`
			TargetFile      string `json:"targetFile"`
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
			return nil, apperror.New("snyk_returned_an_error_or_unsupported_report", "Snyk returned an error or unsupported report")
		}

		for _, v := range doc.Vulnerabilities {
			id := v.ID
			if len(v.Identifiers.CVE) > 0 {
				id = v.Identifiers.CVE[0]
			}

			f := finding("Snyk", id, v.PackageName, v.Version, v.Title, v.Severity, "", "https://security.snyk.io/vuln/"+v.ID)
			f.FixedVersions = v.FixedIn
			f.ScanPath = reportDirectory(doc.TargetFile)
			out = append(out, f)
		}
	}

	return out, nil
}

func parseGoVulncheck(data []byte) ([]model.Finding, error) {
	out := []model.Finding{}
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
			return nil, apperror.New("unrecognized_govulncheck_message", "unrecognized govulncheck message")
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
		return nil, apperror.New("empty_govulncheck_report", "empty govulncheck report")
	}

	return out, nil
}
