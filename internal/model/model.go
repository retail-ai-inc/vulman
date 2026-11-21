package model

import (
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"vulman/internal/apperror"
)

type Asset struct {
	NeedsAssessment bool   `json:"needs_assessment,omitempty"`
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	Ecosystem       string `json:"ecosystem"`
	CPE             string `json:"cpe"`
}

type Finding struct {
	ID             string   `json:"id"`
	AssetID        string   `json:"asset_id"`
	ScanTarget     string   `json:"scan_target,omitempty"`
	ScanRepository string   `json:"scan_repository,omitempty"`
	ScanPath       string   `json:"scan_path,omitempty"`
	Component      string   `json:"component"`
	Version        string   `json:"version"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Score          float64  `json:"score"`
	Sources        []string `json:"sources"`
	References     []string `json:"references"`
	FixedVersions  []string `json:"fixed_versions"`
	Match          string   `json:"match"`
	Aliases        []string `json:"aliases"`
}

type Run struct {
	ID                      string               `json:"id"`
	StartedAt               time.Time            `json:"started_at"`
	FinishedAt              time.Time            `json:"finished_at"`
	Status                  string               `json:"status"`
	Trigger                 string               `json:"trigger"`
	AssetID                 string               `json:"asset_id,omitempty"`
	AssetName               string               `json:"asset_name,omitempty"`
	Count                   int                  `json:"count"`
	SeverityCounts          map[string]int       `json:"severity_counts,omitempty"`
	Warnings                []string             `json:"warnings"`
	WarningMessages         []apperror.Message   `json:"warning_messages,omitempty"`
	Steps                   []SyncStep           `json:"steps,omitempty"`
	Logs                    []SyncLog            `json:"logs,omitempty"`
	Mode                    string               `json:"mode,omitempty"`
	Severity                string               `json:"severity,omitempty"`
	ScanTargets             []string             `json:"scan_targets,omitempty"`
	ScanTarget              string               `json:"scan_target,omitempty"`
	ScanRepository          string               `json:"scan_repository,omitempty"`
	Selection               *AssessmentSelection `json:"selection,omitempty"`
	ScannerJobs             []ScannerJob         `json:"scanner_jobs,omitempty"`
	ScannerJobSequence      uint64               `json:"scanner_job_sequence,omitempty"`
	ScannersCompleted       int                  `json:"scanners_completed,omitempty"`
	RetainedScannerFindings int                  `json:"retained_scanner_findings,omitempty"`
	DataCheckedAt           time.Time            `json:"data_checked_at"`
	PausedAt                time.Time            `json:"paused_at"`
	PausedSeconds           float64              `json:"paused_seconds,omitempty"`
	DatabaseWaits           []DatabaseWait       `json:"database_waits,omitempty"`
}

type AssessmentSelection struct {
	Assets       []AssessmentItem `json:"assets,omitempty"`
	Repositories []AssessmentItem `json:"repositories,omitempty"`
}

type AssessmentItem struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

type ScannerProfile struct {
	Mode            string   `json:"mode"`
	Tools           []string `json:"tools,omitempty"`
	AdditionalTools []string `json:"additional_tools,omitempty"`
	NeedsScan       bool     `json:"needs_scan,omitempty"`
}

type ScannerJob struct {
	UpdateSequence uint64 `json:"update_sequence,omitempty"`
	Findings       *int   `json:"findings,omitempty"`
	Target         string `json:"target"`
	Repository     string `json:"repository,omitempty"`
	Tool           string `json:"tool"`
	Path           string `json:"path,omitempty"`
	Status         string `json:"status"`
	Reason         string `json:"reason,omitempty"`
}

type DatabaseWait struct {
	Message *apperror.Message `json:"message,omitempty"`
	Source  string            `json:"source"`
	Status  string            `json:"status"`
	Detail  string            `json:"detail,omitempty"`
}

// SyncProgress reports work performed, never an estimate of elapsed completion.
type SyncProgress struct {
	Message        *apperror.Message `json:"message,omitempty"`
	Phase          string            `json:"phase"`
	Item           string            `json:"item,omitempty"`
	ScanTarget     string            `json:"scan_target,omitempty"`
	ScanRepository string            `json:"scan_repository,omitempty"`
	Processed      int               `json:"processed"`
	Total          int               `json:"total"`
	Found          int               `json:"found"`
	WaitSeconds    int               `json:"wait_seconds,omitempty"`
	CacheStatus    string            `json:"cache_status,omitempty"`
	CheckedAt      time.Time         `json:"checked_at"`
}

type SyncStep struct {
	ID         string       `json:"id"`
	Kind       string       `json:"kind"`
	Component  string       `json:"component,omitempty"`
	Status     string       `json:"status"`
	StartedAt  time.Time    `json:"started_at"`
	FinishedAt time.Time    `json:"finished_at"`
	Progress   SyncProgress `json:"progress"`
}

type SyncLog struct {
	Message        *apperror.Message `json:"message,omitempty"`
	Tool           string            `json:"tool,omitempty"`
	At             time.Time         `json:"at"`
	StepID         string            `json:"step_id,omitempty"`
	Event          string            `json:"event"`
	Detail         string            `json:"detail,omitempty"`
	Findings       *int              `json:"findings,omitempty"`
	ScanTarget     string            `json:"scan_target,omitempty"`
	ScanRepository string            `json:"scan_repository,omitempty"`
	ScanPath       string            `json:"scan_path,omitempty"`
	ScanReason     string            `json:"scan_reason,omitempty"`
}

const MaxSyncLogs = 200
const MaxScannerJobs = 1200

type Project struct {
	ID               string                    `json:"id"`
	Name             string                    `json:"name"`
	Description      string                    `json:"description"`
	Repository       string                    `json:"repository"`
	RepositoryURLs   []string                  `json:"repository_urls,omitempty"`
	LocalPath        string                    `json:"local_path"`
	ScanCode         bool                      `json:"scan_code"`
	ScannerProfiles  map[string]ScannerProfile `json:"scanner_profiles,omitempty"`
	Assets           []Asset                   `json:"assets"`
	Schedule         string                    `json:"schedule"`
	NextRun          time.Time                 `json:"next_run"`
	LastSync         time.Time                 `json:"last_sync"`
	CreatedAt        time.Time                 `json:"created_at"`
	UpdatedAt        time.Time                 `json:"updated_at"`
	Revision         int                       `json:"revision"`
	AssessedRevision int                       `json:"assessed_revision"`
	DataCheckedAt    time.Time                 `json:"data_checked_at"`
	Findings         []Finding                 `json:"findings"`
	Runs             []Run                     `json:"runs"`
	Syncing          bool                      `json:"syncing"`
}

// MarkOutdatedComponents recognizes results saved before component freshness
// was tracked explicitly, without discarding the previous assessment.
func (p *Project) MarkOutdatedComponents() {
	assets := make(map[string]int, len(p.Assets))
	for i, asset := range p.Assets {
		assets[asset.ID] = i
	}

	for _, finding := range p.Findings {
		index, ok := assets[finding.AssetID]
		if !ok || finding.Match == "scanner" {
			continue
		}

		asset := &p.Assets[index]
		if finding.Version != "" && finding.Version != asset.Version || finding.Component != "" && finding.Component != asset.Name {
			asset.NeedsAssessment = true
		}
	}
}

type Settings struct {
	OSVUpdateSchedule     string            `json:"osv_update_schedule"`
	OSVEcosystems         []string          `json:"osv_ecosystems"`
	NVDUpdateSchedule     string            `json:"nvd_update_schedule"`
	CVEUpdateSchedule     string            `json:"cve_update_schedule"`
	CacheHours            int               `json:"cache_hours"`
	CacheMaxEntries       int               `json:"cache_max_entries"`
	CacheMaxMiB           int               `json:"cache_max_mib"`
	Language              string            `json:"language"`
	Sources               map[string]bool   `json:"sources"`
	NVDURL                string            `json:"nvd_url"`
	CVEURL                string            `json:"cve_url"`
	OSVURL                string            `json:"osv_url"`
	AIProvider            string            `json:"ai_provider"`
	OpenAIModel           string            `json:"openai_model"`
	ClaudeModel           string            `json:"claude_model"`
	Scanners              map[string]bool   `json:"scanners"`
	ScannerConfigRevision string            `json:"scanner_config_revision,omitempty"`
	Tokens                map[string]string `json:"tokens,omitempty"`
}

type State struct {
	Projects []Project `json:"projects"`
	Settings Settings  `json:"settings"`
}

const DefaultCacheMaxEntries = 10000
const DefaultCVEURL = "https://cveawg.mitre.org/api/cve"
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
const DefaultOSVURL = "https://api.osv.dev/v1/query"
const DefaultCacheMaxMiB = 512
const MinCacheMaxEntries = 100
const MaxCacheMaxEntries = 1000000
const MinCacheMaxMiB = 16
const MaxCacheMaxMiB = 4096

func CacheLimits(s Settings) (uint64, uint64) {
	entries, mib := s.CacheMaxEntries, s.CacheMaxMiB
	if entries <= 0 || entries > MaxCacheMaxEntries {
		entries = DefaultCacheMaxEntries
	}

	if mib <= 0 || mib > MaxCacheMaxMiB {
		mib = DefaultCacheMaxMiB
	}

	return uint64(entries), uint64(mib) << 20
}

func Defaults() State {
	return State{Projects: []Project{}, Settings: Settings{
		OSVUpdateSchedule: "daily",
		NVDUpdateSchedule: "daily",
		CVEUpdateSchedule: "daily",
		CacheHours:        6,
		CacheMaxEntries:   DefaultCacheMaxEntries, CacheMaxMiB: DefaultCacheMaxMiB,
		Language: "en", Sources: map[string]bool{"nvd": true, "cve": true, "osv": false},
		NVDURL: DefaultNVDURL,
		CVEURL: DefaultCVEURL, OSVURL: DefaultOSVURL,
		AIProvider: "public", Scanners: map[string]bool{}, Tokens: map[string]string{},
	}}
}

func NVDInterval(schedule string) time.Duration {
	if schedule == "two_hourly" {
		return 2 * time.Hour
	}
	if schedule == "" || schedule == "daily" {
		return 24 * time.Hour
	}
	return 0
}

func NewID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}

	return hex.EncodeToString(b[:])
}

func Interval(s string) time.Duration {
	switch s {
	case "hourly":
		return time.Hour
	case "daily":
		return 24 * time.Hour
	case "weekly":
		return 7 * 24 * time.Hour
	}
	return 0
}

var githubRepositoryPath = regexp.MustCompile(`^/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/?$`)
var errGitHubRepositoryURL = apperror.New("repository_url_invalid", "Use an HTTPS GitHub repository URL such as https://github.com/owner/repository")

func ValidateRepositoryURL(repository string) error {
	_, err := GitHubCloneURL(repository)
	return err
}

func GitHubCloneURL(repository string) (string, error) {
	u, err := url.Parse(repository)
	if err != nil || u.Scheme != "https" || u.User != nil ||
		(!strings.EqualFold(u.Host, "github.com") && !strings.EqualFold(u.Host, "github.com:443")) {
		return "", errGitHubRepositoryURL
	}

	path := u.EscapedPath()
	if !githubRepositoryPath.MatchString(path) {
		return "", errGitHubRepositoryURL
	}

	path = strings.TrimSuffix(path, "/")
	switch path[strings.LastIndexByte(path, '/')+1:] {
	case ".", "..", ".git":
		return "", errGitHubRepositoryURL
	}

	// Browser view options and anchors are not part of the Git clone URL.
	return "https://github.com" + path, nil
}

func (p Project) Repositories() []string {
	if p.RepositoryURLs != nil {
		return p.RepositoryURLs
	}

	if p.Repository != "" {
		return []string{p.Repository}
	}

	return nil
}

func ValidateProject(p *Project) error {
	if p.Assets == nil {
		p.Assets = []Asset{}
	}

	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 120 {
		return apperror.New("project_name_invalid", "project name must contain 1–120 characters")
	}

	if len(p.Description) > 4000 || len(p.Assets) > 200 {
		return apperror.New("project_inventory_too_large", "description or inventory is too large")
	}

	if p.Schedule != "off" && Interval(p.Schedule) == 0 {
		return apperror.New("project_schedule_invalid", "invalid schedule")
	}

	var repositories []string
	seenRepositories := map[string]bool{}

	for _, repository := range p.Repositories() {
		repository = strings.TrimSpace(repository)
		if repository == "" || seenRepositories[repository] {
			continue
		}

		if err := ValidateRepositoryURL(repository); err != nil {
			return err
		}

		seenRepositories[repository] = true
		repositories = append(repositories, repository)
	}

	p.RepositoryURLs = repositories
	p.Repository = ""
	if len(repositories) > 0 {
		p.Repository = repositories[0]
	}

	if p.ScanCode && len(repositories) == 0 && p.LocalPath == "" {
		return apperror.New("project_scanner_target_required", "code scanning requires a repository or local folder")
	}

	seen := map[string]bool{}

	for i := range p.Assets {
		a := &p.Assets[i]
		a.Name = strings.TrimSpace(a.Name)
		a.Version = strings.TrimSpace(a.Version)

		if a.ID == "" {
			a.ID = NewID()
		}

		if seen[a.ID] {
			return apperror.New("component_id_duplicate", "duplicate component ID")
		}

		seen[a.ID] = true

		if a.Name == "" || a.Version == "" || len(a.Name) > 300 || len(a.Version) > 100 {
			return apperror.New("component_identity_required", "each component needs a name and exact version")
		}

		switch a.Kind {
		case "language", "database", "container", "docker", "webserver", "ai", "library", "other":
		default:
			return apperror.New("component_category_invalid", "invalid component category")
		}

		if a.CPE != "" {
			parts := strings.Split(a.CPE, ":")
			if len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" || parts[5] != a.Version {
				return apperror.New("cpe_version_invalid", "CPE must have 13 fields and contain the component's exact version")
			}
		}
	}

	return nil
}

func Severity(score float64) string {
	switch {
	case score >= 9:
		return "CRITICAL"
	case score >= 7:
		return "HIGH"
	case score >= 4:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func NormalizeSeverity(s string) string {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func Rank(s string) int {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM", "MODERATE":
		return 3
	case "LOW":
		return 2
	default:
		return 1
	}
}

func EffectiveSettings(s Settings) Settings {
	tokens := map[string]string{}
	for k, v := range s.Tokens {
		tokens[k] = v
	}

	for name, env := range map[string]string{"nvd": "NVD_API_KEY", "openai": "OPENAI_API_KEY", "claude": "ANTHROPIC_API_KEY", "snyk": "SNYK_TOKEN", "github": "GITHUB_TOKEN"} {
		if v := os.Getenv(env); v != "" {
			tokens[name] = v
		}
	}

	s.Tokens = tokens
	return s
}
