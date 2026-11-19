package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"vulman/internal/engine"
	"vulman/internal/model"
	"vulman/internal/remediation"
	"vulman/internal/scanner"
	"vulman/internal/store"
)

// Desktop contains the operations exposed to the bundled interface.
type Desktop struct {
	mu                  sync.RWMutex
	store               *store.Store
	engine              *engine.Engine
	closed              bool
	workspaceGeneration uint64
	defaultDirectory    string
	storageWarning      string
	openBrowser         func(string) error
	chooseDirectory     func(title, directory string) (string, error)
}

type ScanRepository struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

type State struct {
	*model.State
	Version              string                      `json:"version"`
	TokenStatus          map[string]bool             `json:"token_status"`
	SavedTokenStatus     map[string]bool             `json:"saved_token_status,omitempty"`
	ScanRepositories     map[string][]ScanRepository `json:"scan_repositories,omitempty"`
	StoragePaths         store.Paths                 `json:"storage_paths,omitzero"`
	CacheStats           store.CacheStats            `json:"cache_stats"`
	DataDirectory        string                      `json:"data_directory,omitempty"`
	DefaultDataDirectory string                      `json:"default_data_directory,omitempty"`
	StorageWarning       string                      `json:"storage_warning,omitempty"`
}

func (d *Desktop) State() (State, error) {
	return d.StateSince("")
}

// StateSince returns cache metrics on every poll and sends workspace data only on a change.
func (d *Desktop) StateSince(since string) (State, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	prefix := strconv.FormatUint(d.workspaceGeneration, 10) + ":"
	// Two workspaces may have the same bbolt sequence number.
	if version, ok := strings.CutPrefix(since, prefix); ok {
		since = version
	} else {
		since = ""
	}

	st, version, err := d.store.ReadSnapshot(since)
	if err != nil {
		return State{}, errors.New("could not read application data")
	}

	cacheStats, err := d.store.CacheStats()
	if err != nil {
		return State{}, errors.New("could not read cache information")
	}

	result := State{State: st, Version: prefix + version, CacheStats: cacheStats}
	if st != nil {
		result.TokenStatus = map[string]bool{}
		result.SavedTokenStatus = map[string]bool{}
		for k, v := range model.EffectiveSettings(st.Settings).Tokens {
			result.TokenStatus[k] = v != ""
			if st.Settings.Tokens[k] != "" {
				result.SavedTokenStatus[k] = true
			}
		}

		st.Settings.Tokens = nil
		result.ScanRepositories = make(map[string][]ScanRepository)
		for _, project := range st.Projects {
			for _, repository := range project.Repositories() {
				label := scanner.RepositoryLabel(repository)
				if label != "" {
					result.ScanRepositories[project.ID] = append(result.ScanRepositories[project.ID], ScanRepository{
						Key: scanner.RemoteTargetKey(repository), Label: label,
					})
				}
			}
		}

		result.StoragePaths = d.store.Paths()
		result.DataDirectory = filepath.Dir(result.StoragePaths.Database)
		result.DefaultDataDirectory = d.defaultDirectory
		result.StorageWarning = d.storageWarning
	}

	return result, nil
}

type ProjectInput struct {
	Name           string        `json:"name"`
	Description    string        `json:"description"`
	Repository     string        `json:"repository"`
	RepositoryURLs []string      `json:"repository_urls"`
	LocalPath      string        `json:"local_path"`
	ScanCode       bool          `json:"scan_code"`
	Assets         []model.Asset `json:"assets"`
	Schedule       string        `json:"schedule"`
	Revision       int           `json:"revision"`
}

func (in ProjectInput) project() model.Project {
	return model.Project{Name: in.Name, Description: in.Description, Repository: in.Repository, RepositoryURLs: in.RepositoryURLs, LocalPath: in.LocalPath, ScanCode: in.ScanCode, Assets: in.Assets, Schedule: in.Schedule}
}

func (d *Desktop) CreateProject(in ProjectInput) (model.Project, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p := in.project()
	if err := model.ValidateProject(&p); err != nil {
		return model.Project{}, err
	}

	p.ID = model.NewID()
	p.Revision = 1
	p.CreatedAt = time.Now()
	p.UpdatedAt = p.CreatedAt
	p.Findings = []model.Finding{}
	p.Runs = []model.Run{}
	if d := model.Interval(p.Schedule); d > 0 {
		p.NextRun = p.CreatedAt.Add(d)
	}

	err := d.store.Update(func(st *model.State) error {
		if len(st.Projects) >= 500 {
			return fmt.Errorf("project limit reached")
		}

		st.Projects = append(st.Projects, p)
		return nil
	})

	if err != nil {
		return model.Project{}, err
	}

	return p, nil
}

func (d *Desktop) UpdateProject(id string, in ProjectInput) (model.Project, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	p := in.project()
	err := d.store.Update(func(st *model.State) error {
		for i := range st.Projects {
			old := &st.Projects[i]
			if old.ID != id {
				continue
			}

			if old.Syncing {
				return fmt.Errorf("wait for the active assessment before editing")
			}

			if in.Revision != old.Revision {
				return fmt.Errorf("project changed; reload before saving")
			}

			if (old.LocalPath != "" || len(old.Repositories()) > 0) && p.LocalPath == "" &&
				!slices.ContainsFunc(p.Repositories(), func(url string) bool { return strings.TrimSpace(url) != "" }) {
				p.ScanCode = false
			}

			if err := model.ValidateProject(&p); err != nil {
				return err
			}

			removeProjectResults(old, p)
			old.Name = p.Name
			old.Description = p.Description
			old.Repository = p.Repository
			old.RepositoryURLs = p.RepositoryURLs
			old.LocalPath = p.LocalPath
			old.ScanCode = p.ScanCode
			old.Assets = p.Assets
			old.Revision++
			old.UpdatedAt = time.Now()

			if old.Schedule != p.Schedule {
				old.Schedule = p.Schedule
				old.NextRun = time.Time{}
				if d := model.Interval(p.Schedule); d > 0 {
					old.NextRun = time.Now().Add(d)
				}
			}

			p = *old
			return nil
		}

		return errors.New("project not found")
	})

	if err != nil {
		return model.Project{}, err
	}

	return p, nil
}

func (d *Desktop) DeleteProject(id, confirmation string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.store.Update(func(st *model.State) error {
		for i, p := range st.Projects {
			if p.ID != id {
				continue
			}

			if confirmation == "" || confirmation != p.Name {
				return errors.New("enter the exact project name to confirm deletion")
			}

			if p.Syncing {
				return errors.New("wait for the active assessment before deleting")
			}

			st.Projects = append(st.Projects[:i], st.Projects[i+1:]...)
			return nil
		}

		return errors.New("project not found")
	})
}

func (d *Desktop) DeleteRun(id, runID string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	found := false
	err := d.store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != id {
				continue
			}

			for j, run := range p.Runs {
				if run.ID != runID {
					continue
				}

				found = true
				switch run.Status {
				case "interrupted", "partial", "failed", "stopped":
					p.Runs = append(p.Runs[:j], p.Runs[j+1:]...)
					return nil
				default:
					return fmt.Errorf("only interrupted, partial, failed, or stopped activity can be deleted")
				}
			}

			return nil
		}

		return nil
	})

	if err != nil {
		return err
	}

	if !found {
		return errors.New("activity not found")
	}

	return nil
}

type SyncInput struct {
	AssetID  string `json:"asset_id"`
	Mode     string `json:"mode"`
	Severity string `json:"severity"`
}

func (d *Desktop) Sync(id string, in SyncInput) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.engine.StartFiltered(id, "manual", in.AssetID, in.Mode, in.Severity)
}

func (d *Desktop) ScanCode(id string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.engine.StartCodeScan(id)
}

func (d *Desktop) ControlRun(id, runID, action string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.engine.Control(id, runID, action)
}

func (d *Desktop) CheckScanner(ctx context.Context, name string) (scanner.CheckResult, error) {
	return scanner.Check(ctx, name)
}

type SettingsInput struct {
	model.Settings
	ClearTokens []string `json:"clear_tokens"`
}

func validCredential(name string) bool {
	switch name {
	case "nvd", "openai", "claude", "snyk", "github":
		return true
	default:
		return false
	}
}

// SavedCredentialPreview returns a partially masked key saved in this workspace.
func (d *Desktop) SavedCredentialPreview(name string) (string, error) {
	if !validCredential(name) {
		return "", errors.New("unsupported token")
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	st, err := d.store.Read()
	if err != nil {
		return "", errors.New("could not read application data")
	}

	const prefix, suffix = 10, 4
	saved := []rune(st.Settings.Tokens[name])

	if len(saved) <= prefix+suffix {
		return strings.Repeat("x", len(saved)), nil
	}

	middle := strings.Repeat("x", len(saved)-prefix-suffix)
	return string(saved[:prefix]) + middle + string(saved[len(saved)-suffix:]), nil
}

func (d *Desktop) SaveSettings(in SettingsInput) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cfg := in.Settings
	if cfg.CacheHours == 0 {
		cfg.CacheHours = 6
	}

	if cfg.CacheHours < 1 || cfg.CacheHours > 168 {
		return errors.New("cache freshness must be between 1 and 168 hours")
	}

	if cfg.CacheMaxEntries != 0 && (cfg.CacheMaxEntries < model.MinCacheMaxEntries || cfg.CacheMaxEntries > model.MaxCacheMaxEntries) {
		return errors.New("cache entry limit must be between 100 and 1000000")
	}

	if cfg.CacheMaxMiB != 0 && (cfg.CacheMaxMiB < model.MinCacheMaxMiB || cfg.CacheMaxMiB > model.MaxCacheMaxMiB) {
		return errors.New("cache size limit must be between 16 and 4096 MiB")
	}

	if cfg.Scanners == nil {
		cfg.Scanners = map[string]bool{}
	}

	localizations, localeErr := bundledLocalizations()
	if localeErr != nil {
		return localeErr
	}

	if _, supported := localizations[cfg.Language]; !supported {
		return errors.New("unsupported language")
	}

	if !cfg.Sources["nvd"] && !cfg.Sources["osv"] {
		return errors.New("enable NVD or OSV for discovery; CVE enriches their records")
	}

	for _, endpoint := range []string{cfg.NVDURL, cfg.CVEURL, cfg.OSVURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("source endpoints must be HTTPS URLs without credentials or fragments")
		}
	}

	if cfg.AIProvider != "public" && cfg.AIProvider != "openai" && cfg.AIProvider != "claude" {
		return errors.New("invalid AI provider")
	}

	for name := range cfg.Scanners {
		if !scanner.Supported(name) {
			return errors.New("unsupported scanner")
		}
	}

	for k := range cfg.Tokens {
		if !validCredential(k) {
			return errors.New("unsupported token")
		}
	}

	for _, k := range in.ClearTokens {
		if !validCredential(k) {
			return errors.New("unsupported token")
		}
	}

	err := d.store.Update(func(st *model.State) error {
		tokens := st.Settings.Tokens
		if cfg.CacheMaxEntries == 0 {
			cfg.CacheMaxEntries = st.Settings.CacheMaxEntries
		}

		if cfg.CacheMaxMiB == 0 {
			cfg.CacheMaxMiB = st.Settings.CacheMaxMiB
		}

		if tokens == nil {
			tokens = map[string]string{}
		}

		for k, v := range cfg.Tokens {
			if v != "" {
				tokens[k] = v
			}
		}

		for _, k := range in.ClearTokens {
			delete(tokens, k)
		}

		cfg.Tokens = tokens
		st.Settings = cfg
		return nil
	})

	if err != nil {
		return errors.New("could not save settings")
	}

	return nil
}

type AdviceInput struct {
	FindingID string `json:"finding_id"`
	AssetID   string `json:"asset_id"`
	Provider  string `json:"provider"`
}

func (d *Desktop) Advice(ctx context.Context, id string, in AdviceInput) (remediation.Advice, error) {
	d.mu.RLock()
	st, err := d.store.Read()
	d.mu.RUnlock()
	if err != nil {
		return remediation.Advice{}, errors.New("could not read data")
	}

	if in.Provider != "public" && in.Provider != "openai" && in.Provider != "claude" {
		return remediation.Advice{}, errors.New("invalid advice provider")
	}

	for _, p := range st.Projects {
		if p.ID != id {
			continue
		}

		for _, f := range p.Findings {
			if f.ID == in.FindingID && f.AssetID == in.AssetID {
				return remediation.Generate(ctx, f, model.EffectiveSettings(st.Settings), in.Provider), nil
			}
		}
	}

	return remediation.Advice{}, errors.New("finding not found")
}

func (d *Desktop) ChooseFolder(title, directory string) (string, error) {
	return d.chooseDirectory(title, directory)
}

func (d *Desktop) OpenExternal(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil {
		return errors.New("invalid external link")
	}

	return d.openBrowser(u.String())
}

// addSample runs during startup before the scheduler or UI can create projects.
func addSample(db *store.Store) error {
	state, err := db.Read()
	if err != nil || len(state.Projects) != 0 {
		return err
	}

	app := Desktop{store: db}
	_, err = app.CreateProject(ProjectInput{
		Name: "Sample · Java service", Schedule: "off",
		Description: "Sample inventory for testing Vulman.",
		Assets: []model.Asset{{
			Kind: "library", Name: "org.apache.logging.log4j:log4j-core", Version: "2.14.1",
			Ecosystem: "Maven", CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
		}},
	})

	return err
}
