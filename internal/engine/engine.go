package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/sources"
	"vulman/internal/store"
	"vulman/internal/workflow"
)

type Engine struct {
	Store   *store.Store
	Sources *sources.Client
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.Mutex
	closed  bool
	active  map[string]activeRun
}

type activeRun struct {
	id      string
	control *workflow.Control
}

var ErrAssetNotFound = errors.New("tech stack component not found")
var ErrInvalidMode = errors.New("invalid sync mode")
var ErrInvalidSeverity = errors.New("invalid sync severity")

const codeScanMode = "code"

func New(s *store.Store) (*Engine, error) {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{Store: s, Sources: sources.New(s), ctx: ctx, cancel: cancel, active: map[string]activeRun{}}
	err := s.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			p.Syncing = false
			for j := range p.Runs {
				if activeStatus(p.Runs[j].Status) {
					finishPause(&p.Runs[j])
					p.Runs[j].Status = "interrupted"
					p.Runs[j].FinishedAt = time.Now()
					p.Runs[j].Warnings = append(p.Runs[j].Warnings, "Application stopped before assessment finished.")
					interruptSteps(&p.Runs[j])
					addLog(&p.Runs[j], "", "interrupted", "")
				}
			}
		}

		return nil
	})

	if err != nil {
		cancel()
		return nil, err
	}

	e.wg.Add(1)
	go e.loop()
	return e, nil
}

func (e *Engine) Close() { e.mu.Lock(); e.closed = true; e.cancel(); e.mu.Unlock(); e.wg.Wait() }

func (e *Engine) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-ticker.C:
			st, err := e.Store.Read()
			if err != nil {
				continue
			}
			for _, id := range dueProjects(st, now) {
				_ = e.Start(id, "schedule")
			}
		}
	}
}

func dueProjects(st model.State, now time.Time) []string {
	ids := []string{}
	for _, p := range st.Projects {
		if model.Interval(p.Schedule) > 0 && !p.Syncing && !p.NextRun.After(now) {
			ids = append(ids, p.ID)
		}
	}
	return ids
}

func (e *Engine) Start(id, trigger string) error {
	return e.StartAsset(id, trigger, "")
}

// An empty assetID assesses the entire project, including enabled code scanners.
// A component assessment leaves full-project freshness and scheduling intact.
func (e *Engine) StartAsset(id, trigger, assetID string) error {
	return e.StartAssetMode(id, trigger, assetID, "auto")
}

func (e *Engine) StartAssetMode(id, trigger, assetID, mode string) error {
	return e.StartFiltered(id, trigger, assetID, mode, "")
}

func (e *Engine) StartFiltered(id, trigger, assetID, mode, severity string) error {
	severity = strings.ToUpper(strings.TrimSpace(severity))
	if severity == "ALL" {
		severity = ""
	}

	switch severity {
	case "", "CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN":
	default:
		return ErrInvalidSeverity
	}

	if mode == "" {
		mode = "auto"
	}

	if mode != "auto" && mode != "local" && mode != "refresh" {
		return ErrInvalidMode
	}

	return e.startRun(id, trigger, assetID, mode, severity)
}

func (e *Engine) StartCodeScan(id string) error {
	return e.startRun(id, "manual", "", codeScanMode, "")
}

func (e *Engine) startRun(id, trigger, assetID, mode, severity string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return fmt.Errorf("application is stopping")
	}

	var snapshot model.Project
	var settings model.Settings
	runID := model.NewID()

	err := e.Store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != id {
				continue
			}

			if p.Syncing {
				return fmt.Errorf("project is already syncing")
			}

			settings = st.Settings
			if mode == codeScanMode {
				if !p.ScanCode || (p.LocalPath == "" && len(p.Repositories()) == 0) {
					return errors.New("enable code scanning and set a repository in Edit project")
				}
				if len(scanner.EnabledTools(settings.Scanners)) == 0 {
					return errors.New("enable a code scanner in Configuration")
				}
				settings.Sources = nil
			}

			assetName := ""
			if assetID != "" {
				for _, a := range p.Assets {
					if a.ID == assetID {
						assetName = a.Name + " " + a.Version
						break
					}
				}
				if assetName == "" {
					return ErrAssetNotFound
				}
			}

			p.Syncing = true
			now := time.Now()
			run := model.Run{ID: runID, StartedAt: now, Status: "running", Trigger: trigger, AssetID: assetID, AssetName: assetName, Mode: mode, Severity: severity, Warnings: []string{}, Steps: planSteps(*p, settings, assetID)}
			addLog(&run, "", "run_started", assetName)
			p.Runs = append([]model.Run{run}, p.Runs...)
			if len(p.Runs) > 30 {
				p.Runs = p.Runs[:30]
			}

			if d := model.Interval(p.Schedule); d > 0 && assetID == "" && mode != "local" && mode != codeScanMode && severity == "" {
				p.NextRun = now.Add(d)
			}

			snapshot = *p
			return nil
		}

		return fmt.Errorf("project not found")
	})

	if err != nil {
		return err
	}

	e.wg.Add(1)
	control := workflow.New(e.ctx, 20*time.Minute, func() { e.acknowledgePause(id, runID) })
	e.active[id] = activeRun{id: runID, control: control}
	go func() {
		defer e.wg.Done()
		defer control.Close()
		e.assess(snapshot, settings, runID, assetID, mode, severity, control)
	}()

	return nil
}

func (e *Engine) assess(p model.Project, s model.Settings, runID, assetID, mode, severity string, control *workflow.Control) {
	tracker := newTracker(e.Store, p.ID, runID)
	s = model.EffectiveSettings(s)
	ctx := sources.WithMode(control.Context(), mode)
	all := []model.Finding{}
	warnings := []string{}
	successes := 0
	usedData := false
	report := func(stepID string) func(model.SyncProgress) {
		return func(p model.SyncProgress) {
			if !p.CheckedAt.IsZero() {
				usedData = true
			}
			tracker.progress(stepID, p)
		}
	}

	if len(p.Assets) == 0 && !p.ScanCode {
		warnings = append(warnings, "No components registered. Add inventory before assessing this project.")
	}

	for _, a := range p.Assets {
		if ctx.Err() != nil {
			break
		}

		if assetID != "" && a.ID != assetID {
			continue
		}

		if s.Sources["nvd"] {
			if workflow.Wait(ctx) != nil {
				break
			}

			stepID := "nvd:" + a.ID
			tracker.start(stepID)
			items, err := e.Sources.NVD(ctx, a, s, report(stepID))
			tracker.finish(stepID, severityCount(items, severity), err)
			all = append(all, items...)

			if err != nil {
				warnings = append(warnings, fmt.Sprintf("NVD · %s: %v", a.Name, err))
			} else {
				successes++
			}
		}

		if s.Sources["osv"] && ctx.Err() == nil {
			if workflow.Wait(ctx) != nil {
				break
			}
			stepID := "osv:" + a.ID
			tracker.start(stepID)
			items, err := e.Sources.OSV(ctx, a, s, report(stepID))
			tracker.finish(stepID, severityCount(items, severity), err)
			all = append(all, items...)

			if err != nil {
				warnings = append(warnings, fmt.Sprintf("OSV · %s: %v", a.Name, err))
			} else {
				successes++
			}
		}
	}

	all = sources.Merge(all)
	all = severityCandidates(all, p.Findings, assetID, severity)
	if s.Sources["cve"] && ctx.Err() == nil {
		_ = workflow.Wait(ctx)
	}

	if s.Sources["cve"] && ctx.Err() == nil {
		tracker.start("cve")
		ids := map[string]bool{}
		for _, f := range all {
			if strings.HasPrefix(f.ID, "CVE-") {
				ids[f.ID] = true
			}
		}

		processed := 0
		failed := 0
		type record struct {
			title string
			refs  []string
			err   error
		}

		cache := map[string]record{}
		for i := range all {
			if workflow.Wait(ctx) != nil {
				break
			}

			f := &all[i]
			if !strings.HasPrefix(f.ID, "CVE-") {
				continue
			}

			r, ok := cache[f.ID]
			if !ok {
				tracker.progress("cve", model.SyncProgress{Phase: "records", Item: f.ID, Processed: processed, Total: len(ids)})
				r.title, r.refs, r.err = e.Sources.CVE(ctx, f.ID, s, report("cve"))
				cache[f.ID] = r
				processed++
				tracker.progress("cve", model.SyncProgress{Phase: "records", Item: f.ID, Processed: processed, Total: len(ids)})
			}

			if r.err != nil {
				if !ok {
					failed++
					tracker.event("cve", "failed", f.ID+": "+r.err.Error())
					warnings = append(warnings, fmt.Sprintf("CVE · %s: %v", f.ID, r.err))
				}
				continue
			}

			f.Sources = sources.Unique(f.Sources, "CVE")
			f.References = sources.Unique(f.References, r.refs...)
			if r.title != "" {
				f.Title = r.title
			}
		}

		tracker.progress("cve", model.SyncProgress{Phase: "page", Processed: processed, Total: len(ids), Found: processed - failed})
		var cveErr error
		if failed > 0 {
			cveErr = fmt.Errorf("%d CVE records could not be retrieved", failed)
		}

		if ctx.Err() != nil {
			cveErr = ctx.Err()
		}

		tracker.finish("cve", processed-failed, cveErr)
	}

	scannerSkipReason := ""
	switch {
	case assetID != "":
		scannerSkipReason = "scanner_skipped_component"
	case !p.ScanCode:
		scannerSkipReason = "scanner_skipped_disabled"
	case mode == "local":
		scannerSkipReason = "scanner_skipped_cache"
		warnings = append(warnings, "Cache-only assessment skips repository scanners; run normal sync for complete scanner coverage.")
	case workflow.Wait(ctx) != nil:
		scannerSkipReason = "scanner_skipped_ended"
	}

	tracker.scannerSetup(p, scanner.EnabledTools(s.Scanners), scannerSkipReason)

	if scannerSkipReason == "" {
		tracker.start("scanner")
		scannersCompleted := 0
		items, warns := scanner.Scan(ctx, p, s, filepath.Dir(e.Store.Paths().Database), func(event scanner.ScanEvent) {
			if event.Phase == "scanner_completed" {
				scannersCompleted++
			}
			tracker.scannerEvent(event)
		})
		var scanErr error

		if len(warns) > 0 {
			scanErr = fmt.Errorf("%s", strings.Join(warns, "; "))
		}

		if ctx.Err() != nil {
			scanErr = ctx.Err()
		}

		tracker.finish("scanner", severityCount(items, severity), scanErr)
		all = append(all, items...)
		warnings = append(warnings, warns...)
		successes += scannersCompleted
	}

	// Fence controls against the final commit: a stop accepted before this lock
	// must discard unsaved results; a completed commit cannot be stopped later.
	for {
		_ = workflow.Wait(ctx)
		e.mu.Lock()
		if !workflow.Paused(ctx) || ctx.Err() != nil {
			break
		}

		e.mu.Unlock()
	}

	defer e.mu.Unlock()
	defer delete(e.active, p.ID)
	status := "complete"
	previous := p.Findings
	var inventoryFindings []model.Finding

	if mode == codeScanMode {
		previous = nil
		for _, finding := range p.Findings {
			if finding.Match == "scanner" {
				previous = append(previous, finding)
			} else {
				inventoryFindings = append(inventoryFindings, finding)
			}
		}
	}

	all = severityCandidates(sources.Merge(all), previous, assetID, severity)
	if len(warnings) > 0 {
		status = "partial"
		if successes == 0 && !usedData {
			status = "failed"
		}
		all = appendPrior(all, previous, assetID, severity)
	}

	if ctx.Err() != nil {
		warnings = append(warnings, "Assessment timed out or application stopped.")
		status = "interrupted"
		all = appendPrior(all, previous, assetID, severity)
	}

	all = sources.Merge(all)
	runCount := severityCount(all, severity)
	var runSeverityCounts map[string]int
	if mode == codeScanMode && status == "complete" {
		runSeverityCounts = findingSeverityCounts(all)
	}

	all = retainOutsideScope(all, previous, assetID, severity)
	if len(inventoryFindings) > 0 {
		all = sources.Merge(append(all, inventoryFindings...))
	}

	if control.Stopped() {
		status = "stopped"
		all = p.Findings
		runCount = 0
		runSeverityCounts = nil
		warnings = []string{"Assessment stopped by user. Unsaved assessment results were discarded; previous findings were kept."}
	}

	fullAssessmentComplete := status == "complete" && assetID == "" && severity == "" && mode != codeScanMode
	tracker.start("save")
	err := e.Store.Update(func(st *model.State) error {
		for i := range st.Projects {
			current := &st.Projects[i]
			if current.ID != p.ID {
				continue
			}

			current.Syncing = false
			current.Findings = all
			if fullAssessmentComplete {
				current.LastSync = time.Now()
				current.AssessedRevision = p.Revision
			}

			for j := range current.Runs {
				r := &current.Runs[j]
				if r.ID == runID {
					finishPause(r)
					r.Status = status
					r.FinishedAt = time.Now()
					r.Warnings = warnings
					r.Count = runCount
					r.SeverityCounts = runSeverityCounts
					if fullAssessmentComplete {
						current.DataCheckedAt = r.DataCheckedAt
					}

					if status == "interrupted" {
						interruptSteps(r)
					}

					if status == "stopped" {
						stopSteps(r)
					}

					for k := range r.Steps {
						step := &r.Steps[k]
						if step.ID == "save" {
							step.Status = "complete"
							step.FinishedAt = time.Now()
							step.Progress.Phase = "saving"
							step.Progress.Found = runCount
						}
					}

					addLog(r, "save", "completed", "")
					addLog(r, "", "run_finished", status)
				}
			}

			return nil
		}

		return nil
	})

	if err != nil {
		log.Printf("Could not persist assessment for project %s: %v", p.ID, err)
	}
}

func appendPrior(findings, prior []model.Finding, assetID, severity string) []model.Finding {
	for _, f := range prior {
		if inScope(f, assetID, severity) {
			findings = append(findings, f)
		}
	}
	return findings
}
