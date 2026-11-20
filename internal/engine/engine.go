package engine

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/cvedb"
	"vulman/internal/model"
	"vulman/internal/nvddb"
	"vulman/internal/osvdb"
	"vulman/internal/scanner"
	"vulman/internal/sources"
	"vulman/internal/store"
	"vulman/internal/workflow"
)

type Engine struct {
	OSV            *osvdb.Updater
	lastOSVAttempt time.Time
	NVD            *nvddb.Updater
	lastNVDAttempt time.Time
	CVE            *cvedb.Updater
	cveClose       sync.Once
	lastCVEAttempt time.Time
	Store          *store.Store
	Sources        *sources.Client
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	mu             sync.Mutex
	closed         bool
	active         map[string]activeRun
}

type activeRun struct {
	id      string
	control *workflow.Control
	queued  *queuedSync
}

var ErrAssetNotFound = apperror.New("tech_stack_component_not_found", "tech stack component not found")
var ErrInvalidMode = apperror.New("invalid_sync_mode", "invalid assessment mode")
var ErrInvalidSeverity = apperror.New("invalid_sync_severity", "invalid assessment severity")

const codeScanMode = "code"

func New(s *store.Store) (*Engine, error) {
	catalogue, err := s.OpenCVEDatabase()
	if err != nil {
		return nil, apperror.Newf("open_cve", "could not open the local CVE catalogue: %w", err)
	}
	nvd, err := s.OpenNVDDatabase()
	if err != nil {
		return nil, errors.Join(apperror.Newf("open_nvd", "could not open the local NVD catalogue: %w", err), catalogue.Close())
	}
	ctx, cancel := context.WithCancel(context.Background())
	osv, err := s.OpenOSVDatabase()
	if err != nil {
		cancel()
		return nil, errors.Join(apperror.Newf("open_osv", "could not open the local OSV catalogue: %w", err), catalogue.Close(), nvd.Close())
	}

	e := &Engine{Store: s, Sources: sources.New(s), ctx: ctx, cancel: cancel, active: map[string]activeRun{}}
	e.OSV = osvdb.NewUpdater(osv)
	e.Sources.LocalOSV = osv
	e.CVE = cvedb.NewUpdater(catalogue)
	e.NVD = nvddb.NewUpdater(nvd)
	e.Sources.LocalNVD = nvd
	e.Sources.LocalCVE = catalogue
	err = s.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			p.MarkOutdatedComponents()
			p.Syncing = false
			for j := range p.Runs {
				if activeStatus(p.Runs[j].Status) {
					queued := p.Runs[j].Status == "queued" || p.Runs[j].Status == "waiting_databases"
					finishPause(&p.Runs[j])
					p.Runs[j].Status = "interrupted"
					p.Runs[j].FinishedAt = time.Now()
					run := &p.Runs[j]
					for len(run.WarningMessages) < len(run.Warnings) {
						run.WarningMessages = append(run.WarningMessages, apperror.Message{Code: "legacy", Fallback: run.Warnings[len(run.WarningMessages)]})
					}
					message := apperror.New("assessment_startup_interrupted", "Application stopped before assessment finished.").PublicMessage()
					run.Warnings = append(run.Warnings, message.English())
					run.WarningMessages = append(run.WarningMessages, message)
					interruptSteps(&p.Runs[j])
					if queued {
						addLog(&p.Runs[j], "", "queue_interrupted", "")
					} else {
						addLog(&p.Runs[j], "", "interrupted", "")
					}
				}
			}
		}

		return nil
	})

	if err != nil {
		cancel()
		return nil, errors.Join(err, e.CVE.Close(), e.NVD.Close(), e.OSV.Close())
	}

	e.wg.Add(1)
	go e.loop()
	return e, nil
}

func (e *Engine) Close() {
	e.mu.Lock()
	e.closed = true
	e.cancel()
	e.mu.Unlock()
	e.wg.Wait()
	e.cveClose.Do(func() {
		if err := e.OSV.Close(); err != nil {
			log.Printf("Closing OSV catalogue: %v", err)
		}

		if err := e.NVD.Close(); err != nil {
			log.Printf("Closing NVD catalogue: %v", err)
		}
		if err := e.CVE.Close(); err != nil {
			log.Printf("Closing CVE catalogue: %v", err)
		}
	})
}

func (e *Engine) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	if st, err := e.Store.Read(); err == nil {
		e.updateCVEDue(time.Now(), st.Settings)
		e.updateNVDDue(time.Now(), st.Settings)
		e.updateOSVDue(time.Now(), st)
	}
	for {
		select {
		case <-e.ctx.Done():
			return
		case now := <-ticker.C:
			st, err := e.Store.Read()
			if err != nil {
				continue
			}
			e.updateCVEDue(now, st.Settings)
			e.updateNVDDue(now, st.Settings)
			e.updateOSVDue(now, st)
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
	return e.StartScoped(id, trigger, assetID, "", mode, severity)
}

// StartScoped assesses inventory, or scans one registered repository in isolation.
func (e *Engine) StartScoped(id, trigger, assetID, scanTarget, mode, severity string) error {
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

	if scanTarget != "" {
		if assetID != "" || mode != "auto" {
			return apperror.New("repository_scan_scope_invalid", "Select either a component or a repository. Repository scans use normal assessment mode.")
		}

		mode = codeScanMode
	}

	return e.startRun(id, trigger, assetID, scanTarget, mode, severity)
}

func (e *Engine) StartCodeScan(id string) error {
	return e.startRun(id, "manual", "", "", codeScanMode, "")
}

func (e *Engine) startRun(id, trigger, assetID, scanTarget, mode, severity string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return apperror.New("application_is_stopping", "application is stopping")
	}

	var snapshot model.Project
	var settings model.Settings
	var queued *queuedSync
	runID := model.NewID()

	err := e.Store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != id {
				continue
			}

			if p.Syncing {
				return apperror.New("project_is_already_syncing", "an assessment is already running for this project")
			}

			scanProject, ok := projectForScanTarget(*p, scanTarget)
			if !ok {
				return apperror.New("scan_repository_not_registered", "The selected repository is no longer registered in this project.")
			}

			settings = st.Settings
			if mode == codeScanMode {
				if !p.ScanCode || (p.LocalPath == "" && len(p.Repositories()) == 0) {
					return apperror.New("enable_code_scanning_and_set_a_repository_in_edit_project", "enable code scanning and set a repository in Edit project")
				}
				if len(scanner.EnabledTools(settings.Scanners)) == 0 {
					return apperror.New("enable_a_code_scanner_in_configuration", "enable a code scanner in Configuration")
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
			run.ScanTarget = scanTarget
			if scanTarget != "" && scanTarget != "local" {
				run.ScanRepository = scanner.RepositoryLabel(scanProject.Repositories()[0])
			}

			waits, err := e.databaseDependenciesForAsset(*p, settings, mode, assetID)
			if err != nil {
				return err
			}

			if len(waits) > 0 {
				queued = &queuedSync{waits: waits}
				run.Status = "queued"
				run.PausedAt = now
				run.DatabaseWaits = waits
				addLog(&run, "", "sync_queued", "")
			} else {
				addLog(&run, "", "run_started", assetName)
			}

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

		return apperror.New("project_not_found", "project not found")
	})

	if err != nil {
		return err
	}

	e.wg.Add(1)
	control := workflow.New(e.ctx, 20*time.Minute, func() { e.acknowledgePause(id, runID) })
	if queued != nil {
		control.Pause()
	}

	e.active[id] = activeRun{id: runID, control: control, queued: queued}
	go func() {
		defer e.wg.Done()
		defer control.Close()
		if queued != nil {
			var ready bool
			mode, ready = e.awaitDatabases(id, runID, queued, control, mode)
			if !ready {
				return
			}
		}

		e.assess(snapshot, settings, runID, assetID, scanTarget, mode, severity, control)
	}()

	return nil
}

func (e *Engine) assess(p model.Project, s model.Settings, runID, assetID, scanTarget, mode, severity string, control *workflow.Control) {
	tracker := newTracker(e.Store, p.ID, runID)
	s = model.EffectiveSettings(s)
	ctx := sources.WithMode(control.Context(), mode)
	all := []model.Finding{}
	warnings := []string{}
	warningMessages := []apperror.Message{}
	addWarning := func(err error) {
		message := apperror.Public(err)
		warnings = append(warnings, message.English())
		warningMessages = append(warningMessages, *message)
	}
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
		addWarning(apperror.New("assessment_no_components", "No components registered. Add inventory before assessing this project."))
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
				addWarning(apperror.Newf("source_component", "%s · %s: %w", "NVD", a.Name, err))
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
				addWarning(apperror.Newf("source_component", "%s · %s: %w", "OSV", a.Name, err))
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
					tracker.errorEvent("cve", "failed", apperror.Newf("context", "%s: %w", f.ID, r.err))
					addWarning(apperror.Newf("source_component", "%s · %s: %w", "CVE", f.ID, r.err))
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
			cveErr = apperror.Newf("cve_records_failed", "%d CVE records could not be retrieved", failed)
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
		addWarning(apperror.New("assessment_scanners_skipped", "Reassessing from local data skips repository scanners; run a normal assessment for complete scanner coverage."))
	case workflow.Wait(ctx) != nil:
		scannerSkipReason = "scanner_skipped_ended"
	}

	// The target was validated against this immutable snapshot before starting.
	scanProject, _ := projectForScanTarget(p, scanTarget)
	tracker.scannerSetup(scanProject, scanner.EnabledTools(s.Scanners), scannerSkipReason)

	if scannerSkipReason == "" {
		tracker.start("scanner")
		scannersCompleted := 0
		items, warns := scanner.ScanDetailed(ctx, scanProject, s, filepath.Dir(e.Store.Paths().Database), func(event scanner.ScanEvent) {
			if event.Phase == "scanner_completed" {
				scannersCompleted++
			}
			tracker.scannerEvent(event)
		})
		var scanErr error

		if len(warns) > 0 {
			scanErr = errors.Join(warns...)
		}

		if ctx.Err() != nil {
			scanErr = ctx.Err()
		}

		tracker.finish("scanner", severityCount(items, severity), scanErr)
		all = append(all, items...)
		for _, warning := range warns {
			addWarning(warning)
		}
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
	var preservedFindings []model.Finding

	if mode == codeScanMode {
		previous = nil
		for _, finding := range p.Findings {
			if finding.Match == "scanner" && (scanTarget == "" || findingInScanTarget(finding, p, scanTarget)) {
				previous = append(previous, finding)
			} else {
				preservedFindings = append(preservedFindings, finding)
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
		addWarning(apperror.New("assessment_interrupted", "Assessment timed out or application stopped."))
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
	if len(preservedFindings) > 0 {
		all = sources.Merge(append(all, preservedFindings...))
	}

	if control.Stopped() {
		status = "stopped"
		all = p.Findings
		runCount = 0
		runSeverityCounts = nil
		warnings = []string{}
		warningMessages = []apperror.Message{}
		addWarning(apperror.New("assessment_stopped", "Assessment stopped by user. Unsaved assessment results were discarded; previous findings were kept."))
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
			if status == "complete" && severity == "" && mode != codeScanMode && current.Revision == p.Revision && (s.Sources["nvd"] || s.Sources["osv"]) {
				for k := range current.Assets {
					if assetID == "" || current.Assets[k].ID == assetID {
						current.Assets[k].NeedsAssessment = false
					}
				}
			}

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
					r.WarningMessages = warningMessages
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
