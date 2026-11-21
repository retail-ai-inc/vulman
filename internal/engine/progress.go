package engine

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/store"
)

func planSteps(p model.Project, s model.Settings, assetID string) []model.SyncStep {
	steps := []model.SyncStep{}
	for _, a := range p.Assets {
		if assetID != "" && a.ID != assetID {
			continue
		}
		for _, kind := range []string{"nvd", "osv"} {
			if s.Sources[kind] {
				steps = append(steps, model.SyncStep{ID: kind + ":" + a.ID, Kind: kind, Component: a.Name + " " + a.Version, Status: "pending", Progress: model.SyncProgress{Phase: "queued"}})
			}
		}
	}

	if s.Sources["cve"] {
		steps = append(steps, model.SyncStep{ID: "cve", Kind: "cve", Status: "pending", Progress: model.SyncProgress{Phase: "queued"}})
	}

	if p.ScanCode && assetID == "" {
		steps = append(steps, model.SyncStep{ID: "scanner", Kind: "scanner", Status: "pending", Progress: model.SyncProgress{Phase: "queued"}})
	}

	return append(steps, model.SyncStep{ID: "save", Kind: "save", Status: "pending", Progress: model.SyncProgress{Phase: "queued"}})
}

func addLog(r *model.Run, stepID, event, detail string) *model.SyncLog {
	r.Logs = append(r.Logs, model.SyncLog{At: time.Now(), StepID: stepID, Event: event, Detail: detail})
	if len(r.Logs) > model.MaxSyncLogs {
		r.Logs = r.Logs[len(r.Logs)-model.MaxSyncLogs:]
	}

	return &r.Logs[len(r.Logs)-1]
}

func interruptSteps(r *model.Run) {
	interruptScannerJobs(r)
	for i := range r.Steps {
		step := &r.Steps[i]
		switch step.Status {
		case "running":
			step.Status = "interrupted"
			step.FinishedAt = time.Now()
		case "pending":
			step.Status = "skipped"
			step.FinishedAt = time.Now()
		}
	}
}

type runTracker struct {
	store            *store.Store
	projectID, runID string
	lastWrite        map[string]time.Time
	lastPhase        map[string]string
	cveMeta          model.SyncProgress
}

func newTracker(s *store.Store, projectID, runID string) *runTracker {
	return &runTracker{store: s, projectID: projectID, runID: runID, lastWrite: map[string]time.Time{}, lastPhase: map[string]string{}}
}

func (t *runTracker) update(fn func(*model.Run)) {
	err := t.store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != t.projectID {
				continue
			}

			for j := range p.Runs {
				r := &p.Runs[j]
				if r.ID == t.runID {
					fn(r)
					return nil
				}
			}
		}

		return nil
	})

	if err != nil {
		log.Printf("Could not persist sync progress for project %s: %v", t.projectID, err)
	}
}

func (t *runTracker) start(id string) {
	t.update(func(r *model.Run) {
		for i := range r.Steps {
			step := &r.Steps[i]

			if step.ID == id {
				step.Status = "running"
				step.StartedAt = time.Now()
				step.Progress.Phase = "request"
				switch step.Kind {
				case "save":
					step.Progress.Phase = "saving"
				case "cve":
					step.Progress.Phase = "records"
				case "scanner":
					step.Progress.Phase = "queued"
				}

				addLog(r, id, "started", step.Component)
				return
			}
		}
	})
}

func (t *runTracker) progress(id string, p model.SyncProgress) {
	if id == "cve" && p.CacheStatus != "" {
		meta := &t.cveMeta
		if meta.CheckedAt.IsZero() || p.CheckedAt.Before(meta.CheckedAt) {
			meta.CheckedAt = p.CheckedAt
		}

		if meta.CacheStatus == "" {
			meta.CacheStatus = p.CacheStatus
		} else if meta.CacheStatus == "stale" || p.CacheStatus == "stale" {
			meta.CacheStatus = "stale"
		} else if meta.CacheStatus != p.CacheStatus {
			meta.CacheStatus = "mixed"
		}

		return
	}

	if id == "cve" && p.Phase == "page" {
		p.CheckedAt = t.cveMeta.CheckedAt
		p.CacheStatus = t.cveMeta.CacheStatus
	}

	// Large CVE batches can report thousands of records. Persist at most twice
	// a second unless the phase changes or a database page is received.
	if t.lastPhase[id] == p.Phase && p.Phase != "page" && time.Since(t.lastWrite[id]) < 500*time.Millisecond {
		return
	}

	t.lastWrite[id] = time.Now()
	t.lastPhase[id] = p.Phase
	t.update(func(r *model.Run) {
		for i := range r.Steps {
			step := &r.Steps[i]
			if step.ID != id {
				continue
			}

			old := step.Progress
			if p.Phase == "waiting" || p.Phase == "request" || p.Phase == "retry" || p.Phase == "queued" || p.Phase == "shared" || (p.CacheStatus != "" && p.Phase != "page") {
				p.Processed = old.Processed
				p.Total = old.Total
				p.Found = old.Found
			}

			if p.CheckedAt.IsZero() {
				p.CheckedAt = old.CheckedAt
			} else {
				if r.DataCheckedAt.IsZero() || p.CheckedAt.Before(r.DataCheckedAt) {
					r.DataCheckedAt = p.CheckedAt
				}
				if !old.CheckedAt.IsZero() && old.CheckedAt.Before(p.CheckedAt) {
					p.CheckedAt = old.CheckedAt
				}
			}

			if p.CacheStatus == "" {
				p.CacheStatus = old.CacheStatus
			} else {
				if old.CacheStatus == "stale" || p.CacheStatus == "stale" {
					p.CacheStatus = "stale"
				} else if old.CacheStatus != "" && old.CacheStatus != p.CacheStatus {
					p.CacheStatus = "mixed"
				}
			}

			step.Progress = p
			switch p.Phase {
			case "waiting":
				addLog(r, id, "waiting", fmt.Sprintf("%d s", p.WaitSeconds))
			case "page":
				detail := fmt.Sprint(p.Processed)
				if p.Total > 0 {
					detail = fmt.Sprintf("%d / %d", p.Processed, p.Total)
				}
				addLog(r, id, "page", detail)
				if p.CacheStatus != "" {
					addLog(r, id, "cache_summary", p.CacheStatus)
				}
			case "retry", "shared", "cache_error":
				addLog(r, id, p.Phase, p.Item).Message = p.Message
			case "cached", "refreshed", "shared_result", "stale_cache":
				addLog(r, id, p.Phase, p.CheckedAt.Format(time.RFC3339))
			}

			return
		}
	})
}

func (t *runTracker) scannerSetup(p model.Project, tools []string, skipReason string) {
	t.update(func(r *model.Run) {
		addLog(r, "scanner", "scanner_configured", strings.Join(tools, ","))
		if skipReason == "" {
			if p.LocalPath != "" {
				r.ScanTargets = append(r.ScanTargets, "local")
			}
			for _, repository := range p.Repositories() {
				r.ScanTargets = append(r.ScanTargets, scanner.RemoteTargetKey(repository))
			}
			return
		}

		addLog(r, "scanner", skipReason, "")
		for i := range r.Steps {
			if r.Steps[i].Kind == "scanner" {
				r.Steps[i].Status = "skipped"
				r.Steps[i].FinishedAt = time.Now()
				r.Steps[i].Progress.Phase = skipReason
				return
			}
		}
	})
}

func (t *runTracker) scannerEvent(event scanner.ScanEvent) {
	// The complete plan and skipped-job reasons are saved in one transaction.
	// Tool execution still records live starts, results, failures, and cleanup.
	if event.Phase == "scanner_skipped" && event.Job != nil {
		return
	}

	t.update(func(r *model.Run) {
		if len(event.Plan) > 0 {
			r.ScannerJobSequence++
			for _, job := range event.Plan {
				job.UpdateSequence = r.ScannerJobSequence
				if len(r.ScannerJobs) < model.MaxScannerJobs {
					r.ScannerJobs = append(r.ScannerJobs, job)
				}
				if job.Status == "skipped" {
					entry := addLog(r, "scanner", "scanner_skipped", job.Tool)
					entry.Tool, entry.ScanPath, entry.ScanReason = job.Tool, job.Path, job.Reason
					entry.ScanTarget, entry.ScanRepository = event.Target, event.Repository
				}
			}
		}
		detail := event.Tool
		if event.Err != nil {
			if detail != "" {
				detail += " · "
			}
			detail += apperror.Public(event.Err).English()
		}

		entry := addLog(r, "scanner", event.Phase, detail)
		entry.Message = apperror.Public(event.Err)
		entry.Tool = event.Tool
		entry.ScanTarget = event.Target
		entry.ScanRepository = event.Repository
		entry.ScanPath = event.Path
		if event.Job != nil {
			r.ScannerJobSequence++
			updated := *event.Job
			updated.UpdateSequence = r.ScannerJobSequence
			if event.Phase == "scanner_completed" {
				count := event.Found
				updated.Findings = &count
			}
			entry.ScanReason = event.Job.Reason
			found := false
			for i, job := range r.ScannerJobs {
				if job.Target == event.Job.Target && job.Tool == event.Job.Tool && job.Path == event.Job.Path {
					r.ScannerJobs[i] = updated
					found = true
					break
				}
			}
			if !found && len(r.ScannerJobs) < model.MaxScannerJobs {
				r.ScannerJobs = append(r.ScannerJobs, updated)
			}
		}

		if event.Phase == "scanner_completed" {
			entry.Findings = &event.Found
			r.ScannersCompleted++
		}

		for i := range r.Steps {
			step := &r.Steps[i]
			if step.Kind != "scanner" {
				continue
			}
			switch event.Phase {
			case "clone", "clone_auth", "scanning":
				step.Progress.Phase = event.Phase
				step.Progress.Item = event.Tool
				step.Progress.ScanTarget = event.Target
				step.Progress.ScanRepository = event.Repository
			case "scanner_completed":
				step.Progress.Found += event.Found
			}
			return
		}
	})
}

func (t *runTracker) errorEvent(id, event string, err error) {
	t.update(func(r *model.Run) {
		message := apperror.Public(err)
		addLog(r, id, event, message.English()).Message = message
	})
}

func (t *runTracker) finish(id string, found int, err error) {
	t.update(func(r *model.Run) {
		for i := range r.Steps {
			step := &r.Steps[i]
			if step.ID != id {
				continue
			}

			step.FinishedAt = time.Now()
			step.Progress.Found = found
			step.Progress.WaitSeconds = 0

			if err != nil {
				step.Status = "failed"
				event := "failed"

				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					step.Status = "interrupted"
					event = "interrupted"
				}
				message := apperror.Public(err)
				addLog(r, id, event, message.English()).Message = message
			} else {
				step.Status = "complete"
				addLog(r, id, "completed", step.Component)
			}

			return
		}
	})
}

func interruptScannerJobs(r *model.Run) {
	sequence := r.ScannerJobSequence + 1
	for i := range r.ScannerJobs {
		job := &r.ScannerJobs[i]
		if job.Status == "running" || job.Status == "planned" {
			job.Status = "interrupted"
			job.Reason = "interrupted"
			job.UpdateSequence = sequence
			r.ScannerJobSequence = sequence
		}
	}
}
