package engine

import (
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/store"
)

var ErrRunNotActive = store.ErrRunNotFound
var ErrInvalidControl = apperror.New("invalid_workflow_action", "invalid workflow action")

func activeStatus(status string) bool {
	return status == "running" || status == "pausing" || status == "paused" || status == "stopping" || status == "queued" || status == "waiting_databases"
}

func finishPause(run *model.Run) {
	if !run.PausedAt.IsZero() {
		run.PausedSeconds += time.Since(run.PausedAt).Seconds()
		run.PausedAt = time.Time{}
	}
}

func (e *Engine) acknowledgePause(projectID, runID string) {
	tracker := newTracker(e.Store, projectID, runID)
	tracker.update(func(r *model.Run) {
		if r.Status == "pausing" {
			r.Status = "paused"
			addLog(r, "", "run_paused", "")
		}
	})
}

// Control addresses an exact run so a stale tab cannot stop a newer assessment.
func (e *Engine) Control(projectID, runID, action string) error {
	if action != "pause" && action != "resume" && action != "stop" && action != "cancel-queued" && action != "retry-databases" && action != "use-available" {
		return ErrInvalidControl
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	a, ok := e.active[projectID]
	if !ok || a.id != runID || e.closed || a.control.Context().Err() != nil {
		return ErrRunNotActive
	}

	if a.queued != nil {
		return e.controlQueued(projectID, a, action)
	}

	if action == "cancel-queued" || action == "retry-databases" || action == "use-available" {
		return ErrRunNotActive
	}

	err := e.Store.UpdateRun(projectID, runID, func(project *store.RunProject, r *model.Run) error {
		if !project.Syncing {
			return ErrRunNotActive
		}
		switch action {
		case "pause":
			if r.Status != "running" {
				return apperror.New("only_a_running_workflow_can_be_paused", "only a running workflow can be paused")
			}

			r.Status = "pausing"
			r.PausedAt = time.Now()
			addLog(r, "", "pause_requested", "")
		case "resume":
			if r.Status != "paused" && r.Status != "pausing" {
				return apperror.New("only_a_paused_workflow_can_be_resumed", "only a paused workflow can be resumed")
			}

			finishPause(r)
			r.Status = "running"
			addLog(r, "", "run_resumed", "")
		case "stop":
			if !activeStatus(r.Status) || r.Status == "stopping" {
				return ErrRunNotActive
			}

			r.Status = "stopping"
			addLog(r, "", "stop_requested", "")
		}
		return nil
	})

	if err != nil {
		return err
	}

	switch action {
	case "pause":
		a.control.Pause()
	case "resume":
		a.control.Resume()
	case "stop":
		a.control.Stop()
	}
	return nil
}

func stopSteps(r *model.Run) {
	interruptScannerJobs(r)
	for i := range r.Steps {
		s := &r.Steps[i]
		switch s.Status {
		case "pending":
			s.Status = "skipped"
			s.FinishedAt = time.Now()
		case "running", "interrupted":
			s.Status = "stopped"
			s.FinishedAt = time.Now()
		}
	}
}
