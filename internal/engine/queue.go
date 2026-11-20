package engine

import (
	"errors"
	"log"
	"reflect"
	"slices"
	"strings"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/osvdb"
	"vulman/internal/workflow"
)

type queuedSync struct {
	waits        []model.DatabaseWait
	useAvailable bool
}

func (e *Engine) databaseStatus(source string) (model.DatabaseWait, error) {
	var running, initialized bool
	var phase, detail string
	var message *apperror.Message

	switch source {
	case "nvd":
		stats, err := e.NVD.Stats()
		if err != nil {
			return model.DatabaseWait{}, err
		}

		running, initialized, phase, detail = stats.Running, stats.Initialized, stats.Phase, stats.Error
		message = stats.ErrorMessage
	case "cve":
		stats, err := e.CVE.Stats()
		if err != nil {
			return model.DatabaseWait{}, err
		}

		running, initialized, phase, detail = stats.Running, stats.Initialized, stats.Phase, stats.Error
		message = stats.ErrorMessage
	default:
		ecosystem, ok := strings.CutPrefix(source, "osv:")
		if !ok {
			return model.DatabaseWait{}, apperror.New("unknown_database_dependency", "unknown database dependency")
		}

		stats, err := e.OSV.Stats()
		if err != nil {
			return model.DatabaseWait{}, err
		}

		for _, item := range stats.Ecosystems {
			if item.Ecosystem == ecosystem {
				running, initialized, phase, detail = item.Running, item.Initialized, item.Phase, item.Error
				message = item.ErrorMessage
			}
		}
	}

	status := "failed"
	if running {
		status = "updating"
	} else if phase == "complete" && initialized && detail == "" {
		status = "complete"
	} else if phase == "interrupted" {
		status = "interrupted"
	}

	return model.DatabaseWait{Source: source, Status: status, Detail: detail, Message: message}, nil
}

// Only updates already running for the selected assessment's sources delay it.
// A standalone scan never depends on the local vulnerability catalogues.
func (e *Engine) databaseDependencies(p model.Project, s model.Settings, mode string) ([]model.DatabaseWait, error) {
	return e.databaseDependenciesForAsset(p, s, mode, "")
}

func (e *Engine) databaseDependenciesForAsset(p model.Project, s model.Settings, mode, assetID string) ([]model.DatabaseWait, error) {
	if mode == codeScanMode || len(p.Assets) == 0 {
		return nil, nil
	}

	var waits []model.DatabaseWait
	for _, source := range []string{"nvd", "cve"} {
		endpoint, defaultEndpoint := s.NVDURL, model.DefaultNVDURL
		if source == "cve" {
			endpoint, defaultEndpoint = s.CVEURL, model.DefaultCVEURL
		}

		if !s.Sources[source] || strings.TrimRight(endpoint, "/") != defaultEndpoint {
			continue
		}

		status, err := e.databaseStatus(source)
		if err != nil {
			return nil, apperror.Newf("read_update_status", "could not read %s update status: %w", source, err)
		}

		if status.Status == "updating" {
			waits = append(waits, status)
		}
	}

	if s.Sources["osv"] && strings.TrimRight(s.OSVURL, "/") == model.DefaultOSVURL {
		seen := map[string]bool{}
		for _, asset := range p.Assets {
			if assetID != "" && asset.ID != assetID {
				continue
			}

			ecosystem, err := osvdb.Ecosystem(asset.Ecosystem)
			if err != nil || seen[ecosystem] {
				continue
			}

			seen[ecosystem] = true
			status, err := e.databaseStatus("osv:" + ecosystem)
			if err != nil {
				return nil, err
			}

			if status.Status == "updating" {
				waits = append(waits, status)
			}
		}
	}

	return waits, nil
}

func (e *Engine) currentDatabaseWaits(q *queuedSync) ([]model.DatabaseWait, bool, bool) {
	waits := make([]model.DatabaseWait, 0, len(q.waits))
	ready, blocked := true, false

	for _, previous := range q.waits {
		status, err := e.databaseStatus(previous.Source)
		if err != nil {
			message := apperror.Public(err)
			status = model.DatabaseWait{Source: previous.Source, Status: "failed", Detail: message.English(), Message: message}
		}

		if status.Status != "complete" {
			ready = false
			blocked = blocked || status.Status != "updating"
		}

		waits = append(waits, status)
	}

	return waits, ready, blocked
}

func (e *Engine) awaitDatabases(projectID, runID string, q *queuedSync, control *workflow.Control, mode string) (string, bool) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		e.mu.Lock()
		if control.Context().Err() != nil || e.closed {
			e.finishQueued(projectID, runID, control.Stopped())
			e.mu.Unlock()
			return mode, false
		}

		waits, ready, blocked := e.currentDatabaseWaits(q)
		if q.useAvailable {
			mode, ready = "local", true
		}

		if ready || !reflect.DeepEqual(waits, q.waits) {
			err := e.persistQueueState(projectID, runID, waits, ready, blocked, mode, q.useAvailable)
			if err != nil {
				log.Printf("Could not update queued sync for project %s: %v", projectID, err)
			} else {
				q.waits = waits
				if ready {
					a := e.active[projectID]
					a.queued = nil
					e.active[projectID] = a
					control.Resume()
					e.mu.Unlock()
					return mode, true
				}
			}
		}

		e.mu.Unlock()

		select {
		case <-control.Context().Done():
		case <-ticker.C:
		}
	}
}

func (e *Engine) persistQueueState(projectID, runID string, waits []model.DatabaseWait, ready, blocked bool, mode string, useAvailable bool) error {
	return e.Store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != projectID {
				continue
			}

			for j := range p.Runs {
				r := &p.Runs[j]
				if r.ID != runID {
					continue
				}

				r.DatabaseWaits = waits
				if ready {
					finishPause(r)
					r.Status, r.Mode = "running", mode
					event := "databases_ready"
					if useAvailable {
						event = "queue_use_available"
					}

					addLog(r, "", event, "")
					addLog(r, "", "run_started", r.AssetName)
					if interval := model.Interval(p.Schedule); interval > 0 && r.AssetID == "" && r.Severity == "" && mode != "local" {
						p.NextRun = time.Now().Add(interval)
					}
				} else {
					r.Status = "queued"
					if blocked {
						r.Status = "waiting_databases"
					}

					for _, wait := range waits {
						addLog(r, "", "database_wait_"+wait.Status, wait.Source)
					}
				}

				return nil
			}
		}

		return ErrRunNotActive
	})
}

// Cancel a queued request without invoking assessment or touching its findings.
func (e *Engine) finishQueued(projectID, runID string, stopped bool) {
	err := e.Store.Update(func(st *model.State) error {
		for i := range st.Projects {
			p := &st.Projects[i]
			if p.ID != projectID {
				continue
			}

			for j := range p.Runs {
				r := &p.Runs[j]
				if r.ID != runID {
					continue
				}

				finishPause(r)
				r.FinishedAt = time.Now()
				r.Status = "interrupted"
				interruptSteps(r)
				if stopped {
					r.Status = "stopped"
					addLog(r, "", "queue_cancelled", "")
				} else {
					addLog(r, "", "queue_interrupted", "")
				}

				p.Syncing = false
				return nil
			}
		}

		return ErrRunNotActive
	})
	if err != nil {
		log.Printf("Could not finish queued sync for project %s: %v", projectID, err)
	}

	delete(e.active, projectID)
}

// Called with the engine lock held, fencing every action against auto-start.
func (e *Engine) controlQueued(projectID string, a activeRun, action string) error {
	switch action {
	case "cancel-queued", "stop":
		a.control.Stop()
		return nil
	case "use-available":
		a.queued.useAvailable = true
		return nil
	case "retry-databases":
		waits, _, _ := e.currentDatabaseWaits(a.queued)
		st, err := e.Store.Read()
		if err != nil {
			return err
		}

		for _, wait := range waits {
			endpoint, defaultEndpoint := st.Settings.NVDURL, model.DefaultNVDURL
			source := wait.Source
			if wait.Source == "cve" {
				endpoint, defaultEndpoint = st.Settings.CVEURL, model.DefaultCVEURL
			}
			if strings.HasPrefix(wait.Source, "osv:") {
				source = "osv"
				endpoint, defaultEndpoint = st.Settings.OSVURL, model.DefaultOSVURL
				if !slices.Contains(OSVEcosystems(st), strings.TrimPrefix(wait.Source, "osv:")) {
					return apperror.New("queue_osv_selection_required", "select the required OSV ecosystem in Configuration before retrying, or use available data")
				}
			}

			if !st.Settings.Sources[source] || strings.TrimRight(endpoint, "/") != defaultEndpoint {
				return apperror.Newf("enable_default_source", "enable the default %s source in Configuration before retrying, or use available data", wait.Source)
			}
		}

		var failures []error

		for _, wait := range waits {
			if wait.Status == "complete" || wait.Status == "updating" {
				continue
			}

			var err error
			if wait.Source == "nvd" {
				e.lastNVDAttempt = time.Now()
				err = e.NVD.Start(e.ctx)
			} else if strings.HasPrefix(wait.Source, "osv:") {
				stats, readErr := e.OSV.Stats()
				if readErr != nil {
					err = readErr
				} else if !stats.Running {
					e.lastOSVAttempt = time.Now()
					err = e.OSV.Start(e.ctx, OSVEcosystems(st))
				}
			} else {
				e.lastCVEAttempt = time.Now()
				err = e.CVE.Start(e.ctx)
			}

			if err != nil {
				failures = append(failures, apperror.Newf("context", "%s: %w", wait.Source, err))
			}
		}

		return errors.Join(failures...)
	default:
		return apperror.Newf("queued_actions", "queued syncs can only be cancelled, retried, or started with available data for project %s", projectID)
	}
}
