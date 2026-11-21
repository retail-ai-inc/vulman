package engine

import (
	"slices"
	"strings"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/osvdb"
)

func OSVEcosystems(st model.State) []string {
	if st.Settings.OSVEcosystems != nil {
		return st.Settings.OSVEcosystems
	}

	var selected []string
	for _, project := range st.Projects {
		for _, asset := range project.Assets {
			if ecosystem, err := osvdb.Ecosystem(asset.Ecosystem); err == nil && !slices.Contains(selected, ecosystem) {
				selected = append(selected, ecosystem)
			}
		}
	}

	slices.Sort(selected)
	return selected
}

func (e *Engine) UpdateOSVDatabase() error {
	return e.updateOSV(false)
}

func (e *Engine) RebuildOSVDatabase() error {
	return e.updateOSV(true)
}

func (e *Engine) updateOSV(rebuild bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return apperror.New("application_is_stopping", "application is stopping")
	}

	st, err := e.Store.Read()
	if err != nil {
		return err
	}

	if !st.Settings.Sources["osv"] || strings.TrimRight(st.Settings.OSVURL, "/") != model.DefaultOSVURL {
		return apperror.New("osv_default_endpoint_required", "enable the default OSV endpoint to update the local catalogue")
	}

	e.lastOSVAttempt = time.Now()
	if rebuild {
		return e.OSV.Rebuild(e.ctx, OSVEcosystems(st))
	}

	return e.OSV.Start(e.ctx, OSVEcosystems(st))
}

func (e *Engine) updateOSVDue(now time.Time, st model.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || now.Sub(e.lastOSVAttempt) < 15*time.Minute || !st.Settings.Sources["osv"] || strings.TrimRight(st.Settings.OSVURL, "/") != model.DefaultOSVURL {
		return
	}

	schedule := st.Settings.OSVUpdateSchedule
	if schedule == "" {
		schedule = "daily"
	}

	interval := model.Interval(schedule)
	if interval == 0 {
		return
	}

	stats, err := e.OSV.Stats()
	if err != nil || stats.Running {
		return
	}

	selected := OSVEcosystems(st)
	due := stats.Resumable
	for _, ecosystem := range selected {
		for _, item := range stats.Ecosystems {
			if item.Ecosystem == ecosystem && item.Initialized && now.Sub(item.CheckedAt) >= interval {
				due = true
			}
		}
	}

	if !due || len(selected) == 0 || stats.Resumable && stats.Phase != "failed" && !e.lastOSVAttempt.IsZero() && now.Sub(e.lastOSVAttempt) < interval {
		return
	}

	// Initialization, including adding another ecosystem, stays explicit.
	if !stats.Resumable {
		selected = slices.DeleteFunc(slices.Clone(selected), func(ecosystem string) bool {
			for _, item := range stats.Ecosystems {
				if item.Ecosystem == ecosystem && item.Initialized {
					return false
				}
			}

			return true
		})
	}

	e.lastOSVAttempt = now
	_ = e.OSV.Start(e.ctx, selected)
}
