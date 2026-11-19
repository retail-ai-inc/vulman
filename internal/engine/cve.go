package engine

import (
	"errors"
	"strings"
	"time"

	"vulman/internal/model"
)

func (e *Engine) UpdateCVEDatabase() error {
	return e.updateCVE(false)
}

func (e *Engine) RebuildCVEDatabase() error {
	return e.updateCVE(true)
}

func (e *Engine) updateCVE(rebuild bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("application is stopping")
	}
	st, err := e.Store.Read()
	if err != nil {
		return err
	}
	if !st.Settings.Sources["cve"] || strings.TrimRight(st.Settings.CVEURL, "/") != model.DefaultCVEURL {
		return errors.New("enable the default CVE Program endpoint to update the local catalogue")
	}
	e.lastCVEAttempt = time.Now()
	if rebuild {
		return e.CVE.Rebuild(e.ctx)
	}
	return e.CVE.Start(e.ctx)
}

func (e *Engine) updateCVEDue(now time.Time, settings model.Settings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || now.Sub(e.lastCVEAttempt) < 15*time.Minute {
		return
	}
	if !settings.Sources["cve"] || strings.TrimRight(settings.CVEURL, "/") != model.DefaultCVEURL {
		return
	}
	schedule := settings.CVEUpdateSchedule
	if schedule == "" {
		schedule = "daily"
	}
	interval := model.Interval(schedule)
	if interval == 0 {
		return
	}
	stats, err := e.CVE.Stats()
	// Full initialization is explicit because the first archive is large.
	if err != nil || stats.Running || (!stats.Initialized && !stats.Resumable) || (!stats.Resumable && now.Sub(stats.CheckedAt) < interval) {
		return
	}
	if stats.Resumable && stats.Phase != "failed" && !e.lastCVEAttempt.IsZero() && now.Sub(e.lastCVEAttempt) < interval {
		return
	}
	e.lastCVEAttempt = now
	_ = e.CVE.Start(e.ctx)
}
