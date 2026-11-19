package engine

import (
	"errors"
	"strings"
	"time"

	"vulman/internal/model"
)

func (e *Engine) UpdateNVDDatabase() error  { return e.updateNVD(false) }
func (e *Engine) RebuildNVDDatabase() error { return e.updateNVD(true) }
func (e *Engine) updateNVD(rebuild bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return errors.New("application is stopping")
	}
	st, err := e.Store.Read()
	if err != nil {
		return err
	}
	if !st.Settings.Sources["nvd"] || strings.TrimRight(st.Settings.NVDURL, "/") != model.DefaultNVDURL {
		return errors.New("enable the default NVD endpoint to update the local catalogue")
	}
	e.lastNVDAttempt = time.Now()
	if rebuild {
		return e.NVD.Rebuild(e.ctx)
	}
	return e.NVD.Start(e.ctx)
}
func (e *Engine) updateNVDDue(now time.Time, settings model.Settings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed || now.Sub(e.lastNVDAttempt) < 15*time.Minute {
		return
	}
	if !settings.Sources["nvd"] || strings.TrimRight(settings.NVDURL, "/") != model.DefaultNVDURL {
		return
	}
	interval := model.NVDInterval(settings.NVDUpdateSchedule)
	if interval == 0 {
		return
	}
	stats, err := e.NVD.Stats()
	if err != nil || stats.Running || (!stats.Initialized && !stats.Resumable) || (!stats.Resumable && now.Sub(stats.CheckedAt) < interval) {
		return
	}
	if stats.Resumable && stats.Phase != "failed" && !e.lastNVDAttempt.IsZero() && now.Sub(e.lastNVDAttempt) < interval {
		return
	}
	e.lastNVDAttempt = now
	_ = e.NVD.Start(e.ctx)
}
