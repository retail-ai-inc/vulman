package sources

import (
	"context"
	"errors"
	"strings"
	"time"

	"vulman/internal/model"
	"vulman/internal/workflow"
)

func (c *Client) localNVD(ctx context.Context, a model.Asset, s model.Settings, reports []func(model.SyncProgress)) ([]model.Finding, error) {
	if err := workflow.Wait(ctx); err != nil {
		return nil, err
	}
	result, err := c.LocalNVD.Query(ctx, a.Name, a.CPE)
	if err != nil {
		notify(reports, model.SyncProgress{Phase: "cache_error", Item: "Local NVD matching is unavailable; checking the query cache or NVD API"})
		return c.query(ctx, "nvd", a, s, reports)
	}
	match := "review"
	if a.CPE != "" && !result.Uncertain {
		match = "cpe"
	}
	items := make([]model.Finding, 0, len(result.Records))
	for _, record := range result.Records {
		items = append(items, nvdFinding(record, a, match))
	}
	if result.Uncertain && modeFor(ctx) != "local" {
		notify(reports, model.SyncProgress{Phase: "cache_error", Item: "NVD API validation is needed for a conditional, deprecated, or unsupported CPE match"})
		remote, err := c.query(ctx, "nvd", a, s, reports)
		if err == nil {
			return remote, nil
		}
		return Merge(append(items, remote...)), err
	}
	interval := model.NVDInterval(s.NVDUpdateSchedule)
	if interval == 0 {
		interval = 24 * time.Hour
	}
	age := time.Since(result.CheckedAt)
	stale := age < 0 || age > interval+2*time.Hour
	if !result.CPEAt.IsZero() {
		cpeAge := time.Since(result.CPEAt)
		stale = stale || cpeAge < 0 || cpeAge > 26*time.Hour
		if result.CPEAt.Before(result.CheckedAt) {
			result.CheckedAt = result.CPEAt
		}
	}
	var warning error
	if stale {
		warning = errors.New("local NVD data is stale; update the NVD database")
	}
	if result.Uncertain {
		warning = errors.Join(warning, errors.New("local CPE applicability needs review; use normal sync for NVD API validation"))
	}
	phase, status := "cached", "cache"
	if stale || result.Uncertain {
		phase, status = "stale_cache", "stale"
	}
	notify(reports, model.SyncProgress{Phase: phase, CacheStatus: status, CheckedAt: result.CheckedAt})
	notify(reports, model.SyncProgress{Phase: "page", Processed: len(items), Total: len(items), Found: len(items), CacheStatus: status, CheckedAt: result.CheckedAt})
	return items, warning
}

func (c *Client) usesLocalNVD(s model.Settings) bool {
	return c.LocalNVD != nil && strings.TrimRight(s.NVDURL, "/") == model.DefaultNVDURL
}
