package sources

import (
	"context"
	"errors"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/workflow"
)

func (c *Client) localOSV(ctx context.Context, a model.Asset, s model.Settings, reports []func(model.SyncProgress)) ([]model.Finding, error) {
	if err := workflow.Wait(ctx); err != nil {
		return nil, err
	}

	result, err := c.LocalOSV.Query(ctx, a.Ecosystem, a.Name, a.Version)
	if err != nil {
		return c.query(ctx, "osv", a, s, reports)
	}

	items := make([]model.Finding, 0, len(result.Records))
	for _, record := range result.Records {
		finding := osvFinding(record, a)
		if result.Uncertain {
			finding.Match = "review"
		}

		items = append(items, finding)
	}

	if result.Uncertain && modeFor(ctx) != "local" {
		notifyIssue(reports, apperror.New("osv_api_validation", "OSV API validation is needed for an unsupported version or commit range"))
		remote, err := c.query(ctx, "osv", a, s, reports)
		if err == nil {
			return remote, nil
		}

		return Merge(append(items, remote...)), err
	}

	schedule := s.OSVUpdateSchedule
	if schedule == "" || schedule == "off" {
		schedule = "daily"
	}

	age := time.Since(result.CheckedAt)
	stale := age < 0 || age > model.Interval(schedule)+time.Hour
	var warning error
	if stale {
		warning = apperror.New("local_osv_data_is_stale_update_the_osv_database", "local OSV data is stale; update the OSV database")
	}

	if result.Uncertain {
		warning = errors.Join(warning, apperror.New("osv_local_match_uncertain", "local OSV version matching needs API validation; this assessment is incomplete"))
	}

	phase, status := "cached", "cache"
	if warning != nil {
		phase, status = "stale_cache", "stale"
	}

	notify(reports, model.SyncProgress{Phase: phase, CacheStatus: status, CheckedAt: result.CheckedAt})
	notify(reports, model.SyncProgress{Phase: "page", Processed: len(items), Total: len(items), Found: len(items), CacheStatus: status, CheckedAt: result.CheckedAt})
	return items, warning
}
