package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"vulman/internal/cvedb"
	"vulman/internal/model"
	"vulman/internal/store"
	"vulman/internal/workflow"
)

func (c *Client) usesLocalCVE(s model.Settings) bool {
	return c.LocalCVE != nil && strings.TrimRight(s.CVEURL, "/") == model.DefaultCVEURL
}

func (c *Client) localCVE(ctx context.Context, id string, s model.Settings, reports []func(model.SyncProgress)) (string, []string, error) {
	if err := workflow.Wait(ctx); err != nil {
		return "", nil, err
	}
	r, found, err := c.LocalCVE.Lookup(id)
	if err != nil {
		notify(reports, model.SyncProgress{Phase: "cache_error", Item: "Could not read the local CVE catalogue"})
	}
	interval := model.Interval(s.CVEUpdateSchedule)
	if s.CVEUpdateSchedule == "" || interval == 0 {
		interval = 24 * time.Hour
	}
	age := time.Since(r.CheckedAt)
	fresh := found && err == nil && age >= 0 && age < interval+time.Hour
	// Bulk catalogue freshness is maintained once for all projects. An overdue
	// catalogue returns explicitly stale enrichment while its updater catches up,
	// avoiding a second refresh of thousands of records through the record API.
	useCatalogue := found && err == nil && c.LocalCVE.Initialized()
	if modeFor(ctx) != "refresh" && (fresh || useCatalogue || modeFor(ctx) == "local" && found) {
		status, phase := "cache", "cached"
		var stale error
		if !fresh {
			status, phase = "stale", "stale_cache"
			stale = errors.New("local CVE data is stale; update the CVE database")
		}
		notify(reports, model.SyncProgress{Phase: phase, CacheStatus: status, CheckedAt: r.CheckedAt})
		if r.State == "REJECTED" {
			return "", nil, ErrRejected
		}
		return r.Title, r.References, stale
	}
	ctx = withRequest(ctx, "cve", "", reports)
	result := c.cached(ctx, cacheKey("cve", s.CVEURL, id), s, func() (json.RawMessage, bool, error) {
		var data json.RawMessage
		if err := c.request(ctx, "GET", strings.TrimRight(s.CVEURL, "/")+"/"+url.PathEscape(id), nil, nil, &data); err != nil {
			return nil, false, err
		}
		full, err := cvedb.Parse(data)
		if err != nil || full.ID != id {
			return nil, false, fmt.Errorf("CVE returned an invalid record for %s", id)
		}
		full.CheckedAt = time.Now().UTC()
		if err := c.LocalCVE.Put(full); err != nil {
			notify(reports, model.SyncProgress{Phase: "cache_error", Item: "Could not save the local CVE record"})
		}
		if full.State == "REJECTED" {
			return nil, false, ErrRejected
		}
		b, err := json.Marshal(struct {
			Title      string
			References []string
		}{full.Title, full.References})
		return b, false, err
	}, reports)
	// A durable record remains available if the shared query cache was evicted.
	// Failed refreshes keep their failure and original freshness timestamp.
	if result.err != nil && !errors.Is(result.err, ErrRejected) && found && len(result.entry.Data) == 0 {
		result.entry = store.CachedResponse{CheckedAt: r.CheckedAt}
		result.mode = "stale"
		reportCache(result, reports)
		return r.Title, r.References, result.err
	}
	reportCache(result, reports)
	var record struct {
		Title      string
		References []string
	}
	if len(result.entry.Data) > 0 {
		if err := json.Unmarshal(result.entry.Data, &record); err != nil {
			return "", nil, err
		}
	}
	return record.Title, record.References, result.err
}
