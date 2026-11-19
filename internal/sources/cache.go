package sources

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
	"vulman/internal/workflow"
)

var ErrRejected = errors.New("CVE record is rejected")
var ErrCacheMiss = errors.New("no cached data is available; use normal sync or force refresh")

type optionsKey struct{}

func WithMode(ctx context.Context, mode string) context.Context {
	return context.WithValue(ctx, optionsKey{}, mode)
}

func modeFor(ctx context.Context) string { mode, _ := ctx.Value(optionsKey{}).(string); return mode }

type cacheResult struct {
	entry   store.CachedResponse
	mode    string
	err     error
	partial json.RawMessage
}

type flight struct {
	done   chan struct{}
	result cacheResult
	owner  context.Context
}

func cacheKey(kind, endpoint string, identity any) string {
	data, _ := json.Marshal([]any{"matching-v1", kind, endpoint, identity})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func ttlFor(s model.Settings, entry store.CachedResponse) time.Duration {
	hours := s.CacheHours
	if hours <= 0 {
		hours = 6
	}

	ttl := time.Duration(hours) * time.Hour
	if entry.Empty && ttl > time.Hour {
		ttl = time.Hour
	}

	return ttl
}

func fresh(entry store.CachedResponse, s model.Settings) bool {
	age := time.Since(entry.CheckedAt)
	return !entry.CheckedAt.IsZero() && age >= 0 && age < ttlFor(s, entry)
}

func (c *Client) cached(ctx context.Context, key string, s model.Settings, fetch func() (json.RawMessage, bool, error), reports []func(model.SyncProgress)) cacheResult {
	if err := workflow.Wait(ctx); err != nil {
		return cacheResult{err: err}
	}

	var old store.CachedResponse
	hasOld := false
	read := func() {
		if c.Cache != nil {
			entry, ok, err := c.Cache.CacheGet(key)

			if err == nil {
				old, hasOld = entry, ok
			} else {
				notify(reports, model.SyncProgress{Phase: "cache_error", Item: "Could not read cached data"})
			}
		}
	}

	read()

	recordUse := func(hit bool) {
		if c.Cache != nil && modeFor(ctx) != "refresh" {
			c.Cache.RecordCacheUse(hit)
		}
	}

	if modeFor(ctx) == "local" {
		recordUse(hasOld && fresh(old, s))
		if !hasOld {
			return cacheResult{err: ErrCacheMiss}
		}
		if !fresh(old, s) {
			return cacheResult{entry: old, mode: "stale", err: fmt.Errorf("cached data expired; upstream freshness was not verified")}
		}
		return cacheResult{entry: old, mode: "cache"}
	}

	if modeFor(ctx) != "refresh" && hasOld && fresh(old, s) {
		recordUse(true)
		return cacheResult{entry: old, mode: "cache"}
	}

	if err := ctx.Err(); err != nil {
		return cacheResult{err: err}
	}

	c.flightsMu.Lock()

	if existing := c.flights[key]; existing != nil {
		c.flightsMu.Unlock()
		changed := workflow.Changes(existing.owner)
		if workflow.Paused(existing.owner) || existing.owner.Err() != nil {
			c.detachFlight(key, existing)
			return c.cached(ctx, key, s, fetch, reports)
		}

		recordUse(false)
		notify(reports, model.SyncProgress{Phase: "shared"})

		select {
		case <-ctx.Done():
			return cacheResult{err: ctx.Err()}
		case <-existing.done:
			result := existing.result
			if ctx.Err() == nil && (errors.Is(result.err, context.Canceled) || errors.Is(result.err, context.DeadlineExceeded)) {
				return c.cached(ctx, key, s, fetch, reports)
			}
			if result.err == nil {
				result.mode = "shared"
			}
			return result
		case <-existing.owner.Done():
			c.detachFlight(key, existing)
			return c.cached(ctx, key, s, fetch, reports)
		case <-changed:
			if workflow.Paused(existing.owner) {
				c.detachFlight(key, existing)
			}
			return c.cached(ctx, key, s, fetch, reports)
		}
	}

	// Another request may have refreshed the entry after our initial read.
	if modeFor(ctx) != "refresh" && c.Cache != nil {
		entry, ok, err := c.Cache.CacheGet(key)
		if err == nil && ok && fresh(entry, s) {
			c.flightsMu.Unlock()
			recordUse(true)
			return cacheResult{entry: entry, mode: "cache"}
		}
	}

	f := &flight{done: make(chan struct{}), owner: ctx}
	c.flights[key] = f
	c.flightsMu.Unlock()
	recordUse(false)
	data, empty, err := fetch()
	result := cacheResult{err: err, mode: "network"}

	if err == nil {
		result.entry = store.CachedResponse{Data: data, Empty: empty, CheckedAt: time.Now().UTC()}
		if c.Cache != nil {
			if e := c.Cache.CachePut(key, result.entry); e != nil {
				notify(reports, model.SyncProgress{Phase: "cache_error", Item: e.Error()})
			}
		}
	} else if errors.Is(err, ErrRejected) {
		if c.Cache != nil {
			_ = c.Cache.CacheDelete(key)
		}
	} else if hasOld && ctx.Err() == nil {
		result.entry = old
		result.partial = data
		result.mode = "stale"
		result.err = fmt.Errorf("using cached data; upstream refresh failed: %w", err)
	} else {
		result.entry.Data = data
	}

	c.flightsMu.Lock()
	f.result = result
	if c.flights[key] == f {
		delete(c.flights, key)
	}

	close(f.done)
	c.flightsMu.Unlock()
	return result
}

func (c *Client) detachFlight(key string, f *flight) {
	c.flightsMu.Lock()
	defer c.flightsMu.Unlock()
	if c.flights[key] == f {
		delete(c.flights, key)
	}
}

func reportCache(result cacheResult, reports []func(model.SyncProgress)) {
	if result.entry.CheckedAt.IsZero() {
		return
	}

	phase := "refreshed"
	switch result.mode {
	case "cache":
		phase = "cached"
	case "shared":
		phase = "shared_result"
	case "stale":
		phase = "stale_cache"
	}

	notify(reports, model.SyncProgress{Phase: phase, CacheStatus: result.mode, CheckedAt: result.entry.CheckedAt})
}

func (c *Client) query(ctx context.Context, kind string, a model.Asset, s model.Settings, reports []func(model.SyncProgress)) ([]model.Finding, error) {
	endpoint := s.NVDURL
	if kind == "osv" {
		endpoint = s.OSVURL
	}

	identity := struct{ Name, Version, Ecosystem, CPE string }{a.Name, a.Version, a.Ecosystem, a.CPE}
	ctx = withRequest(ctx, kind, s.Tokens["nvd"], reports)
	result := c.cached(ctx, cacheKey(kind, endpoint, identity), s, func() (json.RawMessage, bool, error) {
		var items []model.Finding
		var err error

		if kind == "nvd" {
			items, err = c.fetchNVD(ctx, a, s, reports...)
		} else {
			items, err = c.fetchOSV(ctx, a, s, reports...)
		}

		for i := range items {
			items[i].AssetID = ""
			items[i].Component = ""
			items[i].Version = ""
		}

		items = Merge(items)
		b, marshalErr := json.Marshal(items)

		if marshalErr != nil {
			return nil, false, marshalErr
		}

		return b, len(items) == 0, err
	}, reports)

	reportCache(result, reports)
	items := []model.Finding{}

	if len(result.entry.Data) > 0 {
		if err := json.Unmarshal(result.entry.Data, &items); err != nil {
			return nil, fmt.Errorf("invalid cached advisory data: %w", err)
		}
	}

	if len(result.partial) > 0 {
		var partial []model.Finding
		if json.Unmarshal(result.partial, &partial) == nil {
			items = append(items, partial...)
		}
	}

	for i := range items {
		items[i].AssetID = a.ID
		items[i].Component = a.Name
		items[i].Version = a.Version
	}
	return Merge(items), result.err
}

func (c *Client) NVD(ctx context.Context, a model.Asset, s model.Settings, reports ...func(model.SyncProgress)) ([]model.Finding, error) {
	if c.usesLocalNVD(s) && modeFor(ctx) != "refresh" {
		return c.localNVD(ctx, a, s, reports)
	}
	return c.query(ctx, "nvd", a, s, reports)
}

func (c *Client) OSV(ctx context.Context, a model.Asset, s model.Settings, reports ...func(model.SyncProgress)) ([]model.Finding, error) {
	if c.LocalOSV != nil && modeFor(ctx) != "refresh" && strings.TrimRight(s.OSVURL, "/") == model.DefaultOSVURL {
		return c.localOSV(ctx, a, s, reports)
	}

	return c.query(ctx, "osv", a, s, reports)
}

func (c *Client) CVE(ctx context.Context, id string, s model.Settings, reports ...func(model.SyncProgress)) (string, []string, error) {
	if len(id) < 4 || id[:4] != "CVE-" {
		return "", nil, nil
	}
	if c.usesLocalCVE(s) {
		return c.localCVE(ctx, id, s, reports)
	}

	ctx = withRequest(ctx, "cve", "", reports)
	result := c.cached(ctx, cacheKey("cve", s.CVEURL, id), s, func() (json.RawMessage, bool, error) {
		title, refs, err := c.fetchCVE(ctx, id, s)
		if err != nil {
			return nil, false, err
		}

		b, err := json.Marshal(struct {
			Title      string
			References []string
		}{title, refs})
		return b, false, err
	}, reports)

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
