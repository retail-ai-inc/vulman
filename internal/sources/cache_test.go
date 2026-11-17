package sources

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
	"vulman/internal/workflow"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
func cachedClient(t *testing.T, transport roundTripFunc) *Client {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := New(s)
	t.Cleanup(func() {
		if c.Cache != nil {
			if err := c.Cache.Close(); err != nil {
				t.Errorf("close test cache: %v", err)
			}
		}
	})
	c.HTTP.Transport = transport
	c.gapOverride = map[string]time.Duration{"nvd": 0, "osv": 0, "cve": 0}
	c.retryBase = time.Millisecond
	return c
}
func identity(a model.Asset) any {
	return struct{ Name, Version, Ecosystem, CPE string }{a.Name, a.Version, a.Ecosystem, a.CPE}
}

const oneNVD = `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","references":[{"url":"https://example.com"}]}}]}`

func TestCacheReusesQueriesAcrossProjectsAndRestart(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	s := model.Defaults().Settings
	a := model.Asset{ID: "first-project-asset", Name: "demo", Version: "1"}
	first, err := c.NVD(context.Background(), a, s)
	if err != nil {
		t.Fatal(err)
	}
	first[0].References[0] = "modified-in-memory"
	a.ID = "second-project-asset"
	second, err := c.NVD(context.Background(), a, s)
	if err != nil || calls.Load() != 1 || second[0].AssetID != a.ID || second[0].References[0] != "https://example.com" {
		t.Fatalf("cache reused project identity or mutable data: %+v %v", second, err)
	}
	cache := c.Cache
	dir := filepath.Dir(cache.Paths().Database)
	c.Cache = nil
	if err := cache.Close(); err != nil {
		t.Fatalf("close cache before reopening: %v", err)
	}
	reopened, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Errorf("close reopened cache: %v", err)
		}
	})
	next := New(reopened)
	next.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("cache should survive restart")
		return nil, errors.New("unexpected network")
	})
	if _, err = next.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
}

func TestCacheIdentityIncludesVersionAndEndpoint(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	for i := 0; i < 3; i++ {
		if i == 1 {
			a.Version = "2"
		}
		if i == 2 {
			s.NVDURL = "https://different.example/cves"
		}
		if _, err := c.NVD(context.Background(), a, s); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Fatal("version or endpoint change reused an incompatible query")
	}
}

func TestEmptyResultsExpireWithinAnHour(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, `{"totalResults":0,"vulnerabilities":[]}`), nil
	})
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
	key := cacheKey("nvd", s.NVDURL, identity(a))
	entry, found, err := c.Cache.CacheGet(key)
	if err != nil || !found {
		t.Fatalf("read cached empty result (found=%v): %v", found, err)
	}
	entry.CheckedAt = time.Now().Add(-2 * time.Hour)
	if err := c.Cache.CachePut(key, entry); err != nil {
		t.Fatalf("age cached empty result: %v", err)
	}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("empty result was cached longer than an hour")
	}
	entry, found, err = c.Cache.CacheGet(key)
	if err != nil || !found {
		t.Fatalf("read refreshed cache entry (found=%v): %v", found, err)
	}
	entry.Empty = false
	entry.CheckedAt = time.Now().Add(-2 * time.Hour)
	if err := c.Cache.CachePut(key, entry); err != nil {
		t.Fatalf("age cached nonempty result: %v", err)
	}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatal("six-hour cache TTL was not honored")
	}
}

func TestCacheOnlyNeverUsesNetworkAndMarksExpiredData(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	local := WithMode(context.Background(), "local")
	if _, err := c.NVD(local, a, s); !errors.Is(err, ErrCacheMiss) {
		t.Fatalf("missing cache did not fail explicitly: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("cache-only mode made a request")
	}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatalf("populate NVD cache: %v", err)
	}
	key := cacheKey("nvd", s.NVDURL, identity(a))
	entry, found, err := c.Cache.CacheGet(key)
	if err != nil || !found {
		t.Fatalf("read cache entry (found=%v): %v", found, err)
	}
	entry.CheckedAt = time.Now().Add(-8 * time.Hour)
	if err := c.Cache.CachePut(key, entry); err != nil {
		t.Fatalf("expire cache entry: %v", err)
	}
	var metadata model.SyncProgress
	items, err := c.NVD(local, a, s, func(p model.SyncProgress) {
		if p.CacheStatus != "" {
			metadata = p
		}
	})
	if err == nil || len(items) != 1 || calls.Load() != 1 || metadata.CacheStatus != "stale" || !metadata.CheckedAt.Equal(entry.CheckedAt) {
		t.Fatalf("expired cached data was treated as current: %+v %v", metadata, err)
	}
}

func TestFailedRefreshPreservesCacheAndReportsStaleFallback(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return response(200, oneNVD), nil
		}
		res := response(503, "")
		res.Header.Set("Retry-After", "60")
		return res, nil
	})
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatalf("populate NVD cache: %v", err)
	}
	key := cacheKey("nvd", s.NVDURL, identity(a))
	old, found, err := c.Cache.CacheGet(key)
	if err != nil || !found {
		t.Fatalf("read cache entry before refresh (found=%v): %v", found, err)
	}
	old.CheckedAt = time.Now().Add(-8 * time.Hour)
	if err := c.Cache.CachePut(key, old); err != nil {
		t.Fatalf("expire cache entry: %v", err)
	}
	var meta model.SyncProgress
	items, err := c.NVD(context.Background(), a, s, func(p model.SyncProgress) {
		if p.CacheStatus != "" {
			meta = p
		}
	})
	if err == nil || len(items) != 1 || meta.CacheStatus != "stale" {
		t.Fatalf("missing stale fallback: %+v %v", items, err)
	}
	after, found, err := c.Cache.CacheGet(key)
	if err != nil || !found {
		t.Fatalf("read cache entry after failed refresh (found=%v): %v", found, err)
	}
	if !after.CheckedAt.Equal(old.CheckedAt) {
		t.Fatal("failed refresh advanced freshness")
	}
	if calls.Load() != 2 {
		t.Fatal("long Retry-After should defer further requests")
	}
}

func TestIncompletePaginationIsNotCached(t *testing.T) {
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		if r.URL.Query().Get("startIndex") == "0" {
			return response(200, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":"CVE-partial"}}]}`), nil
		}
		return response(400, ""), nil
	})
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	items, err := c.NVD(context.Background(), a, s)
	if err == nil || len(items) != 1 {
		t.Fatal("partial positive findings were lost")
	}
	stats, _ := c.Cache.CacheStats()
	if stats.Entries != 0 {
		t.Fatal("partial pagination was cached as complete")
	}
}

func TestConcurrentProjectsShareLookupAndCancelledWaiterDoesNotCancelIt(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		close(started)
		<-release
		return response(200, oneNVD), nil
	})
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	done := make(chan error, 1)
	go func() { _, err := c.NVD(context.Background(), a, s); done <- err }()
	<-started
	waiterStarted := make(chan struct{}, 1)
	ctx, cancel := context.WithCancel(context.Background())
	waiterDone := make(chan error, 1)
	go func() {
		_, err := c.NVD(ctx, a, s, func(p model.SyncProgress) {
			if p.Phase == "shared" {
				waiterStarted <- struct{}{}
			}
		})
		waiterDone <- err
	}()
	<-waiterStarted
	cancel()
	if err := <-waiterDone; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	shared := make(chan struct{}, 1)
	secondDone := make(chan error, 1)
	a.ID = "b"
	go func() {
		items, err := c.NVD(WithMode(context.Background(), "refresh"), a, s, func(p model.SyncProgress) {
			if p.Phase == "shared" {
				shared <- struct{}{}
			}
		})
		if err == nil && (len(items) != 1 || items[0].AssetID != "b") {
			err = fmt.Errorf("shared result has wrong identity")
		}
		secondDone <- err
	}()
	<-shared
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("concurrent lookups were duplicated")
	}
}

func TestRetriesTemporaryFailuresButNotAuthenticationErrors(t *testing.T) {
	for _, status := range []int{503, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var calls atomic.Int32
			c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) < 3 {
					return response(status, ""), nil
				}
				return response(200, `{}`), nil
			})
			s := model.Defaults().Settings
			_, err := c.OSV(context.Background(), model.Asset{Name: "demo", Version: "1", Ecosystem: "npm"}, s)
			if status == 503 {
				if err != nil || calls.Load() != 3 {
					t.Fatalf("temporary failures not retried: %d %v", calls.Load(), err)
				}
			} else if err == nil || calls.Load() != 1 {
				t.Fatal("authentication error retried")
			}
		})
	}
}

func TestProviderCooldownAppliesToQueuedRequests(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	queued := make(chan struct{}, 1)
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		res := response(429, "")
		res.Header.Set("Retry-After", "60")
		return res, nil
	})
	s := model.Defaults().Settings
	done := make(chan error, 2)
	go func() {
		_, err := c.OSV(context.Background(), model.Asset{Name: "one", Version: "1", Ecosystem: "npm"}, s)
		done <- err
	}()
	<-started
	go func() {
		_, err := c.OSV(context.Background(), model.Asset{Name: "two", Version: "1", Ecosystem: "npm"}, s, func(p model.SyncProgress) {
			if p.Phase == "queued" {
				queued <- struct{}{}
			}
		})
		done <- err
	}()
	<-queued
	close(release)
	firstErr := <-done
	secondErr := <-done
	if firstErr == nil || secondErr == nil {
		t.Fatalf("rate limit was ignored: request errors were %v and %v", firstErr, secondErr)
	}
	if calls.Load() != 1 {
		t.Fatal("queued lookup bypassed provider cooldown")
	}
}

func TestRetryBudgetAndCancellation(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(503, ""), nil })
	s := model.Defaults().Settings
	a := model.Asset{Name: "demo", Version: "1", Ecosystem: "npm"}
	if _, err := c.OSV(context.Background(), a, s); err == nil || calls.Load() != 3 {
		t.Fatal("retry budget was not enforced")
	}
	stats, _ := c.Cache.CacheStats()
	if stats.Entries != 0 {
		t.Fatal("failed requests were cached")
	}
	c = cachedClient(t, func(r *http.Request) (*http.Response, error) {
		res := response(429, "")
		res.Header.Set("Retry-After", "1")
		return res, nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.OSV(ctx, a, s); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("retry wait ignored cancellation: %v", err)
	}
}

func TestRejectedCVEInvalidatesCachedRecord(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			return response(200, `{"cveMetadata":{"state":"PUBLISHED"},"containers":{"cna":{"title":"Published"}}}`), nil
		}
		return response(200, `{"cveMetadata":{"state":"REJECTED"}}`), nil
	})
	s := model.Defaults().Settings
	if _, _, err := c.CVE(context.Background(), "CVE-2024-0001", s); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CVE(WithMode(context.Background(), "refresh"), "CVE-2024-0001", s); !errors.Is(err, ErrRejected) {
		t.Fatal("rejected record returned stale guidance")
	}
	if _, _, err := c.CVE(WithMode(context.Background(), "local"), "CVE-2024-0001", s); !errors.Is(err, ErrCacheMiss) {
		t.Fatal("rejected record remained cached")
	}
}

func TestLogicalCacheMetricsExcludeDiagnosticsAndForcedRefresh(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	s := model.Defaults().Settings
	a := model.Asset{ID: "a", Name: "demo", Version: "1"}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
	if _, err := c.NVD(context.Background(), a, s); err != nil {
		t.Fatal(err)
	}
	stats, err := c.Cache.CacheStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("logical lookup counts are wrong: %+v", stats)
	}
	if _, found, err := c.Cache.CacheGet(cacheKey("nvd", s.NVDURL, identity(a))); err != nil || !found {
		t.Fatalf("read cache entry for diagnostics (found=%v): %v", found, err)
	}
	if _, err := c.Cache.CacheStats(); err != nil {
		t.Fatalf("read diagnostic cache stats: %v", err)
	}
	if _, err := c.NVD(WithMode(context.Background(), "refresh"), a, s); err != nil {
		t.Fatal(err)
	}
	stats, err = c.Cache.CacheStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hits != 1 || stats.Misses != 1 || calls.Load() != 2 {
		t.Fatalf("diagnostics or forced refresh changed hit ratio: %+v", stats)
	}
	if _, err := c.NVD(WithMode(context.Background(), "local"), a, s); err != nil {
		t.Fatal(err)
	}
	stats, err = c.Cache.CacheStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats.Hits != 2 || stats.Misses != 1 || stats.Evictions != 0 {
		t.Fatalf("cache-only lookup metrics are wrong: %+v", stats)
	}
}

func TestSharedQueriesSurviveOwnerPauseOrStop(t *testing.T) {
	for _, action := range []string{"pause", "pause before waiter", "stop"} {
		t.Run(action, func(t *testing.T) {
			c := New()
			c.gapOverride = map[string]time.Duration{"osv": 0}
			started, release, shared := make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			notifyShared := sync.OnceFunc(func() { close(shared) })
			var calls atomic.Int32
			c.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return response(200, `{"vulns":[{"id":"first"}],"next_page_token":"next"}`), nil
				}
				return response(200, `{"vulns":[{"id":"shared-success"}]}`), nil
			})
			owner := workflow.New(context.Background(), time.Minute, nil)
			defer owner.Close()
			s := model.Defaults().Settings
			a := model.Asset{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}
			ownerDone := make(chan error, 1)
			go func() { _, err := c.OSV(owner.Context(), a, s); ownerDone <- err }()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("owner did not start")
			}
			if action == "pause before waiter" {
				owner.Pause()
			}
			waiterDone := make(chan error, 1)
			go func() {
				items, err := c.OSV(context.Background(), a, s, func(p model.SyncProgress) {
					if p.Phase == "shared" {
						notifyShared()
					}
				})
				if err == nil && (len(items) != 1 || items[0].ID != "shared-success") {
					err = fmt.Errorf("wrong shared results: %+v", items)
				}
				waiterDone <- err
			}()
			if action != "pause before waiter" {
				select {
				case <-shared:
				case <-time.After(time.Second):
					t.Fatal("waiter did not share query")
				}
				if action == "stop" {
					owner.Stop()
				} else {
					owner.Pause()
				}
			}
			unblock()
			select {
			case err := <-waiterDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("other project blocked by controlled owner")
			}
			if action != "stop" {
				owner.Resume()
			}
			select {
			case err := <-ownerDone:
				if action == "stop" && !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
				if action != "stop" && err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("owner did not finish")
			}
			c.flightsMu.Lock()
			remaining := len(c.flights)
			c.flightsMu.Unlock()
			if remaining != 0 {
				t.Fatal("shared query leaked")
			}
		})
	}
}
