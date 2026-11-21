package sources

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/cvedb"
	"vulman/internal/model"
)

const fullCVERecord = `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED","dateUpdated":"2026-01-01T00:00:00Z"},"containers":{"cna":{"title":"Local catalogue advisory","references":[{"url":"https://example.com/advisory"}]}}}`

func enableLocalCVE(t *testing.T, c *Client) *cvedb.Store {
	t.Helper()
	s, err := c.Cache.OpenCVEDatabase()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	c.LocalCVE = s
	return s
}

func TestLocalCVEOutlivesQueryCacheAndHonorsModes(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(r *http.Request) (*http.Response, error) { calls.Add(1); return response(200, fullCVERecord), nil })
	local := enableLocalCVE(t, c)
	s := model.Defaults().Settings
	ctx := context.Background()
	if _, _, err := c.CVE(ctx, "CVE-2026-0001", s); err != nil {
		t.Fatal(err)
	}
	// Replacing the query cache with an empty database must not cause another
	// HTTP request. Catalogue records have an independent refresh schedule.
	cache := c.Cache
	c.Cache = nil
	defer func() { c.Cache = cache }()
	s.CacheHours = 1
	for _, mode := range []string{"auto", "local"} {
		title, refs, err := c.CVE(WithMode(ctx, mode), "CVE-2026-0001", s)
		if err != nil || title != "Local catalogue advisory" || len(refs) != 1 || calls.Load() != 1 {
			t.Fatalf("local lookup: %s %+v %v calls=%d", title, refs, err, calls.Load())
		}
	}
	if _, _, err := c.CVE(WithMode(ctx, "refresh"), "CVE-2026-0001", s); err != nil || calls.Load() != 2 {
		t.Fatalf("force refresh did not query upstream: %v", err)
	}
	r, _, err := local.Lookup("CVE-2026-0001")
	if err != nil {
		t.Fatal(err)
	}
	r.CheckedAt = time.Now().Add(-72 * time.Hour)
	if err := local.Put(r); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CVE(WithMode(ctx, "local"), r.ID, s); err == nil || calls.Load() != 2 {
		t.Fatalf("stale offline result presented as fresh: %v", err)
	}
	c.HTTP.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("offline") })
	title, _, err := c.CVE(ctx, r.ID, s)
	if err == nil || title != r.Title {
		t.Fatalf("failed refresh lost saved record: %q %v", title, err)
	}
}

func TestLocalCVERejectionsAndCustomEndpointIsolation(t *testing.T) {
	c := cachedClient(t, func(*http.Request) (*http.Response, error) {
		return response(200, `{"cveMetadata":{"state":"PUBLISHED"},"containers":{"cna":{"title":"Custom source"}}}`), nil
	})
	local := enableLocalCVE(t, c)
	r := cvedb.Record{ID: "CVE-2026-0001", State: "REJECTED", UpdatedAt: time.Now(), CheckedAt: time.Now()}
	if err := local.Put(r); err != nil {
		t.Fatal(err)
	}
	s := model.Defaults().Settings
	if _, _, err := c.CVE(context.Background(), r.ID, s); !errors.Is(err, ErrRejected) {
		t.Fatalf("rejected record enriched a finding: %v", err)
	}
	s.CVEURL = "https://example.com/custom-cve"
	title, _, err := c.CVE(context.Background(), r.ID, s)
	if err != nil || title != "Custom source" {
		t.Fatalf("official catalogue leaked into custom endpoint: %q %v", title, err)
	}
}

func TestOverdueBulkCatalogueDoesNotRefetchEveryCVE(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return response(200, fullCVERecord), nil
	})
	local := enableLocalCVE(t, c)
	var archive bytes.Buffer
	z := zip.NewWriter(&archive)
	w, err := z.Create("CVE-2026-0001.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, fullCVERecord); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(archive.Bytes())
	metadata, err := json.Marshal(map[string]any{
		"tag_name": "cve_2026-01-01_0000Z",
		"assets": []map[string]any{{
			"name":                 "2026-01-01_all_CVEs_at_midnight.zip",
			"browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/fixture/baseline.zip",
			"size":                 archive.Len(), "digest": "sha256:" + hex.EncodeToString(digest[:]),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	updater := cvedb.NewUpdater(local)
	updater.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "github.com" {
			return response(200, archive.String()), nil
		}
		if r.URL.Path == "/repos/CVEProject/cvelistV5/releases/latest" {
			return response(200, string(metadata)), nil
		}
		return response(200, "[]"), nil
	})
	if err := updater.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		stats, err := updater.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if !stats.Running {
			if !stats.Initialized || stats.Error != "" {
				t.Fatalf("initialization failed: %+v", stats)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("catalogue initialization timed out")
		}
		time.Sleep(time.Millisecond)
	}
	title, _, err := c.CVE(context.Background(), "CVE-2026-0001", model.Defaults().Settings)
	if err == nil || title != "Local catalogue advisory" || calls.Load() != 0 {
		t.Fatalf("overdue catalogue caused per-record refresh or hid its age: %q %v requests=%d", title, err, calls.Load())
	}
}
