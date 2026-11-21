package sources

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/nvddb"
)

const localTestCPE = "cpe:2.3:a:golang:go:1.26.0:*:*:*:*:*:*:*"

func initializeNVD(t *testing.T, c *Client, conditional bool) {
	t.Helper()
	local, err := c.Cache.OpenNVDDatabase()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := local.Close(); err != nil {
			t.Error(err)
		}
	})
	c.LocalNVD = local
	operator := "OR"
	if conditional {
		operator = "AND"
	}
	record := map[string]any{"id": "CVE-2026-0001", "descriptions": []map[string]string{{"lang": "en", "value": "Go vulnerability"}}, "configurations": []any{map[string]any{"operator": operator, "nodes": []any{map[string]any{"operator": "OR", "cpeMatch": []any{map[string]any{"vulnerable": true, "criteria": localTestCPE}}}}}}}
	data, err := json.Marshal(map[string]any{"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": []any{map[string]any{"cve": record}}})
	if err != nil {
		t.Fatal(err)
	}
	cpeData, err := json.Marshal(map[string]any{"totalResults": 1, "resultsPerPage": 1, "products": []any{map[string]any{"cpe": map[string]any{"cpeNameId": "dictionary-id", "cpeName": localTestCPE, "deprecated": false}}}})
	if err != nil {
		t.Fatal(err)
	}
	var nvd, cpe bytes.Buffer
	g := gzip.NewWriter(&nvd)
	if _, err := g.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(&cpe)
	w, err := z.Create("dictionary.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(cpeData); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	meta := func(raw, compressed []byte) string {
		hash := sha256.Sum256(raw)
		return fmt.Sprintf("lastModifiedDate:%s\nsize:%d\ngzSize:%d\nzipSize:%d\nsha256:%s\n", time.Now().UTC().Format(time.RFC3339Nano), len(raw), len(compressed), len(compressed), hex.EncodeToString(hash[:]))
	}
	updater := nvddb.NewUpdater(local)
	updater.HTTP.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		isCPE := strings.Contains(r.URL.Path, "/cpe/")
		if strings.HasSuffix(r.URL.Path, ".meta") {
			if isCPE {
				return response(200, meta(cpeData, cpe.Bytes())), nil
			}
			return response(200, meta(data, nvd.Bytes())), nil
		}
		if isCPE {
			return response(200, cpe.String()), nil
		}
		return response(200, nvd.String()), nil
	})
	if err := updater.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		stats, err := updater.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if !stats.Running {
			if !stats.Initialized || stats.Error != "" {
				t.Fatalf("initialize NVD: %+v", stats)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("NVD initialization timed out")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNVDLocalMatchingAndForceRefreshUseNormalEntryPoint(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	initializeNVD(t, c, false)
	s := model.Defaults().Settings
	a := model.Asset{ID: "component", Name: "Go", Version: "1.26.0", CPE: localTestCPE}
	for _, mode := range []string{"auto", "local"} {
		items, err := c.NVD(WithMode(context.Background(), mode), a, s)
		if err != nil || len(items) != 1 || items[0].AssetID != a.ID || items[0].Match != "cpe" || calls.Load() != 0 {
			t.Fatalf("local NVD query: %+v %v calls=%d", items, err, calls.Load())
		}
	}
	a.CPE = ""
	items, err := c.NVD(context.Background(), a, s)
	if err != nil || len(items) != 1 || items[0].Match != "review" || calls.Load() != 0 {
		t.Fatalf("name-only match lost review status: %+v %v", items, err)
	}
	if _, err := c.NVD(WithMode(context.Background(), "refresh"), a, s); err != nil || calls.Load() != 1 {
		t.Fatalf("force refresh bypass failed: %v", err)
	}
	s.NVDURL = "https://example.com/nvd"
	if _, err := c.NVD(context.Background(), a, s); err != nil || calls.Load() != 2 {
		t.Fatalf("custom endpoint did not use its own cache: %v", err)
	}
}

func TestUncertainLocalApplicabilityRequiresValidation(t *testing.T) {
	var calls atomic.Int32
	c := cachedClient(t, func(*http.Request) (*http.Response, error) { calls.Add(1); return response(200, oneNVD), nil })
	initializeNVD(t, c, true)
	s := model.Defaults().Settings
	a := model.Asset{ID: "component", Name: "Go", Version: "1.26.0", CPE: localTestCPE}
	items, err := c.NVD(WithMode(context.Background(), "local"), a, s)
	if err == nil || len(items) != 1 || items[0].Match != "review" || calls.Load() != 0 {
		t.Fatalf("uncertain offline result was silently confirmed: %+v %v", items, err)
	}
	items, err = c.NVD(context.Background(), a, s)
	if err != nil || len(items) != 1 || items[0].Match != "cpe" || calls.Load() != 1 {
		t.Fatalf("normal sync did not validate through NVD: %+v %v", items, err)
	}
}
