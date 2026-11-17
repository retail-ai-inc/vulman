package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"vulman/internal/model"
)

func TestNVDPaginationAndConfidence(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		q := r.URL.Query()
		if r.Header.Get("apiKey") != "key" {
			t.Error("API key header missing")
		}
		if q.Get("cpeName") == "" || !q.Has("isVulnerable") {
			t.Error("exact CPE query missing")
		}
		id := "CVE-2024-0001"
		if q.Get("startIndex") == "1" {
			id = "CVE-2024-0002"
		}
		if _, err := fmt.Fprintf(w, `{"totalResults":2,"vulnerabilities":[{"cve":{"id":%q,"descriptions":[{"lang":"en","value":"Test advisory"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}}]}`, id); err != nil {
			t.Errorf("write mock NVD page: %v", err)
		}
	}))
	defer server.Close()
	s := model.Defaults().Settings
	s.NVDURL = server.URL
	s.Tokens["nvd"] = "key"
	a := model.Asset{ID: "a", Name: "log4j", Version: "2.14.1", CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}
	var updates []model.SyncProgress
	items, err := New().NVD(context.Background(), a, s, func(p model.SyncProgress) { updates = append(updates, p) })
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || requests.Load() != 2 || items[0].Severity != "CRITICAL" || items[0].Match != "cpe" {
		t.Fatalf("incorrect paginated results: %+v", items)
	}
	waited := false
	for _, p := range updates {
		if p.Phase == "waiting" && p.WaitSeconds > 0 {
			waited = true
		}
	}
	var last model.SyncProgress
	for _, update := range updates {
		if update.Phase == "page" {
			last = update
		}
	}
	if !waited || last.Phase != "page" || last.Processed != 2 || last.Total != 2 {
		t.Fatalf("missing pagination or rate-limit progress: %+v", updates)
	}
}

func TestNVDKeywordIsNeverVerified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("keywordSearch") != "redis" {
			t.Error("name query missing")
		}
		if _, err := fmt.Fprint(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001"}}]}`); err != nil {
			t.Errorf("write mock NVD response: %v", err)
		}
	}))
	defer server.Close()
	s := model.Defaults().Settings
	s.NVDURL = server.URL
	items, err := New().NVD(context.Background(), model.Asset{ID: "a", Name: "redis", Version: "7.0"}, s)
	if err != nil || len(items) != 1 || items[0].Match != "review" {
		t.Fatalf("name match treated as verified: %v %+v", err, items)
	}
}

func TestOSVPaginationAndFixedVersionScope(t *testing.T) {
	var count atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var query struct {
			Version   string
			Package   struct{ Name, Ecosystem string }
			PageToken string `json:"page_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
			t.Error(err)
		}
		if query.Version != "1.0.0" || query.Package.Ecosystem != "npm" {
			t.Error("package identity not sent")
		}
		count.Add(1)
		body := `{"vulns":[{"id":"withdrawn","withdrawn":"2024-01-01"}]}`
		if query.PageToken == "" {
			body = `{"next_page_token":"next","vulns":[{"id":"GHSA-one","aliases":["CVE-2024-0001"],"summary":"Example","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"demo","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.2.3"}]}]},{"package":{"name":"different","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"fixed":"9.0.0"}]}]}]}]}`
		}
		if _, err := fmt.Fprint(w, body); err != nil {
			t.Errorf("write mock OSV page: %v", err)
		}
	}))
	defer server.Close()
	s := model.Defaults().Settings
	s.OSVURL = server.URL
	items, err := New().OSV(context.Background(), model.Asset{ID: "a", Name: "demo", Version: "1.0.0", Ecosystem: "npm"}, s)
	if err != nil {
		t.Fatal(err)
	}
	if count.Load() != 2 || len(items) != 1 || items[0].ID != "CVE-2024-0001" || len(items[0].FixedVersions) != 1 || items[0].FixedVersions[0] != "1.2.3" {
		t.Fatalf("incorrect results: %+v", items)
	}
}

func TestCVEIncludesADPReferences(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, `{"cveMetadata":{"state":"PUBLISHED"},"containers":{"cna":{"title":"Original title","references":[{"url":"https://example.com/cna"}]},"adp":[{"references":[{"url":"https://example.com/adp"}]}]}}`); err != nil {
			t.Errorf("write mock CVE response: %v", err)
		}
	}))
	defer server.Close()
	s := model.Defaults().Settings
	s.CVEURL = server.URL
	title, refs, err := New().CVE(context.Background(), "CVE-2024-0001", s)
	if err != nil || title != "Original title" || len(refs) != 2 {
		t.Fatalf("missing record data: %s %v %v", title, refs, err)
	}
}

func TestMergePreservesComponentBoundaries(t *testing.T) {
	out := Merge([]model.Finding{{ID: "CVE-1", AssetID: "a", Severity: "HIGH", Match: "review", Sources: []string{"NVD"}}, {ID: "CVE-1", AssetID: "a", Severity: "CRITICAL", Match: "package", Sources: []string{"OSV"}, FixedVersions: []string{"1.2.3"}}, {ID: "CVE-1", AssetID: "b", Severity: "LOW", Match: "review"}})
	if len(out) != 2 || out[0].Severity != "CRITICAL" || out[0].Match != "package" || len(out[0].Sources) != 2 {
		t.Fatalf("incorrect merge: %+v", out)
	}
}
