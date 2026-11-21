package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
)

const mixedOSV = `{"vulns":[
 {"id":"GHSA-new","summary":"New critical","database_specific":{"severity":"CRITICAL"}},
 {"id":"GHSA-down","summary":"Downgraded advisory","database_specific":{"severity":"HIGH"}},
 {"id":"GHSA-high","summary":"Changed high title","database_specific":{"severity":"HIGH"}},
 {"id":"GHSA-promote","summary":"Promoted advisory","database_specific":{"severity":"CRITICAL"}},
 {"id":"GHSA-unrated","summary":"Unrated advisory"},
 {"id":"GHSA-low","summary":"Low advisory","database_specific":{"severity":"LOW"}}
]}`

func TestSeveritySyncPreservesOutsideFindingsAndReconcilesRatingChanges(t *testing.T) {
	for _, assetID := range []string{"", "a"} {
		t.Run("asset="+assetID, func(t *testing.T) {
			s := testStore(t)
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				var query struct{ Package struct{ Name string } }
				if err := json.NewDecoder(r.Body).Decode(&query); err != nil {
					t.Error(err)
				}
				body := `{}`
				if query.Package.Name == "demo" {
					body = mixedOSV
				}
				if _, err := fmt.Fprint(w, body); err != nil {
					t.Errorf("write mock OSV response: %v", err)
				}
			}))
			defer server.Close()
			old := time.Now().Add(-time.Hour).UTC()
			next := time.Now().Add(time.Hour).UTC()
			a := model.Asset{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}
			if err := s.Update(func(st *model.State) error {
				st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": true}
				st.Settings.OSVURL = server.URL
				st.Projects = []model.Project{{ID: "p", Revision: 2, AssessedRevision: 1, LastSync: old, DataCheckedAt: old, Schedule: "daily", NextRun: next, Assets: []model.Asset{a, {ID: "b", Name: "other", Version: "1", Ecosystem: "npm"}}, Findings: []model.Finding{
					{ID: "GHSA-down", AssetID: "a", Severity: "CRITICAL"}, {ID: "GHSA-resolved", AssetID: "a", Severity: "CRITICAL"},
					{ID: "GHSA-high", AssetID: "a", Severity: "HIGH", Title: "Keep original high title"}, {ID: "GHSA-promote", AssetID: "a", Severity: "MEDIUM"},
					{ID: "GHSA-b-critical", AssetID: "b", Severity: "CRITICAL"}, {ID: "GHSA-b-low", AssetID: "b", Severity: "LOW"}, {ID: "CVE-code", AssetID: "code:lib", Severity: "HIGH", Match: "scanner"},
				}}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			e, err := New(s)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err = e.StartFiltered("p", "manual", assetID, "auto", "critical"); err != nil {
				t.Fatal(err)
			}
			p := awaitRun(t, s)
			r := p.Runs[0]
			if r.Severity != "CRITICAL" || r.Status != "complete" || r.Count != 2 {
				t.Fatalf("incorrect severity assessment: %+v", r)
			}
			if !p.LastSync.Equal(old) || !p.DataCheckedAt.Equal(old) || p.AssessedRevision != 1 || !p.NextRun.Equal(next) {
				t.Fatal("severity-only sync changed full-project freshness or schedule")
			}
			found := map[string]model.Finding{}
			for _, f := range p.Findings {
				found[f.ID] = f
			}
			if _, ok := found["GHSA-resolved"]; ok {
				t.Fatal("resolved selected-severity finding was retained")
			}
			if found["GHSA-down"].Severity != "HIGH" || found["GHSA-promote"].Severity != "CRITICAL" {
				t.Fatal("severity change erased or duplicated an advisory")
			}
			if found["GHSA-high"].Title != "Keep original high title" || found["GHSA-b-low"].Severity != "LOW" || found["CVE-code"].Match != "scanner" {
				t.Fatal("unselected findings changed")
			}
			_, hasOtherCritical := found["GHSA-b-critical"]
			if hasOtherCritical != (assetID != "") {
				t.Fatal("component and severity scopes did not intersect")
			}
			if _, ok := found["GHSA-unrated"]; ok {
				t.Fatal("new unselected severity was added to project findings")
			}
			st, _ := s.Read()
			before := calls.Load()
			cached, err := e.Sources.OSV(context.Background(), a, st.Settings)
			if err != nil || len(cached) != 6 || calls.Load() != before {
				t.Fatal("severity sync narrowed or bypassed the shared cache")
			}
			if err = e.Start("p", "manual"); err != nil {
				t.Fatal(err)
			}
			full := awaitRun(t, s)
			if len(full.Findings) != 7 || full.AssessedRevision != 2 || full.Runs[0].Severity != "" {
				t.Fatal("default sync did not restore all-severity coverage while retaining unassessed scanner findings")
			}
		})
	}
}

func TestSeveritySyncEnrichesOnlySelectedCVERecords(t *testing.T) {
	s := testStore(t)
	var nvdCalls, cveCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/nvd" {
			nvdCalls.Add(1)
			if _, err := fmt.Fprint(w, `{"totalResults":3,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]}}},{"cve":{"id":"CVE-2024-0002","metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]}}},{"cve":{"id":"CVE-2024-0003"}}]}`); err != nil {
				t.Errorf("write mock NVD response: %v", err)
			}
			return
		}
		cveCalls.Add(1)
		if r.URL.Path != "/cve/CVE-2024-0001" {
			t.Errorf("unselected advisory enriched: %s", r.URL.Path)
		}
		if _, err := fmt.Fprint(w, `{"cveMetadata":{"state":"PUBLISHED"},"containers":{"cna":{"title":"Original advisory"}}}`); err != nil {
			t.Errorf("write mock CVE response: %v", err)
		}
	}))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.NVDURL = server.URL + "/nvd"
		st.Settings.CVEURL = server.URL + "/cve"
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.StartFiltered("p", "manual", "", "auto", "CRITICAL"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if nvdCalls.Load() != 1 || cveCalls.Load() != 1 || len(p.Findings) != 1 || p.Findings[0].Title != "Original advisory" {
		t.Fatal("severity-specific enrichment did not apply")
	}
}

func TestFailedSeveritySyncPreservesFindingsAndInvalidSeverityDoesNotStart(t *testing.T) {
	s := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": true}
		st.Settings.OSVURL = server.URL
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}}, Findings: []model.Finding{{ID: "critical", AssetID: "a", Severity: "CRITICAL"}, {ID: "low", AssetID: "a", Severity: "LOW"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.StartFiltered("p", "manual", "", "auto", "invalid"); !errors.Is(err, ErrInvalidSeverity) {
		t.Fatal("invalid severity accepted")
	}
	st, _ := s.Read()
	if st.Projects[0].Syncing || len(st.Projects[0].Runs) != 0 {
		t.Fatal("invalid severity changed project state")
	}
	if err = e.StartFiltered("p", "manual", "", "auto", "CRITICAL"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if p.Runs[0].Status != "failed" || len(p.Findings) != 2 {
		t.Fatal("failed severity sync hid prior findings")
	}
}

func TestUnratedScopeIncludesMissingSeverity(t *testing.T) {
	prior := []model.Finding{{ID: "missing", AssetID: "a", Severity: ""}, {ID: "critical", AssetID: "a", Severity: "CRITICAL"}}
	updates := severityCandidates([]model.Finding{{ID: "new", AssetID: "a", Severity: "UNKNOWN"}}, prior, "", "UNKNOWN")
	result := retainOutsideScope(updates, prior, "", "UNKNOWN")
	if len(result) != 2 || result[0].ID != "critical" || result[1].ID != "new" {
		t.Fatalf("unrated scope lost other severities: %+v", result)
	}
}
