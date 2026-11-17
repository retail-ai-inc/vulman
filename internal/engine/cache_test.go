package engine

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
)

func TestCachedAssessmentAndForcedRefreshHaveDistinctFreshness(t *testing.T) {
	s := testStore(t)
	var calls atomic.Int32
	var empty atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body := `{"vulns":[{"id":"GHSA-demo","summary":"Issue"}]}`
		if empty.Load() {
			body = `{}`
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write mock OSV response: %v", err)
		}
	}))
	defer server.Close()
	next := time.Now().Add(time.Hour).UTC()
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": true}
		st.Settings.OSVURL = server.URL
		st.Projects = []model.Project{{ID: "p", Revision: 1, Schedule: "daily", NextRun: next, Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	first := awaitRun(t, s)
	if first.DataCheckedAt.IsZero() || first.Runs[0].Steps[0].Progress.CacheStatus != "network" {
		t.Fatal("upstream freshness not recorded")
	}
	if err = e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	cached := awaitRun(t, s)
	if calls.Load() != 1 || cached.Runs[0].Steps[0].Progress.CacheStatus != "cache" || !cached.DataCheckedAt.Equal(first.DataCheckedAt) {
		t.Fatal("cached assessment fetched data or advanced source freshness")
	}
	beforeLocal := cached.NextRun
	if err = e.StartAssetMode("p", "manual", "", "local"); err != nil {
		t.Fatal(err)
	}
	local := awaitRun(t, s)
	if calls.Load() != 1 || !local.NextRun.Equal(beforeLocal) || local.Runs[0].Mode != "local" {
		t.Fatal("cache-only assessment used network or delayed scheduled sync")
	}
	empty.Store(true)
	if err = e.StartAssetMode("p", "manual", "", "refresh"); err != nil {
		t.Fatal(err)
	}
	forced := awaitRun(t, s)
	if calls.Load() != 2 || len(forced.Findings) != 0 || forced.Runs[0].Status != "complete" || !forced.DataCheckedAt.After(first.DataCheckedAt) {
		t.Fatal("forced refresh did not replace obsolete findings")
	}
	if err = s.Update(func(st *model.State) error { st.Projects[0].ScanCode = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = e.StartAssetMode("p", "manual", "", "local"); err != nil {
		t.Fatal(err)
	}
	skipped := awaitRun(t, s)
	if calls.Load() != 2 || skipped.Runs[0].Status != "partial" {
		t.Fatal("cache-only assessment claimed complete scanner coverage")
	}
	for _, step := range skipped.Runs[0].Steps {
		if step.Kind == "scanner" && step.Status != "skipped" {
			t.Fatal("cache-only mode executed code scanners")
		}
	}
}
