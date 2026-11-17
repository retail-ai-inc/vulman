package engine

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("close test store: %v", err)
		}
	})
	return s
}
func awaitRun(t *testing.T, s *store.Store) model.Project {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Read()
		if err != nil {
			t.Fatal(err)
		}
		if !st.Projects[0].Syncing && len(st.Projects[0].Runs) > 0 {
			return st.Projects[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("assessment did not finish")
	return model.Project{}
}

func TestSyncLifecycleAndOverlap(t *testing.T) {
	s := testStore(t)
	started := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		if _, err := fmt.Fprint(w, `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-2024-0001"}}]}`); err != nil {
			t.Errorf("write mock NVD response: %v", err)
		}
	}))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.NVDURL = server.URL
		st.Settings.Sources["cve"] = false
		st.Projects = []model.Project{{ID: "p", Name: "App", Revision: 2, Schedule: "daily", Assets: []model.Asset{{ID: "a", Kind: "database", Name: "redis", Version: "7"}}}}
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
	<-started
	if err = e.Start("p", "manual"); err == nil {
		t.Fatal("overlapping sync accepted")
	}
	if err = e.StartAsset("p", "manual", "a"); err == nil {
		t.Fatal("component sync overlapped an active project sync")
	}
	close(release)
	p := awaitRun(t, s)
	if p.Runs[0].Status != "complete" || len(p.Findings) != 1 || p.AssessedRevision != 2 || p.NextRun.IsZero() || p.LastSync.IsZero() {
		t.Fatalf("incorrect assessment: %+v", p)
	}
}

func TestFailedRefreshPreservesPriorFindings(t *testing.T) {
	s := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Header().Set("Retry-After", "60"); w.WriteHeader(429) }))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.NVDURL = server.URL
		st.Settings.Sources["cve"] = false
		st.Projects = []model.Project{{ID: "p", Revision: 2, AssessedRevision: 1, Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}, Findings: []model.Finding{{ID: "CVE-old", AssetID: "a", Severity: "HIGH"}}}}
		return nil
	}); err != nil {
		t.Fatalf("seed prior findings: %v", err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err = e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if len(p.Findings) != 1 || p.Runs[0].Status != "failed" || p.AssessedRevision != 1 {
		t.Fatal("failed scan hid prior findings or marked inventory current")
	}
}

func TestRestartRecoversInterruptedRuns(t *testing.T) {
	s := testStore(t)
	if err := s.Update(func(st *model.State) error {
		st.Projects = []model.Project{{ID: "p", Syncing: true, Runs: []model.Run{{Status: "running", Steps: []model.SyncStep{{ID: "active", Status: "running"}, {ID: "pending", Status: "pending"}}}}}}
		return nil
	}); err != nil {
		t.Fatalf("seed interrupted run: %v", err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	e.Close()
	st, _ := s.Read()
	if st.Projects[0].Syncing || st.Projects[0].Runs[0].Status != "interrupted" {
		t.Fatal("interrupted job not recovered")
	}
	run := st.Projects[0].Runs[0]
	if run.Steps[0].Status != "interrupted" || run.Steps[1].Status != "skipped" || len(run.Logs) == 0 {
		t.Fatal("interrupted workflow was not recovered")
	}
	if err = e.Start("p", "manual"); err == nil {
		t.Fatal("closed engine accepted work")
	}
}

func TestCancelledNVDWaitReturnsPromptly(t *testing.T) {
	e, err := New(testStore(t))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = e.Sources.NVD(ctx, model.Asset{Name: "demo"}, model.Defaults().Settings)
	if err == nil {
		t.Fatal("cancelled request succeeded")
	}
}

func TestDueSchedulesIncludeOverdueAndExcludeRunning(t *testing.T) {
	now := time.Now()
	st := model.State{Projects: []model.Project{
		{ID: "overdue", Schedule: "daily", NextRun: now.Add(-time.Hour)},
		{ID: "running", Schedule: "hourly", Syncing: true, NextRun: now.Add(-time.Hour)},
		{ID: "future", Schedule: "weekly", NextRun: now.Add(time.Hour)},
		{ID: "disabled", Schedule: "off", NextRun: now.Add(-time.Hour)},
	}}
	ids := dueProjects(st, now)
	if len(ids) != 1 || ids[0] != "overdue" {
		t.Fatalf("incorrect due projects: %v", ids)
	}
}

func TestComponentSyncReplacesOnlyItsFindings(t *testing.T) {
	for _, tc := range []struct {
		name        string
		fail, empty bool
	}{
		{name: "new findings"}, {name: "no vulnerabilities", empty: true}, {name: "upstream failure", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testStore(t)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("keywordSearch") != "demo-a" {
					t.Error("queried an unselected component")
				}
				if tc.fail {
					w.Header().Set("Retry-After", "60")
					w.WriteHeader(429)
					return
				}
				body := `{"totalResults":1,"vulnerabilities":[{"cve":{"id":"CVE-new"}}]}`
				if tc.empty {
					body = `{"totalResults":0,"vulnerabilities":[]}`
				}
				if _, err := fmt.Fprint(w, body); err != nil {
					t.Errorf("write mock NVD response: %v", err)
				}
			}))
			defer server.Close()
			last := time.Now().Add(-time.Hour).UTC()
			next := time.Now().Add(time.Hour).UTC()
			other := model.Finding{ID: "CVE-new", AssetID: "b", Component: "demo-b", Severity: "HIGH"}
			code := model.Finding{ID: "CVE-code", AssetID: "code:demo", Component: "demo", Match: "scanner", Severity: "CRITICAL"}
			if err := s.Update(func(st *model.State) error {
				st.Settings.Sources["cve"] = false
				st.Settings.NVDURL = server.URL
				st.Projects = []model.Project{{ID: "p", Revision: 2, AssessedRevision: 1, LastSync: last, NextRun: next, Schedule: "daily", ScanCode: true,
					Assets:   []model.Asset{{ID: "a", Name: "demo-a", Version: "1"}, {ID: "b", Name: "demo-b", Version: "2"}},
					Findings: []model.Finding{{ID: "CVE-old", AssetID: "a", Severity: "LOW"}, other, code}}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			e, err := New(s)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			if err = e.StartAsset("p", "manual", "a"); err != nil {
				t.Fatal(err)
			}
			p := awaitRun(t, s)
			run := p.Runs[0]
			if len(run.Steps) != 2 || run.Steps[0].ID != "nvd:a" || run.Steps[1].Kind != "save" {
				t.Fatal("component workflow contains unrelated work")
			}
			if !p.LastSync.Equal(last) || !p.NextRun.Equal(next) || p.AssessedRevision != 1 {
				t.Fatal("component sync changed full-project freshness or schedule")
			}
			if run.AssetID != "a" || run.AssetName != "demo-a 1" {
				t.Fatalf("missing assessment scope: %+v", run)
			}
			foundOther, foundCode, selected := false, false, []model.Finding{}
			for _, f := range p.Findings {
				switch f.AssetID {
				case "a":
					selected = append(selected, f)
				case "b":
					foundOther = f.ID == other.ID && f.Severity == other.Severity
				case code.AssetID:
					foundCode = f.ID == code.ID && f.Severity == code.Severity
				}
			}
			if !foundOther || !foundCode {
				t.Fatal("unrelated findings changed")
			}
			if tc.fail {
				if run.Steps[0].Status != "failed" {
					t.Fatal("failed database query was not reflected in workflow")
				}
				if run.Status != "failed" || run.Count != 1 || len(selected) != 1 || selected[0].ID != "CVE-old" {
					t.Fatal("failed assessment lost previous component findings")
				}
			} else {
				if run.Status != "complete" {
					t.Fatalf("component assessment ran project-wide scanners or failed: %+v", run)
				}
				if tc.empty {
					if len(selected) != 0 || run.Count != 0 {
						t.Fatal("successful empty component result did not clear its old findings")
					}
				} else if len(selected) != 1 || selected[0].ID != "CVE-new" || run.Count != 1 {
					t.Fatal("component findings were not replaced")
				}
			}
		})
	}
}

func TestUnknownComponentCannotStartAssessment(t *testing.T) {
	s := testStore(t)
	if err := s.Update(func(st *model.State) error {
		st.Projects = []model.Project{{ID: "p", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1"}}}, {ID: "other", Assets: []model.Asset{{ID: "b", Name: "other", Version: "1"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	for _, id := range []string{"missing", "b"} {
		if err := e.StartAsset("p", "manual", id); !errors.Is(err, ErrAssetNotFound) {
			t.Fatalf("invalid component accepted: %v", err)
		}
	}
	st, _ := s.Read()
	if st.Projects[0].Syncing || len(st.Projects[0].Runs) != 0 {
		t.Fatal("invalid selection changed assessment state")
	}
}

func TestDefaultSyncStillAssessesEveryComponent(t *testing.T) {
	s := testStore(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := fmt.Fprint(w, `{"vulns":[{"id":"GHSA-demo","summary":"Issue"}]}`); err != nil {
			t.Errorf("write mock OSV response: %v", err)
		}
	}))
	defer server.Close()
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": false, "cve": false, "osv": true}
		st.Settings.OSVURL = server.URL
		st.Projects = []model.Project{{ID: "p", Revision: 1, Assets: []model.Asset{{ID: "a", Name: "one", Version: "1", Ecosystem: "npm"}, {ID: "b", Name: "two", Version: "2", Ecosystem: "npm"}}}}
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
	p := awaitRun(t, s)
	if len(p.Findings) != 2 || p.Runs[0].Count != 2 || p.Runs[0].AssetID != "" || p.Runs[0].Status != "complete" || p.AssessedRevision != 1 {
		t.Fatalf("default sync did not assess every component: %+v", p)
	}
}
