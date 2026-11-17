package engine

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
)

type controlTransport func(*http.Request) (*http.Response, error)

func (f controlTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func controlResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

func controlEngine(t *testing.T) (*store.Store, *Engine) {
	s := testStore(t)
	old := time.Now().Add(-time.Hour).UTC()
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"osv": true, "nvd": false, "cve": false}
		st.Projects = []model.Project{{ID: "p", Revision: 2, AssessedRevision: 1, LastSync: old, DataCheckedAt: old, Schedule: "daily", Assets: []model.Asset{{ID: "a", Name: "demo", Version: "1", Ecosystem: "npm"}}, Findings: []model.Finding{{ID: "old", AssetID: "a", Severity: "HIGH"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return s, e
}
func waitControlStatus(t *testing.T, s *store.Store, status string) model.Project {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, err := s.Read()
		if err != nil {
			t.Fatal(err)
		}
		if len(st.Projects[0].Runs) > 0 && st.Projects[0].Runs[0].Status == status {
			return st.Projects[0]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("workflow did not become %s", status)
	return model.Project{}
}
func signalControl(t *testing.T, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("operation did not start")
	}
}

func TestPausePreventsNextDatabasePageAndResumeContinuesSameRun(t *testing.T) {
	s, e := controlEngine(t)
	started, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	var calls atomic.Int32
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		if calls.Add(1) == 1 {
			close(started)
			select {
			case <-release:
			case <-r.Context().Done():
				return nil, r.Context().Err()
			}
			return controlResponse(`{"vulns":[{"id":"new-1"}],"next_page_token":"next"}`), nil
		}
		return controlResponse(`{"vulns":[{"id":"new-2"}]}`), nil
	})
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	signalControl(t, started)
	st, _ := s.Read()
	id := st.Projects[0].Runs[0].ID
	if err := e.Control("p", id, "pause"); err != nil {
		t.Fatal(err)
	}
	if waitControlStatus(t, s, "pausing").Syncing != true {
		t.Fatal("pausing run lost lock")
	}
	if e.Start("p", "manual") == nil || e.Control("p", id, "pause") == nil || e.Control("other", id, "stop") == nil || e.Control("p", "stale", "stop") == nil {
		t.Fatal("overlap or stale controls accepted")
	}
	unblock()
	paused := waitControlStatus(t, s, "paused")
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 || !paused.Syncing || paused.Runs[0].PausedAt.IsZero() || paused.Findings[0].ID != "old" {
		t.Fatal("paused run advanced or overwrote findings")
	}
	if err := e.Control("p", id, "resume"); err != nil {
		t.Fatal(err)
	}
	p := awaitRun(t, s)
	if p.Runs[0].ID != id || p.Runs[0].Status != "complete" || len(p.Findings) != 2 || p.Runs[0].PausedSeconds <= 0 || !p.Runs[0].PausedAt.IsZero() {
		t.Fatalf("resume did not complete same run: %+v", p)
	}
	if !errors.Is(e.Control("p", id, "stop"), ErrRunNotActive) {
		t.Fatal("completed run accepted stop")
	}
}

func TestStopCancelsActiveOrPausedRunAndDiscardsUnsavedResults(t *testing.T) {
	for _, paused := range []bool{false, true} {
		t.Run(map[bool]string{true: "paused", false: "in flight"}[paused], func(t *testing.T) {
			s, e := controlEngine(t)
			first, release, second, cancelled := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var calls atomic.Int32
			e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					close(first)
					select {
					case <-release:
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return controlResponse(`{"vulns":[{"id":"unsaved-new"}],"next_page_token":"next"}`), nil
				}
				close(second)
				<-r.Context().Done()
				close(cancelled)
				return nil, r.Context().Err()
			})
			if err := e.Start("p", "manual"); err != nil {
				t.Fatal(err)
			}
			signalControl(t, first)
			before, _ := s.Read()
			p := before.Projects[0]
			id := p.Runs[0].ID
			if paused {
				if err := e.Control("p", id, "pause"); err != nil {
					t.Fatal(err)
				}
			}
			unblock()
			if paused {
				waitControlStatus(t, s, "paused")
			} else {
				signalControl(t, second)
			}
			if err := e.Control("p", id, "stop"); err != nil {
				t.Fatal(err)
			}
			if !paused {
				signalControl(t, cancelled)
			}
			after := awaitRun(t, s)
			if after.Runs[0].Status != "stopped" || after.Runs[0].Count != 0 || !reflect.DeepEqual(after.Findings, p.Findings) || !after.LastSync.Equal(p.LastSync) || !after.DataCheckedAt.Equal(p.DataCheckedAt) || after.AssessedRevision != p.AssessedRevision || !after.NextRun.Equal(p.NextRun) {
				t.Fatalf("stop changed saved assessment: %+v", after)
			}
			if after.Syncing || e.Control("p", id, "resume") == nil {
				t.Fatal("stopped run remained active")
			}
			for _, step := range after.Runs[0].Steps {
				if step.Status == "running" || step.Status == "pending" {
					t.Fatal("stopped workflow retained active steps")
				}
			}
			if err := e.StartAssetMode("p", "manual", "a", "local"); err != nil {
				t.Fatal(err)
			}
			if !errors.Is(e.Control("p", id, "stop"), ErrRunNotActive) {
				t.Fatal("old run controlled new run")
			}
			if awaitRun(t, s).Runs[0].ID == id {
				t.Fatal("new sync reused stopped run")
			}
		})
	}
}

func TestShutdownWakesPausedWorkflowAndRestartRecoversControlStates(t *testing.T) {
	s, e := controlEngine(t)
	started, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return controlResponse(`{}`), nil
	})
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	signalControl(t, started)
	st, _ := s.Read()
	id := st.Projects[0].Runs[0].ID
	if err := e.Control("p", id, "pause"); err != nil {
		t.Fatal(err)
	}
	unblock()
	waitControlStatus(t, s, "paused")
	done := make(chan struct{})
	go func() { e.Close(); close(done) }()
	signalControl(t, done)
	if awaitRun(t, s).Runs[0].Status != "interrupted" {
		t.Fatal("shutdown did not interrupt paused run")
	}
	if err := s.Update(func(st *model.State) error {
		st.Projects[0].Syncing = true
		st.Projects[0].Runs = []model.Run{{Status: "paused", PausedAt: time.Now().Add(-time.Minute)}, {Status: "pausing"}, {Status: "stopping"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	restarted.Close()
	st, _ = s.Read()
	for _, r := range st.Projects[0].Runs {
		if r.Status != "interrupted" || !r.PausedAt.IsZero() {
			t.Fatal("control state not recovered")
		}
	}
}
