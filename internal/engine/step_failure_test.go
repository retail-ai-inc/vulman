package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/store"
)

func TestStepFailuresSurviveLogTruncationAndReopening(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if s != nil {
			if err := s.Close(); err != nil {
				t.Errorf("close fixture: %v", err)
			}
		}
	})

	publicFailure := apperror.New("cve_download_rate_limited_retry_later", "CVE download rate limited; retry later")
	if err := s.Update(func(state *model.State) error {
		state.Projects = []model.Project{{ID: "p", Runs: []model.Run{{ID: "r", Steps: []model.SyncStep{
			{ID: "nvd:a", Kind: "nvd", Status: "running"},
			{ID: "osv:a", Kind: "osv", Status: "running"},
			{ID: "scanner", Kind: "scanner", Status: "running"},
			{ID: "save", Kind: "save", Status: "failed", Failure: apperror.Public(publicFailure)},
		}}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := s.ReadChanges("")
	if err != nil {
		t.Fatal(err)
	}

	tracker := newTracker(s, "p", "r")
	tracker.finish("nvd:a", 3, publicFailure)
	tracker.finish("osv:a", 0, context.DeadlineExceeded)
	privateDiagnostic := rand.Text()
	tracker.finish("scanner", 0, errors.New(privateDiagnostic))
	tracker.start("save")
	state, err := s.Read()
	if err != nil || state.Projects[0].Runs[0].Steps[3].Failure != nil {
		t.Fatalf("restarting a step retained its previous failure: %v", err)
	}
	tracker.finish("save", 3, nil)
	tracker.update(func(run *model.Run) {
		for range model.MaxSyncLogs + 1 {
			addLog(run, "save", "page", "later progress")
		}
	})

	change, err := s.ReadChanges(before.Version)
	if err != nil || change.Delta == nil || len(change.Delta.Projects) != 1 || change.Delta.Projects[0].Workflows == nil {
		t.Fatalf("failure details missing from incremental polling: %v", err)
	}
	body, err := json.Marshal(change.Delta)
	if err != nil || bytes.Contains(body, []byte(privateDiagnostic)) {
		t.Fatal("raw diagnostic escaped into a workflow response")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s = nil
	s, err = store.OpenExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	state, err = s.Read()
	if err != nil {
		t.Fatal(err)
	}
	run := state.Projects[0].Runs[0]
	for _, entry := range run.Logs {
		if entry.Event == "failed" || entry.Event == "interrupted" {
			t.Fatal("fixture did not expire the original failure logs")
		}
	}
	for index, expected := range []struct{ status, code string }{
		{"failed", "cve_download_rate_limited_retry_later"},
		{"interrupted", "timeout"},
		{"failed", "unexpected"},
		{"complete", ""},
	} {
		step := run.Steps[index]
		if step.Status != expected.status || expected.code == "" && step.Failure != nil ||
			expected.code != "" && (step.Failure == nil || step.Failure.Code != expected.code) {
			t.Fatalf("wrong retained failure for step %d: %+v", index, step)
		}
	}
	if run.Steps[0].Failure.English() != publicFailure.Error() {
		t.Fatal("the recorded failure lost its public explanation")
	}
}
