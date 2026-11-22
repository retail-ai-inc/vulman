package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"vulman/internal/model"
	"vulman/internal/store"
)

func TestDesktopIncrementalPollingRedactsCredentialsAndKeepsFindingPayloadsSeparate(t *testing.T) {
	db := newTestStore(t)
	token := rand.Text()
	if err := db.Update(func(state *model.State) error {
		state.Settings.Tokens["openai"] = token
		state.Projects = []model.Project{{ID: "p", Name: "Demo", Findings: []model.Finding{{ID: "CVE-one", Description: strings.Repeat("private finding description", 1000)}}, Runs: []model.Run{{ID: "r", Status: "running"}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	desktop := &Desktop{store: db}
	initial, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateRun("p", "r", func(_ *store.RunProject, run *model.Run) error {
		run.Logs = append(run.Logs, model.SyncLog{Event: "page"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	progress, err := desktop.StateSince(initial.Version)
	if err != nil || progress.State != nil || progress.Delta == nil || progress.MetadataChanged || progress.BaseVersion != initial.Version {
		t.Fatalf("wrong incremental response: %v", err)
	}
	body, err := json.Marshal(progress)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte(token)) || bytes.Contains(body, []byte("private finding description")) || len(body) > 8<<10 {
		t.Fatal("progress response included unrelated data")
	}
	if err := db.Update(func(state *model.State) error { state.Settings.Language = "ja"; return nil }); err != nil {
		t.Fatal(err)
	}
	settings, err := desktop.StateSince(progress.Version)
	if err != nil || !settings.MetadataChanged || settings.Delta == nil || settings.Delta.Settings == nil || settings.Delta.Settings.Tokens != nil || !settings.TokenStatus["openai"] {
		t.Fatalf("credential status or settings delta was incorrect: %v", err)
	}
	body, err = json.Marshal(settings)
	if err != nil || bytes.Contains(body, []byte(token)) {
		t.Fatal("settings delta exposed a saved credential")
	}
}

func TestDesktopPollingResetsForeignGenerationAndInvalidCursors(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	initial, err := desktop.State()
	if err != nil {
		t.Fatal(err)
	}
	for _, cursor := range []string{"not-a-cursor", "99:" + strings.SplitN(initial.Version, ":", 2)[1]} {
		state, err := desktop.StateSince(cursor)
		if err != nil || state.State == nil || state.Delta != nil {
			t.Fatalf("invalid workspace cursor did not reset: %v", err)
		}
	}
}
