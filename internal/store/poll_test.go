package store

import (
	"bytes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

func pollFixture(t *testing.T) (*Store, ChangeSet) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeTestStore(t, s) })
	if err := s.Update(func(state *model.State) error { *state = recordFixture(); return nil }); err != nil {
		t.Fatal(err)
	}
	initial, err := s.ReadChanges("")
	if err != nil || initial.Full == nil || initial.View == nil || initial.Delta != nil {
		t.Fatalf("initial snapshot failed: %v", err)
	}
	return s, initial
}

func TestPollRevisionsSeparateFindingsMetadataAndWorkflows(t *testing.T) {
	s, initial := pollFixture(t)
	before, valid := s.decodeCursor(initial.Version)
	if !valid {
		t.Fatal("generated cursor is invalid")
	}
	projectID := initial.Full.Projects[0].ID
	if err := s.UpdateRun(projectID, "active", func(_ *RunProject, run *model.Run) error {
		run.Logs = append(run.Logs, model.SyncLog{Event: "page"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	progress, err := s.ReadChanges(initial.Version)
	if err != nil || progress.Full != nil || progress.View != nil || progress.Delta == nil || progress.Delta.Settings != nil || progress.Delta.ProjectOrder != nil {
		t.Fatalf("progress returned workspace data: %v", err)
	}
	if len(progress.Delta.Projects) != 1 {
		t.Fatal("unrelated project was returned")
	}
	patch := progress.Delta.Projects[0]
	if patch.Metadata != nil || patch.Findings != nil || patch.Workflows == nil || len(patch.Workflows.Updated) != 1 || patch.Workflows.Updated[0].Run.ID != "active" {
		t.Fatalf("wrong progress delta: %+v", patch)
	}
	current, _ := s.decodeCursor(progress.Version)
	if current.Projects[0].Findings != before.Projects[0].Findings || current.Projects[0].Metadata != before.Projects[0].Metadata || current.Projects[0].Workflow <= before.Projects[0].Workflow {
		t.Fatal("progress changed the wrong revisions")
	}
	if err := s.Update(func(state *model.State) error { state.Projects[0].Findings[0].Title = "Updated title"; return nil }); err != nil {
		t.Fatal(err)
	}
	findings, err := s.ReadChanges(progress.Version)
	if err != nil || findings.Delta == nil || len(findings.Delta.Projects) != 1 {
		t.Fatalf("findings delta failed: %v", err)
	}
	patch = findings.Delta.Projects[0]
	if patch.Findings == nil || (*patch.Findings)[0].Title != "Updated title" || patch.Workflows != nil || patch.Metadata != nil || findings.View != nil {
		t.Fatal("finding-only change reloaded other data")
	}
	after, _ := s.decodeCursor(findings.Version)
	if after.Projects[0].Findings <= current.Projects[0].Findings || after.Projects[0].Workflow != current.Projects[0].Workflow {
		t.Fatal("finding change advanced workflow revisions")
	}
}

type pollReadCipher struct {
	cipher.AEAD
	identities []string
}

func (a *pollReadCipher) Open(dst, nonce, ciphertext, associated []byte) ([]byte, error) {
	a.identities = append(a.identities, string(associated))
	return a.AEAD.Open(dst, nonce, ciphertext, associated)
}

func TestProgressPollNeverDecryptsFindingsSettingsOrUnchangedRuns(t *testing.T) {
	s, initial := pollFixture(t)
	if err := s.UpdateRun(initial.Full.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
		t.Fatal(err)
	}
	tracker := &pollReadCipher{AEAD: s.aead}
	s.aead = tracker
	change, err := s.ReadChanges(initial.Version)
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range tracker.identities {
		if strings.Contains(identity, "/findings/") || identity == "vulman-record-v2:settings" || strings.Contains(identity, "/runs/1/") {
			t.Fatalf("unrelated payload decrypted: %s", identity)
		}
	}
	if change.View != nil || change.Full != nil || len(tracker.identities) > 10 {
		t.Fatal("progress poll reconstructed the workspace")
	}
	tracker.identities = nil
	idle, err := s.ReadChanges(change.Version)
	if err != nil || idle.Delta != nil || idle.Full != nil || len(tracker.identities) != 0 {
		t.Fatal("unchanged poll decrypted records")
	}
}

func TestPollCumulativeDeltasHandleSkippedUpdatesRunDeletionAndProjectDeletion(t *testing.T) {
	s, initial := pollFixture(t)
	id := initial.Full.Projects[0].ID
	for i := 0; i < 3; i++ {
		if err := s.UpdateRun(id, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Update(func(state *model.State) error {
		state.Projects[0].Runs = state.Projects[0].Runs[:1]
		state.Projects = state.Projects[:1]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	change, err := s.ReadChanges(initial.Version)
	if err != nil || change.Delta == nil || change.Delta.ProjectOrder == nil || !slices.Equal(*change.Delta.ProjectOrder, []string{id}) {
		t.Fatalf("project deletion missing: %v", err)
	}
	workflow := change.Delta.Projects[0].Workflows
	if workflow == nil || !slices.Equal(workflow.Order, []string{"active"}) || len(workflow.Updated) != 1 || workflow.Updated[0].Run.Count != 6 {
		t.Fatal("cumulative changes or deleted runs were lost")
	}
}

func TestPollPublishesAssessmentAndSettingsChangesInOneSnapshot(t *testing.T) {
	s, initial := pollFixture(t)
	if err := s.Update(func(state *model.State) error {
		state.Settings.Language = "en"
		state.Projects[0].Syncing = false
		state.Projects[0].Findings = nil
		state.Projects[0].Runs[0].Status = "complete"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	change, err := s.ReadChanges(initial.Version)
	if err != nil || change.Full != nil || change.View == nil || change.Delta.Settings == nil || change.Delta.Settings.Language != "en" {
		t.Fatalf("settings delta missing: %v", err)
	}
	patch := change.Delta.Projects[0]
	if patch.Metadata == nil || patch.Metadata.Syncing || patch.Findings == nil || *patch.Findings != nil || patch.Workflows == nil || patch.Workflows.Updated[0].Run.Status != "complete" {
		t.Fatal("assessment changes were split across snapshots")
	}
}

func TestPollRevisionsRollBackWithRecordsAndSurviveReopening(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Update(func(state *model.State) error { *state = recordFixture(); return nil }); err != nil {
		t.Fatal(err)
	}
	initial, err := s.ReadChanges("")
	if err != nil {
		t.Fatal(err)
	}
	abort := errors.New("rollback revisions")
	if err := s.UpdateRun(initial.Full.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return abort }); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	unchanged, err := s.ReadChanges(initial.Version)
	if err != nil || unchanged.Version != initial.Version || unchanged.Delta != nil {
		t.Fatal("rollback advanced revisions")
	}
	if err := s.UpdateRun(initial.Full.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	change, err := s.ReadChanges(initial.Version)
	if err != nil || change.Full != nil || change.Delta == nil || change.Delta.Projects[0].Findings != nil {
		t.Fatalf("committed revision was lost after reopen: %v", err)
	}
}

func TestPollInvalidForeignLegacyAndFutureCursorsFallBackToFullSnapshot(t *testing.T) {
	s, initial := pollFixture(t)
	other, foreign := pollFixture(t)
	_ = other
	future, _ := s.decodeCursor(initial.Version)
	future.Sequence++
	futureToken, err := s.encodeCursor(future)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"", "42", "p1.bad.signature", initial.Version + "changed", foreign.Version, futureToken, strings.Repeat("x", (1<<20)+1)} {
		change, err := s.ReadChanges(token)
		if err != nil || change.Full == nil || change.Delta != nil || change.Version == "" {
			t.Fatalf("invalid cursor did not reset: %v", err)
		}
	}
}

func TestRecordRevisionUpgradeTouchesOnlyEncryptedHeaders(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixture := recordFixture()
	if err := s.Update(func(state *model.State) error { *state = fixture; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))
		manifest, err := s.readManifest(root)
		if err != nil {
			return err
		}
		manifest.RevisionsReady = false
		manifest.SettingsRevision, manifest.ProjectOrderRevision = 0, 0
		for _, id := range manifest.Projects {
			key := s.projectKey(id)
			bucket := root.Bucket([]byte("projects")).Bucket(key)
			identity := fmt.Sprintf("projects/%x", key)
			record, err := s.readProject(bucket, identity, id, false)
			if err != nil {
				return err
			}
			record.MetadataRevision, record.FindingsRevision, record.WorkflowRevision = 0, 0, 0
			record.RunRevisions = nil
			if err := s.writeRecord(bucket, []byte("metadata"), identity+"/metadata", record); err != nil {
				return err
			}
		}
		return s.writeRecord(root, []byte("manifest"), "manifest", manifest)
	}); err != nil {
		t.Fatal(err)
	}
	before := workspaceCiphertexts(t, s)
	abort := errors.New("rollback revision initialization")
	err = s.db.Update(func(tx *bolt.Tx) error {
		if err := s.initializeRevisions(tx, tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) || !reflect.DeepEqual(before, workspaceCiphertexts(t, s)) {
		t.Fatal("revision initialization did not roll back")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	after := workspaceCiphertexts(t, s)
	for key, data := range before {
		// Manifest and metadata keys are the only values allowed to change.
		if !bytes.HasSuffix([]byte(key), []byte(fmt.Sprintf("/%x", []byte("metadata")))) && !bytes.HasSuffix([]byte(key), []byte(fmt.Sprintf("/%x", []byte("manifest")))) && !bytes.Equal(data, after[key]) {
			t.Fatal("revision upgrade rewrote a payload")
		}
	}
	change, err := s.ReadChanges("")
	if err != nil || change.Full == nil || !reflect.DeepEqual(*change.Full, fixture) {
		t.Fatalf("revision upgrade lost data: %v", err)
	}
}

func TestIncrementalPollingPayloadStaysSmallWithManyFindings(t *testing.T) {
	s, initial := pollFixture(t)
	if err := s.Update(func(state *model.State) error {
		state.Projects[0].Findings = make([]model.Finding, 10000)
		for i := range state.Projects[0].Findings {
			state.Projects[0].Findings[i] = model.Finding{ID: fmt.Sprint(i), Description: strings.Repeat("description", 20)}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	initial, err := s.ReadChanges("")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRun(initial.Full.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
		t.Fatal(err)
	}
	change, err := s.ReadChanges(initial.Version)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(change.Delta)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 32<<10 || bytes.Contains(body, []byte(`"findings":`)) || bytes.Contains(body, []byte("descriptiondescription")) {
		t.Fatalf("progress payload included finding data: %d bytes", len(body))
	}
}

func TestNoOpWritesAdvanceOnlyTheWorkspaceSequence(t *testing.T) {
	s, initial := pollFixture(t)
	if err := s.Update(func(*model.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	next, err := s.ReadChanges(initial.Version)
	if err != nil || next.Full != nil || next.View != nil || next.Delta == nil || len(next.Delta.Projects) != 0 || next.Delta.Settings != nil || next.Version == initial.Version {
		t.Fatalf("no-op write reloaded records: %v", err)
	}
}
