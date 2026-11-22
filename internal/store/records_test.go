package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

func recordFixture() model.State {
	state := model.Defaults()
	state.Settings.Language = "ja"
	state.Settings.Tokens["openai"] = rand.Text()
	project := model.Project{ID: "private-project-identity", Name: "Private project name", RepositoryURLs: []string{"https://github.com/private-owner/private-repository"}, Syncing: true, Schedule: "daily", Runs: []model.Run{
		{ID: "active", Status: "running", Count: 3, Steps: []model.SyncStep{{ID: "scanner", Status: "running"}}, SeverityCounts: map[string]int{"HIGH": 3}},
		{ID: "history", Status: "complete", Logs: []model.SyncLog{}},
	}}
	for i := 0; i < 600; i++ {
		project.Findings = append(project.Findings, model.Finding{ID: fmt.Sprintf("CVE-2026-%d", i%10), AssetID: fmt.Sprintf("component-%d", i), Title: "Private vulnerability title", Description: "Private advisory description", Sources: []string{"OSV"}, Severity: "HIGH"})
	}
	for i := 0; i < 130; i++ {
		project.Runs[0].Logs = append(project.Runs[0].Logs, model.SyncLog{Event: "page", Detail: fmt.Sprint(i)})
	}
	state.Projects = []model.Project{project, {ID: "empty", Name: "Empty", Findings: []model.Finding{}, Runs: []model.Run{}}}
	return state
}

func testRecordCipher(t testing.TB, key []byte) cipher.AEAD {
	t.Helper()
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

func legacyRoundTrip(t testing.TB, state model.State) model.State {
	t.Helper()
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	result := model.Defaults()
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

// Build the actual v1 layout directly; using Open would already upgrade it.
func seedLegacyRecords(t testing.TB, dir string, state model.State) ([]byte, []byte) {
	t.Helper()
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile), key, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := bolt.Open(filepath.Join(dir, databaseFile), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	aead := testRecordCipher(t, key)
	plain, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	legacy := aead.Seal(nonce, nonce, plain, []byte("vulman-state-v1"))
	err = db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucket([]byte("state"))
		if err != nil {
			return err
		}
		if err := bucket.Put([]byte("v1"), legacy); err != nil {
			return err
		}
		if err := bucket.SetSequence(41); err != nil {
			return err
		}
		cache, err := tx.CreateBucket([]byte("cache-v1"))
		if err != nil {
			return err
		}
		for _, name := range []string{"entries", "order", "meta"} {
			if _, err := cache.CreateBucket([]byte(name)); err != nil {
				return err
			}
		}
		if err := initializeCacheMetadata(cache); err != nil {
			return err
		}
		return applyCacheLimits(cache, state.Settings)
	})
	if err == nil {
		s := &Store{db: db, aead: aead}
		err = s.CachePut("legacy-response", CachedResponse{Data: json.RawMessage(`{"result":"private cached response"}`), CheckedAt: time.Now().UTC()})
	}
	if err := errors.Join(err, db.Close()); err != nil {
		t.Fatal(err)
	}
	return key, legacy
}

func workspaceCiphertexts(t testing.TB, s *Store) map[string][]byte {
	t.Helper()
	values := make(map[string][]byte)
	err := s.db.View(func(tx *bolt.Tx) error {
		var visit func(*bolt.Bucket, string) error
		visit = func(bucket *bolt.Bucket, path string) error {
			return bucket.ForEach(func(key, data []byte) error {
				identity := fmt.Sprintf("%s/%x", path, key)
				if data == nil {
					return visit(bucket.Bucket(key), identity)
				}
				values[identity] = bytes.Clone(data)
				return nil
			})
		}
		return visit(tx.Bucket([]byte("state")), "state")
	})
	if err != nil {
		t.Fatal(err)
	}
	return values
}

func TestLegacyRecordMigrationPreservesStateCacheKeyAndCatalogues(t *testing.T) {
	dir := t.TempDir()
	expected := legacyRoundTrip(t, recordFixture())
	key, legacy := seedLegacyRecords(t, dir, expected)
	for _, name := range []string{"vulman-cve.db", "vulman-nvd.db", "vulman-osv.db"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("untouched catalogue fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	s, err := OpenExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := s.Read()
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("migration changed workspace values: %v", err)
	}
	entry, found, err := s.CacheGet("legacy-response")
	if err != nil || !found || !bytes.Contains(entry.Data, []byte("private cached response")) {
		t.Fatalf("migration lost the API response cache: %v", err)
	}
	_, version, err := s.ReadSnapshot("")
	if err != nil || version != "42" {
		t.Fatalf("migration did not advance the snapshot version: %s, %v", version, err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		marker := tx.Bucket([]byte("state")).Get([]byte("v1"))
		if bytes.Equal(marker, legacy) {
			t.Fatal("stale legacy snapshot retained as an active value")
		}
		if _, err := s.readLegacy(tx); err == nil {
			t.Fatal("older readers would accept the migrated database as a workspace")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := workspaceCiphertexts(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenExisting(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, workspaceCiphertexts(t, s)) {
		t.Fatal("reopening migrated records rewrote their ciphertext")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	actualKey, err := root.ReadFile(keyFile)
	if err != nil || !bytes.Equal(actualKey, key) {
		t.Fatal("migration replaced the encryption key")
	}
	for _, name := range []string{"vulman-cve.db", "vulman-nvd.db", "vulman-osv.db"} {
		data, err := root.ReadFile(name)
		if err != nil || string(data) != "untouched catalogue fixture" {
			t.Fatalf("migration modified %s: %v", name, err)
		}
	}
	raw := readTestDatabase(t, dir)
	for _, private := range []string{expected.Settings.Tokens["openai"], expected.Projects[0].ID, expected.Projects[0].Name, "Private vulnerability title", "Private advisory description", "private-owner", "private cached response"} {
		if bytes.Contains(raw, []byte(private)) {
			t.Fatalf("workspace contained plaintext private data: %q", private)
		}
	}
}

func TestMigrationRollbackKeepsLegacyGeneration(t *testing.T) {
	dir := t.TempDir()
	key, legacy := seedLegacyRecords(t, dir, recordFixture())
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	db, err := bolt.Open(filepath.Join(dir, databaseFile), 0600, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	s := &Store{db: db, root: root, aead: testRecordCipher(t, key), indexKey: recordIndexKey(key)}
	abort := errors.New("abort after writing every migration record")
	err = db.Update(func(tx *bolt.Tx) error {
		if err := s.migrateRecords(tx); err != nil {
			return err
		}
		return abort
	})
	if !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("state"))
		if bucket.Bucket([]byte(recordsBucket)) != nil || !bytes.Equal(bucket.Get([]byte("v1")), legacy) || bucket.Sequence() != 41 {
			t.Fatal("rolled-back migration published a partial schema")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

type interruptedMigrationCipher struct {
	cipher.AEAD
	mode  string
	seals int
}

func (a *interruptedMigrationCipher) Seal(dst, nonce, plaintext, associated []byte) []byte {
	a.seals++
	if a.mode == "mid-records" && a.seals == 3 || a.mode == "before-publication" && string(associated) == "vulman-state-v1" || a.mode == "update-before-commit" && a.seals == 2 {
		os.Exit(23)
	}
	return a.AEAD.Seal(dst, nonce, plaintext, associated)
}

func changeRecordsAfterRestart(state *model.State) {
	state.Settings.Language = "en"
	state.Projects[0].Syncing = false
	for i := range state.Projects[0].Findings {
		state.Projects[0].Findings[i].Title = "Updated after restart"
	}
	state.Projects[0].Runs[0].Status = "complete"
	state.Projects[0].Runs[0].Logs = append(state.Projects[0].Runs[0].Logs, model.SyncLog{Event: "run_finished"})
}

func TestRecordProcessInterruption(t *testing.T) {
	if mode := os.Getenv("VULMAN_TEST_RECORD_MIGRATION"); mode != "" {
		// The parent sets the child's working directory to its disposable fixture.
		if strings.HasPrefix(mode, "update-") {
			s, err := OpenExisting(".")
			if err != nil {
				t.Fatal(err)
			}
			s.aead = &interruptedMigrationCipher{AEAD: s.aead, mode: mode}
			if err := s.Update(func(state *model.State) error { changeRecordsAfterRestart(state); return nil }); err != nil {
				t.Fatal(err)
			}
			if mode != "update-after-commit" {
				t.Fatal("update interruption point was not reached")
			}
			os.Exit(24)
		}
		root, err := os.OpenRoot(".")
		if err != nil {
			t.Fatal(err)
		}
		key, err := loadOrCreateKey(root, false)
		if err != nil {
			t.Fatal(err)
		}
		db, err := bolt.Open(databaseFile, 0600, nil)
		if err != nil {
			t.Fatal(err)
		}
		aead := &interruptedMigrationCipher{AEAD: testRecordCipher(t, key), mode: mode}
		s := &Store{db: db, root: root, aead: aead, indexKey: recordIndexKey(key)}
		if err := s.initialize(false); err != nil {
			t.Fatal(err)
		}
		if mode != "after-commit" {
			t.Fatal("interruption point was not reached")
		}
		os.Exit(24) // Deliberately skip Close and all deferred cleanup.
	}
	for _, mode := range []string{"mid-records", "before-publication", "after-commit", "update-before-commit", "update-after-commit"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			expected := legacyRoundTrip(t, recordFixture())
			_, legacy := seedLegacyRecords(t, dir, expected)
			var previousCursor string
			if strings.HasPrefix(mode, "update-") {
				s, err := OpenExisting(dir)
				if err != nil {
					t.Fatal(err)
				}
				before, err := s.ReadChanges("")
				if err != nil {
					t.Fatal(err)
				}
				previousCursor = before.Version
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(executable, "-test.run=^TestRecordProcessInterruption$") // #nosec G204 -- reexecutes this test binary with a fixed test selector.
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "VULMAN_TEST_RECORD_MIGRATION="+mode)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			committed := strings.HasSuffix(mode, "after-commit")
			if !errors.As(err, &exit) || committed && exit.ExitCode() != 24 || !committed && exit.ExitCode() != 23 {
				t.Fatalf("unexpected child exit: %v, %s", err, output)
			}
			db, err := bolt.Open(filepath.Join(dir, databaseFile), 0600, nil)
			if err != nil {
				t.Fatal(err)
			}
			err = db.View(func(tx *bolt.Tx) error {
				bucket := tx.Bucket([]byte("state"))
				if !committed && !strings.HasPrefix(mode, "update-") && (bucket.Bucket([]byte(recordsBucket)) != nil || !bytes.Equal(bucket.Get([]byte("v1")), legacy)) {
					t.Fatal("abrupt exit published an incomplete migration")
				}
				return nil
			})
			if err := errors.Join(err, db.Close()); err != nil {
				t.Fatal(err)
			}
			s, err := OpenExisting(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer closeTestStore(t, s)
			if mode == "update-after-commit" {
				changeRecordsAfterRestart(&expected)
			}
			actual, err := s.Read()
			if err != nil || !reflect.DeepEqual(expected, actual) {
				t.Fatalf("workspace did not recover after process exit: %v", err)
			}
			if previousCursor != "" {
				changes, err := s.ReadChanges(previousCursor)
				if err != nil {
					t.Fatal(err)
				}
				if committed {
					if changes.Delta == nil || len(changes.Delta.Projects) == 0 || changes.Delta.Projects[0].Findings == nil || changes.Delta.Projects[0].Workflows == nil {
						t.Fatal("committed revisions were lost during recovery")
					}
				} else if changes.Delta != nil || changes.Version != previousCursor {
					t.Fatal("interrupted update published revision counters")
				}
			}
		})
	}
}

func TestTargetedRunUpdateLeavesOtherRecordsUntouched(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	expected := recordFixture()
	if err := s.Update(func(state *model.State) error { *state = expected; return nil }); err != nil {
		t.Fatal(err)
	}
	before := workspaceCiphertexts(t, s)
	_, previousVersion, _ := s.ReadSnapshot("")
	if err := s.UpdateRun(expected.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
		t.Fatal(err)
	}
	after := workspaceCiphertexts(t, s)
	changed := 0
	for path, data := range before {
		if !bytes.Equal(after[path], data) {
			changed++
		}
	}
	if changed != 2 || len(before) != len(after) {
		t.Fatalf("progress changed %d records; expected the active run metadata and its revision header", changed)
	}
	expected.Projects[0].Runs[0].Count++
	actual, version, err := s.ReadSnapshot(previousVersion)
	if err != nil || actual == nil || version == previousVersion || !reflect.DeepEqual(*actual, expected) {
		t.Fatalf("run update did not publish one coherent snapshot: %v", err)
	}
}

func TestRecordTransactionsRollbackEveryChangedPayloadAndCacheEviction(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	expected := recordFixture()
	if err := s.Update(func(state *model.State) error { *state = expected; return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := s.CachePut(fmt.Sprint(i), CachedResponse{Data: json.RawMessage(`{}`), CheckedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	before := workspaceCiphertexts(t, s)
	_, version, _ := s.ReadSnapshot("")
	err = s.Update(func(state *model.State) error {
		state.Settings.CacheMaxEntries = 1
		state.Projects[0].Findings[0].Description = "uncommitted replacement"
		state.Projects[1].Runs = []model.Run{{ID: "invalid", PausedSeconds: math.NaN()}}
		return nil
	})
	if err == nil {
		t.Fatal("invalid final record was committed")
	}
	if !reflect.DeepEqual(before, workspaceCiphertexts(t, s)) {
		t.Fatal("full-state failure committed some changed records")
	}
	stats, err := s.CacheStats()
	if err != nil || stats.Entries != 3 || stats.Evictions != 0 {
		t.Fatalf("failed transaction changed the cache: %+v, %v", stats, err)
	}
	err = s.UpdateRun(expected.Projects[0].ID, "active", func(project *RunProject, run *model.Run) error {
		project.Syncing = false
		run.Logs = append(run.Logs, model.SyncLog{Event: "uncommitted"})
		run.PausedSeconds = math.NaN()
		return nil
	})
	if err == nil || !reflect.DeepEqual(before, workspaceCiphertexts(t, s)) {
		t.Fatal("run failure committed logs or metadata")
	}
	snapshot, current, err := s.ReadSnapshot(version)
	if err != nil || snapshot != nil || current != version {
		t.Fatal("failed writes advanced the snapshot version")
	}
}

func TestRecordDeletionPrunesFindingsLogsRunsAndProjects(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	expected := recordFixture()
	if err := s.Update(func(state *model.State) error { *state = expected; return nil }); err != nil {
		t.Fatal(err)
	}
	original := workspaceCiphertexts(t, s)
	if err := s.Update(func(state *model.State) error {
		state.Projects[0].Findings = state.Projects[0].Findings[:1]
		state.Projects[0].Runs = state.Projects[0].Runs[1:]
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(workspaceCiphertexts(t, s)) >= len(original) {
		t.Fatal("removed finding chunks and workflow logs remained active")
	}
	if err := s.UpdateRun(expected.Projects[0].ID, "active", func(*RunProject, *model.Run) error { t.Fatal("removed run was updated"); return nil }); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("removed run was recreated: %v", err)
	}
	if err := s.Update(func(state *model.State) error { state.Projects = state.Projects[1:]; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		projects := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket)).Bucket([]byte("projects"))
		if projects.Bucket(s.projectKey(expected.Projects[0].ID)) != nil {
			t.Fatal("deleted project's encrypted buckets remained active")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateRun(expected.Projects[0].ID, "history", func(*RunProject, *model.Run) error { t.Fatal("deleted project was updated"); return nil }); !errors.Is(err, ErrRunNotFound) {
		t.Fatalf("late progress resurrected deleted project: %v", err)
	}
}

func TestRecordCiphertextCannotBeMovedBetweenProjects(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	state := recordFixture()
	state.Projects[1].Findings = append([]model.Finding{}, state.Projects[0].Findings[:1]...)
	if err := s.Update(func(next *model.State) error { *next = state; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Update(func(tx *bolt.Tx) error {
		projects := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket)).Bucket([]byte("projects"))
		first := projects.Bucket(s.projectKey(state.Projects[0].ID)).Bucket([]byte("findings"))
		second := projects.Bucket(s.projectKey(state.Projects[1].ID)).Bucket([]byte("findings"))
		return second.Put(uintBytes(0), first.Get(uintBytes(0)))
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("ciphertext authenticated at another project's record location")
	}
}

func TestUnknownRecordSchemaAndMissingRecordNeverFallBackToEmptyState(t *testing.T) {
	for _, mode := range []string{"future-schema", "missing-findings", "missing-state"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			state := recordFixture()
			if err := s.Update(func(next *model.State) error { *next = state; return nil }); err != nil {
				t.Fatal(err)
			}
			if err := s.db.Update(func(tx *bolt.Tx) error {
				if mode == "missing-state" {
					return tx.DeleteBucket([]byte("state"))
				}
				root := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))
				if mode == "future-schema" {
					return s.writeRecord(root, []byte("manifest"), "manifest", recordManifest{Schema: 999, Projects: []string{state.Projects[0].ID}})
				}
				return root.Bucket([]byte("projects")).Bucket(s.projectKey(state.Projects[0].ID)).Bucket([]byte("findings")).Delete(uintBytes(0))
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			before := readTestDatabase(t, dir)
			for _, open := range []func(string) (*Store, error){OpenExisting, Open} {
				if reopened, err := open(dir); err == nil {
					closeTestStore(t, reopened)
					t.Fatal("incompatible or incomplete records opened as a new workspace")
				}
			}
			if !bytes.Equal(before, readTestDatabase(t, dir)) {
				t.Fatal("failed open modified database bytes")
			}
		})
	}
}

func TestRunAndFullStateWritersSerializeWithoutLostChanges(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	state := recordFixture()
	if err := s.Update(func(next *model.State) error { *next = state; return nil }); err != nil {
		t.Fatal(err)
	}
	var writers sync.WaitGroup
	for i := 0; i < 12; i++ {
		writers.Add(2)
		go func() {
			defer writers.Done()
			if err := s.UpdateRun(state.Projects[0].ID, "active", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
				t.Error(err)
			}
		}()
		go func(index int) {
			defer writers.Done()
			if err := s.Update(func(next *model.State) error { next.Projects[0].Findings[index].Title = "Updated finding"; return nil }); err != nil {
				t.Error(err)
			}
		}(i)
	}
	writers.Wait()
	actual, err := s.Read()
	if err != nil || actual.Projects[0].Runs[0].Count != state.Projects[0].Runs[0].Count+12 {
		t.Fatalf("workflow writes were lost: %v", err)
	}
	for i := 0; i < 12; i++ {
		if !strings.HasPrefix(actual.Projects[0].Findings[i].Title, "Updated") {
			t.Fatal("full-state writes were lost")
		}
	}
}

func TestLegacyMigrationRejectsWrongKeyAndAmbiguousProjectIDs(t *testing.T) {
	for _, mode := range []string{"wrong-key", "duplicate-project-id"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			state := recordFixture()
			if mode == "duplicate-project-id" {
				state.Projects[1].ID = state.Projects[0].ID
			}
			key, _ := seedLegacyRecords(t, dir, state)
			if mode == "wrong-key" {
				replacement := make([]byte, keySize)
				if _, err := rand.Read(replacement); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, keyFile), replacement, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := readTestDatabase(t, dir)
			if s, err := OpenExisting(dir); err == nil {
				closeTestStore(t, s)
				t.Fatal("invalid migration was accepted")
			}
			if !bytes.Equal(before, readTestDatabase(t, dir)) {
				t.Fatal("failed migration changed the legacy database")
			}
			if mode == "wrong-key" {
				if err := os.WriteFile(filepath.Join(dir, keyFile), key, 0600); err != nil {
					t.Fatal(err)
				}
				s, err := OpenExisting(dir)
				if err != nil {
					t.Fatal(err)
				}
				closeTestStore(t, s)
			}
		})
	}
}

func TestRecordIDsCannotChangeDuringJSONEncoding(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestStore(t, s)
	before := workspaceCiphertexts(t, s)
	err = s.Update(func(state *model.State) error {
		state.Projects = []model.Project{{ID: string([]byte{0xff}), Name: "Invalid identity"}}
		return nil
	})
	if err == nil || !reflect.DeepEqual(before, workspaceCiphertexts(t, s)) {
		t.Fatal("an identity that changes on JSON decoding was committed")
	}
}
