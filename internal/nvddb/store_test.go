package nvddb

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

const testCPE = "cpe:2.3:a:golang:go:1.26.0:*:*:*:*:*:*:*"

func testAEAD(t testing.TB, key []byte) cipher.AEAD {
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
func testStore(t *testing.T) *Store {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	s, err := Open(t.TempDir(), testAEAD(t, key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func advisory(id, text, cpe string) json.RawMessage {
	r := Record{ID: id, VulnStatus: "Analyzed", Descriptions: []Text{{Lang: "en", Value: text}}, Configurations: []Node{{Nodes: []Node{{Operator: "OR", Matches: []Criteria{{Vulnerable: true, Name: cpe}}}}}}}
	data, _ := json.Marshal(r)
	return data
}
func dictionary(id, cpe string) json.RawMessage {
	data, _ := json.Marshal(CPE{ID: id, Name: cpe})
	return data
}
func readyCatalogue(t *testing.T, s *Store, records []json.RawMessage) {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC()
	feeds := []Feed{{Kind: "nvd", ID: "modified", At: at}, {Kind: "cpe", ID: "dictionary", At: at}}
	if err := s.begin(ctx, true, feeds); err != nil {
		t.Fatal(err)
	}
	for offset := 0; offset < len(records); offset += batchSize {
		end := min(len(records), offset+batchSize)
		if err := s.batch(ctx, records[offset:end], end); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.finishFeed(ctx, feeds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.batch(ctx, []json.RawMessage{dictionary("dictionary-id", testCPE)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finishFeed(ctx, feeds[1], true); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicBaselineAndIndexedReplacement(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	var records []json.RawMessage
	for i := 0; i < 600; i++ {
		records = append(records, advisory(fmt.Sprintf("CVE-2026-%04d", i+1), "Go critical advisory", testCPE))
	}
	readyCatalogue(t, s, records)
	result, err := s.Query(ctx, "Go", "")
	if err != nil || len(result.Records) != 600 {
		t.Fatalf("cursor pagination missed records: %d %v", len(result.Records), err)
	}
	stats, err := s.Stats()
	if err != nil || stats.Records != 600 || stats.CPEs != 1 {
		t.Fatalf("incorrect counters: %+v %v", stats, err)
	}
	data, err := s.root.ReadFile(Filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "Go critical advisory") {
		t.Fatal("record payload was not encrypted")
	}
	feeds := []Feed{{Kind: "nvd", ID: "modified", At: time.Now().UTC()}}
	if err := s.begin(ctx, false, feeds); err != nil {
		t.Fatal(err)
	}
	oldOffset := s.snapshot().Job.Offset
	if err := s.batch(ctx, []json.RawMessage{advisory("CVE-2026-0001", "Rust corrected advisory", testCPE), json.RawMessage(`{"id":"bad"}`)}, 2); err == nil {
		t.Fatal("invalid batch accepted")
	}
	if s.snapshot().Job.Offset != oldOffset {
		t.Fatal("rolled back batch advanced its cursor")
	}
	result, err = s.Query(ctx, "Rust", "")
	if err != nil || len(result.Records) != 0 {
		t.Fatal("rolled back index entries survived")
	}
	if err := s.batch(ctx, []json.RawMessage{advisory("CVE-2026-0001", "Rust corrected advisory", testCPE)}, 1); err != nil {
		t.Fatal(err)
	}
	result, err = s.Query(ctx, "Go", "")
	if err != nil || len(result.Records) != 599 {
		t.Fatalf("obsolete index postings survived: %d %v", len(result.Records), err)
	}
	result, err = s.Query(ctx, "Rust", "")
	if err != nil || len(result.Records) != 1 {
		t.Fatal("replacement index was not updated atomically")
	}
	if err := s.finishFeed(ctx, feeds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
	stats, err = s.Stats()
	if err != nil || stats.Records != 600 {
		t.Fatal("replacing a record changed its count")
	}
}

func TestDictionaryReplacementKeepsDuplicateNamesAndDeprecationChecks(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	readyCatalogue(t, s, []json.RawMessage{advisory("CVE-2026-0001", "Go advisory", testCPE)})
	at := time.Now().UTC()
	feeds := []Feed{{Kind: "nvd", ID: "modified", At: at}, {Kind: "cpe", ID: "dictionary", At: at}}
	if err := s.begin(ctx, false, feeds); err != nil {
		t.Fatal(err)
	}
	if err := s.finishFeed(ctx, feeds[0], false); err != nil {
		t.Fatal(err)
	}
	deprecated, err := json.Marshal(CPE{ID: "first", Name: testCPE, Deprecated: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.batch(ctx, []json.RawMessage{deprecated, dictionary("second", testCPE)}, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.finishFeed(ctx, feeds[1], true); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := s.Query(ctx, "Go", testCPE)
	if err != nil || !result.Uncertain || len(result.Records) != 1 {
		t.Fatalf("duplicate or deprecated dictionary identities were not flagged: %+v %v", result, err)
	}
	// Removing one UUID must retain the other name mapping. This also exercises
	// dictionary cleanup used after replacing a published generation.
	if err := s.update(func(tx *bolt.Tx, m *metadata) error { return s.remove(tx, m.CPE, "cpe", "first") }); err != nil {
		t.Fatal(err)
	}
	result, err = s.Query(ctx, "Go", testCPE)
	stats, statsErr := s.Stats()
	if err != nil || result.Uncertain || statsErr != nil || stats.CPEs != 1 {
		t.Fatalf("removing a duplicate damaged the remaining identity: %+v %+v %v %v", result, stats, err, statsErr)
	}
	if err := s.update(func(tx *bolt.Tx, m *metadata) error { return s.remove(tx, m.CPE, "cpe", "second") }); err != nil {
		t.Fatal(err)
	}
	result, err = s.Query(ctx, "Go", testCPE)
	if err != nil || result.Uncertain {
		t.Fatalf("last dictionary removal left a dangling index: %+v %v", result, err)
	}
}

func TestConcurrentReadersKeepPublishedGenerationDuringRebuild(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyCatalogue(t, s, []json.RawMessage{advisory("CVE-2026-0001", "Go first", testCPE)})
	var readers sync.WaitGroup
	defer func() { cancel(); readers.Wait() }()
	for range 4 {
		readers.Go(func() {
			for ctx.Err() == nil {
				result, err := s.Query(ctx, "Go", "")
				if errors.Is(err, context.Canceled) {
					return
				}
				if err != nil || len(result.Records) != 1 {
					t.Errorf("reader saw incomplete catalogue: %+v %v", result, err)
					return
				}
			}
		})
	}
	feeds := []Feed{{Kind: "nvd", ID: "modified", At: time.Now().UTC()}, {Kind: "cpe", ID: "dictionary", At: time.Now().UTC()}}
	if err := s.begin(ctx, true, feeds); err != nil {
		t.Fatal(err)
	}
	if err := s.batch(ctx, []json.RawMessage{advisory("CVE-2026-0002", "Go second", testCPE)}, 1); err != nil {
		t.Fatal(err)
	}
	result, err := s.Query(ctx, "Go", "")
	if err != nil || result.Records[0].ID != "CVE-2026-0001" {
		t.Fatal("staged baseline was published early")
	}
	if err := s.finishFeed(ctx, feeds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.batch(ctx, []json.RawMessage{dictionary("new-id", testCPE)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finishFeed(ctx, feeds[1], true); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	readers.Wait()
	result, err = s.Query(context.Background(), "Go", "")
	if err != nil || result.Records[0].ID != "CVE-2026-0002" {
		t.Fatal("completed rebuild was not published")
	}
	if err := s.clear(context.Background(), other(s.snapshot().NVD), "nvd", ""); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedNVDProcessRecoversRecordsIndexesAndCheckpoint(t *testing.T) {
	if dir := os.Getenv("VULMAN_NVD_CRASH_DIR"); dir != "" {
		key, err := hex.DecodeString(os.Getenv("VULMAN_NVD_TEST_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, testAEAD(t, key))
		if err != nil {
			t.Fatal(err)
		}
		feeds := []Feed{{Kind: "nvd", ID: "modified", At: time.Now().UTC()}, {Kind: "cpe", ID: "dictionary", At: time.Now().UTC()}}
		if err := s.begin(context.Background(), true, feeds); err != nil {
			t.Fatal(err)
		}
		if err := s.batch(context.Background(), []json.RawMessage{advisory("CVE-2026-0001", "Go committed", testCPE)}, 1); err != nil {
			t.Fatal(err)
		}
		err = s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.Bucket([]byte("meta")).Put([]byte("state"), []byte("uncommitted corruption")); err != nil {
				return err
			}
			os.Exit(47)
			return nil
		})
		t.Fatalf("child did not exit: %v", err)
	}
	dir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestInterruptedNVDProcessRecoversRecordsIndexesAndCheckpoint$") // #nosec G204 -- runs this test executable with a fixed selector.
	cmd.Env = append(os.Environ(), "VULMAN_NVD_CRASH_DIR="+dir, "VULMAN_NVD_TEST_KEY="+hex.EncodeToString(key))
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 47 {
		t.Fatalf("unexpected child exit: %v", err)
	}
	s, err := Open(dir, testAEAD(t, key))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	if s.snapshot().Job.Offset != 1 {
		t.Fatal("committed import checkpoint was lost")
	}
	if _, err := s.Query(context.Background(), "Go", ""); !errors.Is(err, ErrNotReady) {
		t.Fatal("unfinished baseline exposed to queries")
	}
	m := s.snapshot()
	ctx := context.Background()
	if err := s.finishFeed(ctx, m.Job.Feeds[0], true); err != nil {
		t.Fatal(err)
	}
	if err := s.batch(ctx, []json.RawMessage{dictionary("resumed-id", testCPE)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finishFeed(ctx, m.Job.Feeds[1], true); err != nil {
		t.Fatal(err)
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := s.Query(ctx, "Go", "")
	if err != nil || len(result.Records) != 1 {
		t.Fatalf("record or index missing after crash recovery: %+v %v", result, err)
	}
}
