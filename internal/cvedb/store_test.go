package cvedb

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
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

func testAEAD(t *testing.T, key []byte) cipher.AEAD {
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

func testCatalogue(t *testing.T) *Store {
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

func testRecord(id string) Record {
	return Record{ID: id, State: "PUBLISHED", Title: "Sensitive cached advisory", UpdatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), CheckedAt: time.Now().UTC()}
}

func TestBaselineVisibilityRollbackAndCursorCleanup(t *testing.T) {
	s := testCatalogue(t)
	ctx := context.Background()
	a := Archive{Name: "baseline", Base: true, At: time.Now().UTC()}
	if err := s.begin(ctx, a); err != nil {
		t.Fatal(err)
	}
	r := testRecord("CVE-2026-0001")
	if err := s.commitBatch(ctx, []Record{r}, 1); err != nil {
		t.Fatal(err)
	}
	if _, found, err := s.Lookup(r.ID); err != nil || found {
		t.Fatalf("uncommitted baseline visible: %v %v", found, err)
	}
	// A valid record and an invalid record must roll back together, including
	// the cursor and maintained count, when either write fails validation.
	if err := s.commitBatch(ctx, []Record{testRecord("CVE-2026-0002"), {ID: "invalid"}}, 3); err == nil {
		t.Fatal("invalid import accepted")
	}
	if s.snapshot().Pending.Next != 1 {
		t.Fatal("rolled back import advanced its checkpoint")
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	if got, found, err := s.Lookup(r.ID); err != nil || !found || got.Title != r.Title {
		t.Fatalf("completed baseline unavailable: %+v %v", got, err)
	}
	stats, err := s.Stats()
	if err != nil || stats.Records != 1 {
		t.Fatalf("count includes rolled-back records: %+v %v", stats, err)
	}
	data, err := s.root.ReadFile(Filename)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), r.Title) {
		t.Fatal("CVE payload was stored in plaintext")
	}
	// Clear more than one page and transaction. Cursor deletion must not skip
	// entries or reset counters while entries remain in the bucket.
	for i := 0; i < 600; i++ {
		r.ID = fmt.Sprintf("CVE-2026-%04d", i+1000)
		if err := s.Put(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.clearBucket(ctx, "on-demand"); err != nil {
		t.Fatal(err)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("on-demand"))
		k, _ := b.Cursor().First()
		if k != nil || b.Sequence() != 0 {
			return errors.New("cursor cleanup skipped records")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// The child exits inside an uncommitted bbolt write without closing the file,
// exercising the same recovery boundary as a process termination mid-import.
func TestInterruptedImportProcess(t *testing.T) {
	if dir := os.Getenv("VULMAN_CVE_CRASH_DIR"); dir != "" {
		key, err := hex.DecodeString(os.Getenv("VULMAN_CVE_TEST_KEY"))
		if err != nil {
			t.Fatal(err)
		}
		s, err := Open(dir, testAEAD(t, key))
		if err != nil {
			t.Fatal(err)
		}
		if err := s.begin(context.Background(), Archive{Name: "baseline", Base: true, At: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)}); err != nil {
			t.Fatal(err)
		}
		if err := s.commitBatch(context.Background(), []Record{testRecord("CVE-2026-0001")}, 1); err != nil {
			t.Fatal(err)
		}
		err = s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.Bucket(metaBucket).Put([]byte("uncommitted"), []byte("discard")); err != nil {
				return err
			}
			os.Exit(42)
			return nil
		})
		t.Fatalf("child did not terminate: %v", err)
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
	cmd := exec.Command(executable, "-test.run=^TestInterruptedImportProcess$") // #nosec G204 -- re-executes the running test binary with a fixed test selector.
	cmd.Env = append(os.Environ(), "VULMAN_CVE_CRASH_DIR="+dir, "VULMAN_CVE_TEST_KEY="+hex.EncodeToString(key))
	err = cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 42 {
		t.Fatalf("unexpected child result: %v", err)
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
	m := s.snapshot()
	if m.Pending == nil || m.Pending.Next != 1 || m.Initialized {
		t.Fatalf("bad recovered checkpoint: %+v", m)
	}
	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket(metaBucket).Get([]byte("uncommitted")) != nil {
			return errors.New("uncommitted transaction survived")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitBatch(context.Background(), []Record{testRecord("CVE-2026-0002")}, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CVE-2026-0001", "CVE-2026-0002"} {
		if _, found, err := s.Lookup(id); err != nil || !found {
			t.Fatalf("record lost on resume: %s %v", id, err)
		}
	}
}

func TestRecordParsingAndNewerOnDemandResultWins(t *testing.T) {
	s := testCatalogue(t)
	r, err := Parse([]byte(`{"cveMetadata":{"cveId":"CVE-2026-0001","state":"REJECTED","dateUpdated":"2026-01-03T00:00:00"},"containers":{"cna":{"references":[{"url":"https://example.com"}]},"adp":[{"references":[{"url":"https://example.com"},{"url":"https://example.org"}]}]}}`))
	if err != nil || len(r.References) != 2 {
		t.Fatalf("parse: %+v %v", r, err)
	}
	r.CheckedAt = time.Now()
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := s.begin(ctx, Archive{Name: "older-baseline", Base: true, At: r.UpdatedAt.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitBatch(ctx, []Record{testRecord(r.ID)}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	got, _, err := s.Lookup(r.ID)
	if err != nil || got.State != "REJECTED" {
		t.Fatalf("baseline resurrected a rejected record: %+v %v", got, err)
	}
}

func TestOptionalModificationDateUsesObservationOrder(t *testing.T) {
	r, err := Parse([]byte(`{"cveMetadata":{"cveId":"CVE-2026-0001","state":"REJECTED"}}`))
	if err != nil || !r.UpdatedAt.IsZero() {
		t.Fatalf("optional modification date was required or fabricated: %+v %v", r, err)
	}
	r.CheckedAt = time.Now()
	previous := testRecord(r.ID)
	previous.CheckedAt = r.CheckedAt.Add(-time.Hour)
	if !newer(r, previous) || newer(previous, r) {
		t.Fatal("missing dates prevented a newer rejection from replacing a published record")
	}
}

func TestLaterReleaseAppliesBackdatedCorrections(t *testing.T) {
	s := testCatalogue(t)
	ctx := context.Background()
	at := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	r := testRecord("CVE-2026-0001")
	r.UpdatedAt = at
	if err := s.begin(ctx, Archive{Name: "first", Base: true, At: at}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitBatch(ctx, []Record{r}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	r.Title = "Corrected original record"
	r.UpdatedAt = at.Add(-365 * 24 * time.Hour)
	if err := s.begin(ctx, Archive{Name: "correction", At: at.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitBatch(ctx, []Record{r}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	got, found, err := s.Lookup(r.ID)
	if err != nil || !found || got.Title != r.Title || !got.UpdatedAt.Equal(r.UpdatedAt) {
		t.Fatalf("a backdated correction was skipped: %+v %v", got, err)
	}
}

func TestConcurrentReadersSeeOnlyCompletedBaselineGenerations(t *testing.T) {
	s := testCatalogue(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := testRecord("CVE-2026-0001")
	r.Title = "first generation"
	if err := s.begin(ctx, Archive{Name: "first", Base: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.commitBatch(ctx, []Record{r}, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	var readers sync.WaitGroup
	defer func() { cancel(); readers.Wait() }()
	for range 4 {
		readers.Go(func() {
			for ctx.Err() == nil {
				got, found, err := s.Lookup(r.ID)
				if err != nil || !found || (got.Title != "first generation" && got.Title != "second generation") {
					t.Errorf("reader saw an incomplete generation: %+v %v", got, err)
					return
				}
			}
		})
	}
	if err := s.begin(ctx, Archive{Name: "second", Base: true}); err != nil {
		t.Fatal(err)
	}
	newRecord := r
	newRecord.Title = "second generation"
	for i := 1; i <= 10; i++ {
		if err := s.commitBatch(ctx, []Record{newRecord}, i); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.finish(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	readers.Wait()
	got, found, err := s.Lookup(r.ID)
	if err != nil || !found || got.Title != newRecord.Title {
		t.Fatalf("new generation unavailable: %+v %v", got, err)
	}
}
