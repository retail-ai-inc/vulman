package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	"vulman/internal/model"
)

func closeTestStore(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Errorf("close test store: %v", err)
	}
}

func TestCachePersistsEncryptedIndependentlyOfState(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	entry := CachedResponse{Data: json.RawMessage(`{"title":"private-cache-test-value"}`), CheckedAt: time.Now().UTC()}
	if err = s.CachePut("test", entry); err != nil {
		t.Fatal(err)
	}

	stats, err := s.CacheStats()
	if err != nil || stats.Entries != 1 || stats.Bytes == 0 {
		t.Fatalf("invalid cache stats: %+v %v", stats, err)
	}

	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	raw := readTestDatabase(t, dir)
	if bytes.Contains(raw, []byte("private-cache-test-value")) {
		t.Fatal("cached data was not encrypted")
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)
	got, ok, err := s.CacheGet("test")

	if err != nil || !ok || !bytes.Equal(got.Data, entry.Data) || !got.CheckedAt.Equal(entry.CheckedAt) {
		t.Fatalf("cache not persisted: %+v %v", got, err)
	}

	if err = s.CachePut("test", CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: time.Now().UTC(), Empty: true}); err != nil {
		t.Fatal(err)
	}

	stats, _ = s.CacheStats()
	if stats.Entries != 1 {
		t.Fatal("replacement duplicated a cache entry")
	}

	if err = s.CacheDelete("test"); err != nil {
		t.Fatal(err)
	}

	stats, _ = s.CacheStats()
	if stats.Entries != 0 || stats.Bytes != 0 {
		t.Fatalf("cache deletion left metadata: %+v", stats)
	}
}

func TestCacheEvictsOldestEntriesAtCapacity(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	const limit = 3
	if err = s.Update(func(st *model.State) error { st.Settings.CacheMaxEntries = limit; return nil }); err != nil {
		t.Fatal(err)
	}

	at := time.Now().UTC()
	for i := 0; i < limit+2; i++ {
		if err = s.CachePut(fmt.Sprint(i), CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: at.Add(time.Duration(i) * time.Nanosecond)}); err != nil {
			t.Fatal(err)
		}
	}

	stats, _ := s.CacheStats()
	if stats.Entries != limit || stats.Evictions != 2 {
		t.Fatal("cache entry count was not bounded")
	}

	if _, ok, _ := s.CacheGet("0"); ok {
		t.Fatal("oldest cache entry was not evicted")
	}

	if _, ok, _ := s.CacheGet(fmt.Sprint(limit + 1)); !ok {
		t.Fatal("newest cache entry was evicted")
	}
}

func TestCacheLimitsApplyImmediatelyAndCountersPersist(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	stats, _ := s.CacheStats()
	if stats.MaxEntries != 10000 || stats.MaxBytes != 512<<20 {
		t.Fatalf("wrong default cache limits: %+v", stats)
	}

	for i := 0; i < 5; i++ {
		if err = s.CachePut(fmt.Sprint(i), CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: time.Now().UTC().Add(time.Duration(i) * time.Nanosecond)}); err != nil {
			t.Fatal(err)
		}
	}

	s.RecordCacheUse(true)
	s.RecordCacheUse(true)
	s.RecordCacheUse(false)

	if err = s.Update(func(st *model.State) error { st.Settings.CacheMaxEntries = 2; st.Settings.CacheMaxMiB = 16; return nil }); err != nil {
		t.Fatal(err)
	}

	stats, _ = s.CacheStats()
	if stats.Entries != 2 || stats.Evictions != 3 || stats.Hits != 2 || stats.Misses != 1 || stats.MaxBytes != 16<<20 {
		t.Fatalf("limits or counters were not applied: %+v", stats)
	}

	if err = s.Update(func(st *model.State) error { st.Settings.CacheMaxEntries = 10; return nil }); err != nil {
		t.Fatal(err)
	}

	stats, _ = s.CacheStats()
	if stats.Evictions != 3 || stats.Entries != 2 {
		t.Fatal("raising capacity evicted data")
	}

	s.RecordCacheUse(true)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	stats, _ = s.CacheStats()
	if stats.Hits != 3 || stats.Misses != 1 || stats.Evictions != 3 || stats.MaxEntries != 10 {
		t.Fatalf("cache metrics or limits were not restored: %+v", stats)
	}
}

func TestCacheRepairsMissingLegacyUsageCountersOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err = s.CachePut("old", CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}

	before, _ := s.CacheStats()
	if err = s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("cache-v1")).Bucket([]byte("meta"))
		if err := meta.Delete([]byte("_count")); err != nil {
			return err
		}

		return meta.Delete([]byte("_bytes"))
	}); err != nil {
		t.Fatal(err)
	}

	if err = s.Close(); err != nil {
		t.Fatalf("close cache store before reopening: %v", err)
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	after, _ := s.CacheStats()
	if after.Entries != 1 || after.Bytes != before.Bytes {
		t.Fatalf("legacy cache metadata not repaired: %+v", after)
	}
}

func TestCacheRepairsOverflowingMetadataOnOpen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("corrupt metadata", func(t *testing.T) {
		defer closeTestStore(t, s)
		entry := CachedResponse{Data: json.RawMessage(`[]`), CheckedAt: time.Now().UTC()}

		if err := s.CachePut("keep", entry); err != nil {
			t.Fatal(err)
		}

		if err := s.db.Update(func(tx *bolt.Tx) error {
			meta := tx.Bucket([]byte("cache-v1")).Bucket([]byte("meta"))
			for _, key := range []string{"_count", "_bytes", "_limit_entries", "_limit_bytes"} {
				if err := meta.Put([]byte(key), uintBytes(math.MaxUint64)); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if err := s.CachePut("reject", entry); err == nil {
			t.Fatal("cache write accepted overflowing counters")
		}
	})

	if t.Failed() {
		return
	}

	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	stats, err := s.CacheStats()
	if err != nil || stats.Entries != 1 || stats.Bytes == 0 || stats.MaxEntries != model.DefaultCacheMaxEntries || stats.MaxBytes != model.DefaultCacheMaxMiB<<20 {
		t.Fatalf("cache metadata was not repaired: %+v, %v", stats, err)
	}

	if _, found, err := s.CacheGet("keep"); err != nil || !found {
		t.Fatalf("cached response was lost: found=%v, %v", found, err)
	}
}

func TestLoweringByteLimitEvictsWithoutChangingFreshness(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	defer closeTestStore(t, s)

	at := time.Now().UTC()
	data := json.RawMessage(`"` + strings.Repeat("x", 6<<20) + `"`)
	for i := 0; i < 3; i++ {
		if err = s.CachePut(fmt.Sprint(i), CachedResponse{Data: data, CheckedAt: at.Add(time.Duration(i) * time.Nanosecond)}); err != nil {
			t.Fatal(err)
		}
	}

	if err = s.Update(func(st *model.State) error { st.Settings.CacheMaxMiB = 16; return nil }); err != nil {
		t.Fatal(err)
	}

	stats, _ := s.CacheStats()
	if stats.Entries != 2 || stats.Bytes > 16<<20 || stats.Evictions != 1 {
		t.Fatalf("byte limit was not enforced: %+v", stats)
	}

	if _, ok, _ := s.CacheGet("0"); ok {
		t.Fatal("oldest entry survived byte-limit reduction")
	}

	last, ok, err := s.CacheGet("2")
	if err != nil || !ok || !last.CheckedAt.Equal(at.Add(2*time.Nanosecond)) {
		t.Fatal("retained cache freshness was changed")
	}
}
