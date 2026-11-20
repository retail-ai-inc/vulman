package store

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

// Cache entries are independently encrypted, avoiding rewriting the cache when
// application state or workflow progress is saved.
type CachedResponse struct {
	Data      json.RawMessage `json:"data"`
	CheckedAt time.Time       `json:"checked_at"`
	Empty     bool            `json:"empty"`
}

type CacheStats struct {
	Entries    uint64 `json:"entries"`
	Bytes      uint64 `json:"bytes"`
	Hits       uint64 `json:"hits"`
	Misses     uint64 `json:"misses"`
	Evictions  uint64 `json:"evictions"`
	MaxEntries uint64 `json:"max_entries"`
	MaxBytes   uint64 `json:"max_bytes"`
}

const maxCacheEntryBytes = 8 << 20

func uintBytes(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }

func readUint(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}

	return binary.BigEndian.Uint64(b)
}

func (s *Store) CacheGet(key string) (CachedResponse, bool, error) {
	var entry CachedResponse
	found := false

	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("cache-v1")).Bucket([]byte("entries")).Get([]byte(key))
		if b == nil {
			return nil
		}

		n := s.aead.NonceSize()
		if len(b) < n {
			return apperror.New("invalid_cache_entry", "invalid cache entry")
		}

		plain, err := s.aead.Open(nil, b[:n], b[n:], []byte("vulman-cache-v1:"+key))
		if err != nil {
			return err
		}

		if err = json.Unmarshal(plain, &entry); err != nil {
			return err
		}

		found = true
		return nil
	})

	return entry, found, err
}

// Rebuild missing or out-of-range usage counters on open.
// Normal cache operations and polling read only these metadata keys.
func initializeCacheMetadata(root *bolt.Bucket) error {
	entries, meta := root.Bucket([]byte("entries")), root.Bucket([]byte("meta"))
	count, size := meta.Get([]byte("_count")), meta.Get([]byte("_bytes"))

	if len(count) == 8 && readUint(count) <= model.MaxCacheMaxEntries &&
		len(size) == 8 && readUint(size) <= model.MaxCacheMaxMiB<<20 {
		return nil
	}

	var usage cacheUsage
	if err := entries.ForEach(func(_, value []byte) error {
		if value != nil {
			usage.count++
			usage.bytes += uint64(len(value))
		}
		return nil
	}); err != nil {
		return err
	}

	return saveUsage(meta, usage)
}

type cacheUsage struct {
	count uint64
	bytes uint64
}

func usageFor(meta *bolt.Bucket) cacheUsage {
	return cacheUsage{
		count: readUint(meta.Get([]byte("_count"))),
		bytes: readUint(meta.Get([]byte("_bytes"))),
	}
}

func saveUsage(meta *bolt.Bucket, u cacheUsage) error {
	if err := meta.Put([]byte("_count"), uintBytes(u.count)); err != nil {
		return err
	}

	return meta.Put([]byte("_bytes"), uintBytes(u.bytes))
}

func removeCache(root *bolt.Bucket, key []byte, u *cacheUsage) error {
	entries, order, meta := root.Bucket([]byte("entries")), root.Bucket([]byte("order")), root.Bucket([]byte("meta"))
	old := entries.Get(key)

	if old == nil {
		return nil
	}

	if u.count == 0 || u.bytes < uint64(len(old)) {
		return apperror.New("invalid_cache_usage_counters", "invalid cache usage counters")
	}

	u.count--
	u.bytes -= uint64(len(old))
	if stamp := meta.Get(key); len(stamp) == 8 {
		if err := order.Delete(append(append([]byte{}, stamp...), key...)); err != nil {
			return err
		}
	}

	if err := entries.Delete(key); err != nil {
		return err
	}

	return meta.Delete(key)
}

func enforceCacheLimits(root *bolt.Bucket, u *cacheUsage, maxEntries, maxBytes uint64) error {
	order, meta := root.Bucket([]byte("order")), root.Bucket([]byte("meta"))
	var evicted uint64

	for u.count > maxEntries || u.bytes > maxBytes {
		old, _ := order.Cursor().First()
		if len(old) < 8 {
			return apperror.New("cache_eviction_index_is_incomplete", "cache eviction index is incomplete")
		}

		key := append([]byte{}, old[8:]...)
		if root.Bucket([]byte("entries")).Get(key) == nil {
			return apperror.New("cache_eviction_index_references_a_missing_entry", "cache eviction index references a missing entry")
		}

		if err := removeCache(root, key, u); err != nil {
			return err
		}

		evicted++
	}

	if evicted > 0 {
		return meta.Put([]byte("_evictions"), uintBytes(readUint(meta.Get([]byte("_evictions")))+evicted))
	}

	return nil
}

func applyCacheLimits(root *bolt.Bucket, settings model.Settings) error {
	maxEntries, maxBytes := model.CacheLimits(settings)
	meta := root.Bucket([]byte("meta"))
	u := usageFor(meta)

	if u.count <= maxEntries && u.bytes <= maxBytes &&
		readUint(meta.Get([]byte("_limit_entries"))) == maxEntries &&
		readUint(meta.Get([]byte("_limit_bytes"))) == maxBytes {
		return nil
	}

	if err := enforceCacheLimits(root, &u, maxEntries, maxBytes); err != nil {
		return err
	}

	if err := saveUsage(meta, u); err != nil {
		return err
	}

	if err := meta.Put([]byte("_limit_entries"), uintBytes(maxEntries)); err != nil {
		return err
	}

	return meta.Put([]byte("_limit_bytes"), uintBytes(maxBytes))
}

// Hits and misses are logical lookups, not the internal reads used for racing
// refreshes or diagnostics. Force refreshes do not affect the hit ratio.
func (s *Store) RecordCacheUse(hit bool) {
	if hit {
		s.cacheHits.Add(1)
	} else {
		s.cacheMisses.Add(1)
	}
}
func (s *Store) persistCacheCounters(meta *bolt.Bucket) error {
	if err := meta.Put([]byte("_hits"), uintBytes(s.cacheHits.Load())); err != nil {
		return err
	}

	return meta.Put([]byte("_misses"), uintBytes(s.cacheMisses.Load()))
}

func (s *Store) CachePut(key string, entry CachedResponse) error {
	plain, err := json.Marshal(entry)
	if err != nil {
		return err
	}

	if len(plain) > maxCacheEntryBytes {
		return apperror.New("query_result_exceeds_the_8_mib_cache_entry_limit", "query result exceeds the 8 MiB cache entry limit")
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return err
	}

	data := s.aead.Seal(nonce, nonce, plain, []byte("vulman-cache-v1:"+key))
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("cache-v1"))
		entries, order, meta := root.Bucket([]byte("entries")), root.Bucket([]byte("order")), root.Bucket([]byte("meta"))
		u := usageFor(meta)

		if err := removeCache(root, []byte(key), &u); err != nil {
			return err
		}

		size := uint64(len(data))
		if u.count == math.MaxUint64 || u.bytes > math.MaxUint64-size {
			return apperror.New("cache_usage_counters_would_overflow", "cache usage counters would overflow")
		}

		if err := entries.Put([]byte(key), data); err != nil {
			return err
		}

		u.count++
		u.bytes += size
		stamp := uintBytes(uint64(entry.CheckedAt.UnixNano()))

		if err := meta.Put([]byte(key), stamp); err != nil {
			return err
		}

		if err := order.Put(append(stamp, []byte(key)...), []byte{}); err != nil {
			return err
		}

		if err := enforceCacheLimits(root, &u, readUint(meta.Get([]byte("_limit_entries"))), readUint(meta.Get([]byte("_limit_bytes")))); err != nil {
			return err
		}

		if err := saveUsage(meta, u); err != nil {
			return err
		}

		return s.persistCacheCounters(meta)
	})
}

func (s *Store) CacheDelete(key string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("cache-v1"))
		meta := root.Bucket([]byte("meta"))
		u := usageFor(meta)
		if err := removeCache(root, []byte(key), &u); err != nil {
			return err
		}
		return saveUsage(meta, u)
	})
}
func (s *Store) CacheStats() (CacheStats, error) {
	var stats CacheStats
	err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket([]byte("cache-v1")).Bucket([]byte("meta"))
		u := usageFor(meta)
		stats = CacheStats{
			Entries:    u.count,
			Bytes:      u.bytes,
			Evictions:  readUint(meta.Get([]byte("_evictions"))),
			MaxEntries: readUint(meta.Get([]byte("_limit_entries"))),
			MaxBytes:   readUint(meta.Get([]byte("_limit_bytes"))),
		}
		return nil
	})

	stats.Hits = s.cacheHits.Load()
	stats.Misses = s.cacheMisses.Load()
	return stats, err
}
