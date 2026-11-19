package cvedb

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const batchSize = 256

var metaBucket = []byte("metadata")

type Archive struct {
	Name   string    `json:"name"`
	URL    string    `json:"url"`
	Digest string    `json:"digest"`
	Size   int64     `json:"size"`
	At     time.Time `json:"at"`
	Base   bool      `json:"base"`
}

type Import struct {
	Archive Archive `json:"archive"`
	Bucket  string  `json:"bucket"`
	Next    int     `json:"next"`
}

type metadata struct {
	Active      string    `json:"active"`
	Initialized bool      `json:"initialized"`
	SourceAt    time.Time `json:"source_at"`
	CheckedAt   time.Time `json:"checked_at"`
	Pending     *Import   `json:"pending,omitempty"`
}

type Stats struct {
	Path          string    `json:"path"`
	Records       uint64    `json:"records"`
	OnDemand      uint64    `json:"on_demand"`
	Bytes         int64     `json:"bytes"`
	Initialized   bool      `json:"initialized"`
	SourceAt      time.Time `json:"source_at"`
	CheckedAt     time.Time `json:"checked_at"`
	Resumable     bool      `json:"resumable"`
	Imported      int       `json:"imported"`
	Running       bool      `json:"running"`
	Phase         string    `json:"phase"`
	Downloaded    int64     `json:"downloaded"`
	DownloadTotal int64     `json:"download_total"`
	Error         string    `json:"error,omitempty"`
}

type Store struct {
	db   *bolt.DB
	root *os.Root
	aead cipher.AEAD
	// A cached metadata snapshot avoids decrypting metadata for each ID lookup.
	mu   sync.RWMutex
	meta metadata
}

func Open(dir string, aead cipher.AEAD) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root.Name(), Filename)
	db, err := bolt.Open(path, 0600, &bolt.Options{
		Timeout:         time.Second,
		InitialMmapSize: 256 << 20,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			if name != path {
				return nil, errors.New("unexpected CVE database path")
			}
			return root.OpenFile(Filename, flags, mode)
		},
	})
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	s := &Store{db: db, root: root, aead: aead}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"metadata", "base-a", "base-b", "on-demand"} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}
		data := tx.Bucket(metaBucket).Get([]byte("state"))
		if data == nil {
			s.meta.Active = "base-a"
			return s.writeMetadata(tx, s.meta)
		}
		if err := s.decode("metadata", data, &s.meta); err != nil {
			return err
		}
		if s.meta.Active != "base-a" && s.meta.Active != "base-b" {
			return errors.New("invalid CVE catalogue metadata")
		}
		return nil
	})
	if err != nil {
		return nil, errors.Join(err, db.Close(), root.Close())
	}
	return s, nil
}

func (s *Store) Close() error { return errors.Join(s.db.Close(), s.root.Close()) }

func (s *Store) encode(identity string, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte("vulman-cve-v1:"+identity)), nil
}

func (s *Store) decode(identity string, data []byte, value any) error {
	n := s.aead.NonceSize()
	if len(data) < n {
		return errors.New("invalid encrypted CVE entry")
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte("vulman-cve-v1:"+identity))
	if err != nil {
		return fmt.Errorf("cannot decrypt CVE data: %w", err)
	}
	return json.Unmarshal(plain, value)
}

func (s *Store) writeMetadata(tx *bolt.Tx, m metadata) error {
	data, err := s.encode("metadata", m)
	if err != nil {
		return err
	}
	return tx.Bucket(metaBucket).Put([]byte("state"), data)
}

func (s *Store) snapshot() metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.meta
	if m.Pending != nil {
		pending := *m.Pending
		m.Pending = &pending
	}
	return m
}

func (s *Store) Initialized() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.meta.Initialized
}

// update publishes in-memory metadata only after bbolt has durably committed.
func (s *Store) update(fn func(*bolt.Tx, *metadata) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.meta
	if m.Pending != nil {
		pending := *m.Pending
		m.Pending = &pending
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		if err := fn(tx, &m); err != nil {
			return err
		}
		return s.writeMetadata(tx, m)
	})
	if err == nil {
		s.meta = m
	}
	return err
}

// Lookup uses short read transactions and indexed bucket.Get calls. The read
// lock keeps the selected generation consistent with its metadata.
func (s *Store) Lookup(id string) (Record, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result Record
	err := s.db.View(func(tx *bolt.Tx) error {
		for _, bucket := range []string{s.meta.Active, "on-demand"} {
			data := tx.Bucket([]byte(bucket)).Get([]byte(id))
			if data == nil {
				continue
			}
			var r Record
			if err := s.decode(id, data, &r); err != nil {
				return err
			}
			if result.ID == "" || newer(r, result) {
				result = r
			}
		}
		if s.meta.Initialized && s.meta.SourceAt.After(result.CheckedAt) {
			result.CheckedAt = s.meta.SourceAt
		}
		return nil
	})
	return result, result.ID != "", err
}

func (s *Store) Put(r Record) error {
	if !validID.MatchString(r.ID) || (r.State != "PUBLISHED" && r.State != "REJECTED") {
		return errors.New("invalid CVE record")
	}
	data, err := s.encode(r.ID, r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("on-demand"))
		if bucket.Get([]byte(r.ID)) == nil {
			if _, err := bucket.NextSequence(); err != nil {
				return err
			}
		}
		return bucket.Put([]byte(r.ID), data)
	})
}

// clearBucket uses a fresh cursor for each bounded transaction. No cursor or
// mmap-backed byte slice survives the transaction that owns it.
func (s *Store) clearBucket(ctx context.Context, name string) error {
	for {
		removed := 0
		err := s.db.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			c := tx.Bucket([]byte(name)).Cursor()
			for k, _ := c.First(); k != nil && removed < batchSize; k, _ = c.First() {
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
			}
			if removed < batchSize {
				return tx.Bucket([]byte(name)).SetSequence(0)
			}
			return nil
		})
		if err != nil || removed < batchSize {
			return err
		}
	}
}

func (s *Store) begin(ctx context.Context, archive Archive) error {
	m := s.snapshot()
	if m.Pending != nil && m.Pending.Archive == archive {
		return nil
	}
	if m.Pending != nil {
		return errors.New("resume the pending CVE import first")
	}
	bucket := m.Active
	if archive.Base {
		bucket = "base-a"
		if m.Active == bucket {
			bucket = "base-b"
		}
		if err := s.clearBucket(ctx, bucket); err != nil {
			return err
		}
	}
	return s.update(func(_ *bolt.Tx, m *metadata) error {
		m.Pending = &Import{Archive: archive, Bucket: bucket}
		return nil
	})
}

// commitBatch saves complete records and their ZIP cursor in the same durable
// transaction. Interrupted deltas can be replayed without skipping a record.
func (s *Store) commitBatch(ctx context.Context, records []Record, next int) error {
	slices.SortFunc(records, func(a, b Record) int { return strings.Compare(a.ID, b.ID) })
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.Pending == nil || next < m.Pending.Next {
			return errors.New("invalid CVE import checkpoint")
		}
		bucket := tx.Bucket([]byte(m.Pending.Bucket))
		for _, r := range records {
			r.CheckedAt = m.Pending.Archive.At
			if !validID.MatchString(r.ID) || (r.State != "PUBLISHED" && r.State != "REJECTED") {
				return errors.New("invalid CVE record in import")
			}
			if old := bucket.Get([]byte(r.ID)); old != nil {
				var previous Record
				if err := s.decode(r.ID, old, &previous); err != nil {
					return err
				}
				if newer(previous, r) {
					continue
				}
			}
			data, err := s.encode(r.ID, r)
			if err != nil {
				return err
			}
			if bucket.Get([]byte(r.ID)) == nil {
				if _, err := bucket.NextSequence(); err != nil {
					return err
				}
			}
			if err := bucket.Put([]byte(r.ID), data); err != nil {
				return err
			}
		}
		m.Pending.Next = next
		return nil
	})
}

func (s *Store) finish(ctx context.Context) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if m.Pending == nil {
			return errors.New("no pending CVE import")
		}
		if m.Pending.Archive.Base {
			if tx.Bucket([]byte(m.Pending.Bucket)).Sequence() == 0 {
				return errors.New("empty CVE baseline")
			}
			m.Active = m.Pending.Bucket
			m.Initialized = true
		}
		m.SourceAt = m.Pending.Archive.At
		m.Pending = nil
		return nil
	})
}

func (s *Store) Stats() (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.meta
	result := Stats{Path: s.db.Path(), Initialized: m.Initialized, SourceAt: m.SourceAt, CheckedAt: m.CheckedAt, Resumable: m.Pending != nil}
	if m.Pending != nil {
		result.Imported = m.Pending.Next
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		// Counts change atomically with their records and need no bucket scan.
		result.Records = tx.Bucket([]byte(m.Active)).Sequence()
		result.OnDemand = tx.Bucket([]byte("on-demand")).Sequence()
		return nil
	})
	if err == nil {
		var info os.FileInfo
		info, err = s.root.Stat(Filename)
		if err == nil {
			result.Bytes = info.Size()
		}
	}
	return result, err
}
