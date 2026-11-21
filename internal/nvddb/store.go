package nvddb

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"vulman/internal/apperror"
)

const batchSize = 256

func batchLimit(kind string) int {
	if kind == "cpe" {
		return 4096
	}
	return batchSize
}

type Feed struct {
	Kind       string    `json:"kind"`
	ID         string    `json:"id"`
	MetaURL    string    `json:"meta_url"`
	URL        string    `json:"url"`
	SHA        string    `json:"sha"`
	Size       int64     `json:"size"`
	Compressed int64     `json:"compressed"`
	At         time.Time `json:"at"`
	Optional   bool      `json:"optional,omitempty"`
}
type job struct {
	Full       bool      `json:"full"`
	NVDTarget  string    `json:"nvd_target"`
	CPETarget  string    `json:"cpe_target"`
	StartedAt  time.Time `json:"started_at"`
	Feeds      []Feed    `json:"feeds"`
	Feed       int       `json:"feed"`
	Offset     int       `json:"offset"`
	CPEChanged bool      `json:"cpe_changed"`
	NVDAt      time.Time `json:"nvd_at"`
	CPEAt      time.Time `json:"cpe_at"`
}
type metadata struct {
	NVD       string            `json:"nvd"`
	CPE       string            `json:"cpe"`
	Ready     bool              `json:"ready"`
	NVDAt     time.Time         `json:"nvd_at"`
	CPEAt     time.Time         `json:"cpe_at"`
	CheckedAt time.Time         `json:"checked_at"`
	Hashes    map[string]string `json:"hashes"`
	Job       *job              `json:"job,omitempty"`
}
type Stats struct {
	Path          string            `json:"path"`
	Records       uint64            `json:"records"`
	CPEs          uint64            `json:"cpes"`
	Bytes         int64             `json:"bytes"`
	Initialized   bool              `json:"initialized"`
	SourceAt      time.Time         `json:"source_at"`
	CPEAt         time.Time         `json:"cpe_at"`
	CheckedAt     time.Time         `json:"checked_at"`
	Resumable     bool              `json:"resumable"`
	Imported      int               `json:"imported"`
	ImportTotal   int               `json:"import_total"`
	Feed          string            `json:"feed"`
	FeedsDone     int               `json:"feeds_done"`
	FeedsTotal    int               `json:"feeds_total"`
	Running       bool              `json:"running"`
	Phase         string            `json:"phase"`
	Downloaded    int64             `json:"downloaded"`
	DownloadTotal int64             `json:"download_total"`
	ErrorMessage  *apperror.Message `json:"error_message,omitempty"`
	Error         string            `json:"error,omitempty"`
}
type Store struct {
	db   *bolt.DB
	root *os.Root
	aead cipher.AEAD
	mu   sync.RWMutex
	meta metadata
}

func Open(dir string, aead cipher.AEAD) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(root.Name(), Filename)
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second, InitialMmapSize: 256 << 20,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			if name != path {
				return nil, apperror.New("unexpected_nvd_database_path", "unexpected NVD database path")
			}
			return root.OpenFile(Filename, flags, mode)
		},
	})
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	s := &Store{db: db, root: root, aead: aead}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{"meta", "nvd-a", "nvd-b", "cpe-a", "cpe-b"} {
			b, err := tx.CreateBucketIfNotExists([]byte(name))
			if err != nil {
				return err
			}
			if name != "meta" {
				for _, child := range []string{"records", "index"} {
					if _, err := b.CreateBucketIfNotExists([]byte(child)); err != nil {
						return err
					}
				}
			}
		}
		data := tx.Bucket([]byte("meta")).Get([]byte("state"))
		if data == nil {
			s.meta = metadata{NVD: "nvd-a", CPE: "cpe-a", Hashes: map[string]string{}}
			return s.writeMetadata(tx, s.meta)
		}
		if err := s.decode("metadata", data, &s.meta); err != nil {
			return err
		}
		if (s.meta.NVD != "nvd-a" && s.meta.NVD != "nvd-b") || (s.meta.CPE != "cpe-a" && s.meta.CPE != "cpe-b") || s.meta.Hashes == nil {
			return apperror.New("invalid_nvd_catalogue_metadata", "invalid NVD catalogue metadata")
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
	return s.aead.Seal(nonce, nonce, plain, []byte("vulman-nvd-v1:"+identity)), nil
}
func (s *Store) decode(identity string, data []byte, out any) error {
	n := s.aead.NonceSize()
	if len(data) < n {
		return apperror.New("invalid_encrypted_nvd_record", "invalid encrypted NVD record")
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte("vulman-nvd-v1:"+identity))
	if err != nil {
		return err
	}
	return json.Unmarshal(plain, out)
}
func (s *Store) writeMetadata(tx *bolt.Tx, m metadata) error {
	data, err := s.encode("metadata", m)
	if err != nil {
		return err
	}
	return tx.Bucket([]byte("meta")).Put([]byte("state"), data)
}
func cloneMetadata(m metadata) metadata {
	hashes := make(map[string]string, len(m.Hashes))
	for k, v := range m.Hashes {
		hashes[k] = v
	}
	m.Hashes = hashes
	if m.Job != nil {
		j := *m.Job
		j.Feeds = slices.Clone(j.Feeds)
		m.Job = &j
	}
	return m
}
func (s *Store) snapshot() metadata { s.mu.RLock(); defer s.mu.RUnlock(); return cloneMetadata(s.meta) }
func (s *Store) update(fn func(*bolt.Tx, *metadata) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := cloneMetadata(s.meta)
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
func other(name string) string {
	if strings.HasSuffix(name, "-a") {
		return strings.TrimSuffix(name, "-a") + "-b"
	}
	return strings.TrimSuffix(name, "-b") + "-a"
}

func indexBucket(b *bolt.Bucket, key string) *bolt.Bucket {
	hash := sha256.Sum256([]byte(key))
	return b.Bucket([]byte("index")).Bucket(hash[:])
}

func changePostings(b *bolt.Bucket, keys []string, id string, add bool) error {
	root := b.Bucket([]byte("index"))
	for _, key := range keys {
		hash := sha256.Sum256([]byte(key))
		if strings.HasPrefix(key, "name:") {
			if err := changeNameIndex(root, hash[:], id, add); err != nil {
				return err
			}
			continue
		}
		bucket := root.Bucket(hash[:])
		if add {
			var err error
			if bucket == nil {
				bucket, err = root.CreateBucket(hash[:])
				if err != nil {
					return err
				}
			}
			if bucket.Get([]byte(id)) == nil {
				if _, err := bucket.NextSequence(); err != nil {
					return err
				}
				if err := bucket.Put([]byte(id), []byte{1}); err != nil {
					return err
				}
			}
		} else if bucket != nil && bucket.Get([]byte(id)) != nil {
			if err := bucket.Delete([]byte(id)); err != nil {
				return err
			}
			count := bucket.Sequence()
			if count == 0 {
				return apperror.New("invalid_nvd_index_count", "invalid NVD index count")
			}
			if count == 1 {
				if err := root.DeleteBucket(hash[:]); err != nil {
					return err
				}
			} else if err := bucket.SetSequence(count - 1); err != nil {
				return err
			}
		}
	}
	return nil
}

// Dictionary names normally map to one UUID. A flat value avoids creating a
// nested bbolt bucket for every dictionary entry while preserving duplicate IDs.
func changeNameIndex(root *bolt.Bucket, key []byte, id string, add bool) error {
	value := root.Get(key)
	if len(value) == 0 {
		if add {
			return root.Put(key, []byte(id))
		}
		return nil
	}
	ids := bytes.Split(value, []byte{0})
	found := -1
	for i, candidate := range ids {
		if string(candidate) == id {
			found = i
			break
		}
	}
	if add {
		if found >= 0 {
			return nil
		}
		return root.Put(key, append(append(bytes.Clone(value), 0), []byte(id)...))
	}
	if found < 0 {
		return nil
	}
	ids = append(ids[:found], ids[found+1:]...)
	if len(ids) == 0 {
		return root.Delete(key)
	}
	return root.Put(key, bytes.Join(ids, []byte{0}))
}

func (s *Store) remove(tx *bolt.Tx, generation, kind, id string) error {
	b := tx.Bucket([]byte(generation))
	records := b.Bucket([]byte("records"))
	data := records.Get([]byte(id))
	if data == nil {
		return nil
	}
	var raw json.RawMessage
	if err := s.decode(kind+"/"+id, data, &raw); err != nil {
		return err
	}
	_, keys, err := indexKeys(kind, raw)
	if err != nil {
		return err
	}
	if err := changePostings(b, keys, id, false); err != nil {
		return err
	}
	if err := records.Delete([]byte(id)); err != nil {
		return err
	}
	count := records.Sequence()
	if count == 0 {
		return apperror.New("invalid_nvd_record_count", "invalid NVD record count")
	}
	return records.SetSequence(count - 1)
}

// Cleanup keeps cursors and mmap byte slices inside a bounded write transaction.
func (s *Store) clear(ctx context.Context, generation, kind, prefix string) error {
	for {
		removed := 0
		removedBytes := 0
		more := false
		err := s.db.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := tx.Bucket([]byte(generation)).Bucket([]byte("records"))
			c := b.Cursor()
			for k, value := c.Seek([]byte(prefix)); k != nil && strings.HasPrefix(string(k), prefix) && removed < batchLimit(kind) && removedBytes < 4<<20; k, value = c.Seek([]byte(prefix)) {
				id := string(k)
				removedBytes += len(value)
				if err := s.remove(tx, generation, kind, id); err != nil {
					return err
				}
				removed++
			}
			key, _ := c.Seek([]byte(prefix))
			more = key != nil && strings.HasPrefix(string(key), prefix)
			return nil
		})
		if err != nil || !more {
			return err
		}
	}
}

func (s *Store) begin(ctx context.Context, full bool, feeds []Feed) error {
	m := s.snapshot()
	if m.Job != nil {
		return nil
	}
	nvdTarget := m.NVD
	if full {
		nvdTarget = other(m.NVD)
		if err := s.clear(ctx, nvdTarget, "nvd", ""); err != nil {
			return err
		}
	}
	cpeTarget := other(m.CPE)
	if err := s.clear(ctx, cpeTarget, "cpe", ""); err != nil {
		return err
	}
	return s.update(func(_ *bolt.Tx, m *metadata) error {
		m.Job = &job{Full: full, NVDTarget: nvdTarget, CPETarget: cpeTarget, StartedAt: time.Now().UTC(), Feeds: feeds}
		return nil
	})
}

func (s *Store) batch(ctx context.Context, rows []json.RawMessage, next int) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		j := m.Job
		if j == nil || j.Feed >= len(j.Feeds) || next < j.Offset {
			return apperror.New("invalid_nvd_import_checkpoint", "invalid NVD import checkpoint")
		}
		feed := j.Feeds[j.Feed]
		generation := j.NVDTarget
		if feed.Kind == "cpe" {
			generation = j.CPETarget
		}
		b := tx.Bucket([]byte(generation))
		records := b.Bucket([]byte("records"))
		for _, raw := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			id, keys, err := indexKeys(feed.Kind, raw)
			if err != nil {
				return err
			}
			if old := records.Get([]byte(id)); old != nil {
				if err := s.remove(tx, generation, feed.Kind, id); err != nil {
					return err
				}
			}
			data, err := s.encode(feed.Kind+"/"+id, raw)
			if err != nil {
				return err
			}
			if err := records.Put([]byte(id), data); err != nil {
				return err
			}
			if _, err := records.NextSequence(); err != nil {
				return err
			}
			if err := changePostings(b, keys, id, true); err != nil {
				return err
			}
		}
		j.Offset = next
		return nil
	})
}

func (s *Store) finishFeed(ctx context.Context, feed Feed, changed bool) error {
	return s.update(func(_ *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		j := m.Job
		if j == nil || j.Feed >= len(j.Feeds) || j.Feeds[j.Feed].ID != feed.ID {
			return apperror.New("invalid_completed_nvd_feed", "invalid completed NVD feed")
		}
		if feed.Kind == "cpe" {
			j.CPEChanged = changed
			j.CPEAt = feed.At
		} else if feed.ID == "modified" {
			j.NVDAt = feed.At
		}
		m.Hashes[feed.ID] = feed.SHA
		j.Feed++
		j.Offset = 0
		return nil
	})
}

func (s *Store) publish(ctx context.Context) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		j := m.Job
		if j == nil || j.Feed != len(j.Feeds) {
			return apperror.New("nvd_import_is_incomplete", "NVD import is incomplete")
		}
		if j.Full {
			m.NVD = j.NVDTarget
		}
		if j.CPEChanged {
			m.CPE = j.CPETarget
		}
		if tx.Bucket([]byte(m.NVD)).Bucket([]byte("records")).Sequence() == 0 || tx.Bucket([]byte(m.CPE)).Bucket([]byte("records")).Sequence() == 0 {
			return apperror.New("empty_nvd_catalogue_or_cpe_dictionary", "empty NVD catalogue or CPE dictionary")
		}
		m.Ready = true
		m.NVDAt = j.NVDAt
		if j.Full && j.StartedAt.Before(m.NVDAt) {
			m.NVDAt = j.StartedAt
		}
		m.CPEAt = j.CPEAt
		m.CheckedAt = time.Now().UTC()
		m.Job = nil
		return nil
	})
}

func (s *Store) Stats() (Stats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m := s.meta
	stats := Stats{Path: s.db.Path(), Initialized: m.Ready, SourceAt: m.NVDAt, CPEAt: m.CPEAt, CheckedAt: m.CheckedAt, Resumable: m.Job != nil}
	if j := m.Job; j != nil {
		stats.Imported = j.Offset
		stats.FeedsDone = j.Feed
		stats.FeedsTotal = len(j.Feeds)
		if j.Feed < len(j.Feeds) {
			stats.Feed = j.Feeds[j.Feed].ID
		}
	}
	err := s.db.View(func(tx *bolt.Tx) error {
		stats.Records = tx.Bucket([]byte(m.NVD)).Bucket([]byte("records")).Sequence()
		stats.CPEs = tx.Bucket([]byte(m.CPE)).Bucket([]byte("records")).Sequence()
		return nil
	})
	if err == nil {
		info, e := s.root.Stat(Filename)
		err = e
		if e == nil {
			stats.Bytes = info.Size()
		}
	}
	return stats, err
}

type QueryResult struct {
	Records   []Record
	CheckedAt time.Time
	CPEAt     time.Time
	Uncertain bool
}

var ErrNotReady = apperror.New("initialize_the_local_nvd_database_in_configuration", "initialize the local NVD database in Configuration")

// Query pages through an inverted index with short read transactions. Publication
// takes the write lock, so one query consistently uses one catalogue generation.
func (s *Store) Query(ctx context.Context, name, cpe string) (QueryResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := QueryResult{Records: []Record{}, CheckedAt: s.meta.NVDAt}
	if !s.meta.Ready {
		return result, ErrNotReady
	}
	var target []string
	var keys []string
	if cpe != "" {
		result.CPEAt = s.meta.CPEAt
		var err error
		target, err = parseCPE(cpe)
		if err != nil {
			return result, err
		}
		key := productKey(target)
		if key == "product:*" {
			return result, apperror.New("local_matching_needs_a_concrete_cpe_vendor_and_product", "local matching needs a concrete CPE vendor and product")
		}
		keys = []string{key, "product:*"}
	} else {
		terms := words(name)
		if len(terms) == 0 || len(terms[0]) > 256 {
			return result, apperror.New("component_name_cannot_be_indexed_locally", "component name cannot be indexed locally")
		}
		keys = []string{"word:" + terms[0]}
	}
	seen := map[string]bool{}
	for _, key := range keys {
		after := ""
		for {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			processed := 0
			err := s.db.View(func(tx *bolt.Tx) error {
				b := tx.Bucket([]byte(s.meta.NVD))
				index := indexBucket(b, key)
				if index == nil {
					return nil
				}
				cursor := index.Cursor()
				id, _ := cursor.Seek([]byte(after))
				if string(id) == after {
					id, _ = cursor.Next()
				}
				for ; id != nil && processed < batchSize; id, _ = cursor.Next() {
					after = string(id)
					processed++
					if seen[after] {
						continue
					}
					seen[after] = true
					var record Record
					if err := s.decode("nvd/"+after, b.Bucket([]byte("records")).Get(id), &record); err != nil {
						return err
					}
					if strings.EqualFold(record.VulnStatus, "Rejected") {
						continue
					}
					if cpe != "" {
						match := matchRecord(record, target)
						if match == no {
							continue
						}
						if match == unknown {
							result.Uncertain = true
						}
					} else if !strings.Contains(strings.Join(words(description(record)), " "), strings.Join(words(name), " ")) {
						continue
					}
					result.Records = append(result.Records, record)
				}
				return nil
			})
			if err != nil {
				return result, err
			}
			if processed < batchSize {
				break
			}
		}
	}
	// The dictionary provides a local check for deprecated product identities.
	if cpe != "" {
		err := s.db.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(s.meta.CPE))
			hash := sha256.Sum256([]byte("name:" + strings.ToLower(cpe)))
			value := b.Bucket([]byte("index")).Get(hash[:])
			if len(value) == 0 {
				return nil
			}
			ids := bytes.Split(value, []byte{0})
			id := ids[0]
			if len(ids) > 1 {
				result.Uncertain = true
			}
			var record CPE
			if err := s.decode("cpe/"+string(id), b.Bucket([]byte("records")).Get(id), &record); err != nil {
				return err
			}
			if record.Deprecated {
				result.Uncertain = true
			}
			return nil
		})
		if err != nil {
			return result, apperror.Newf("read_cpe", "could not read the CPE dictionary: %w", err)
		}
	}
	return result, nil
}
