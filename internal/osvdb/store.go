package osvdb

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"vulman/internal/apperror"
)

const batchSize = 256

type ecosystemState struct {
	Active     string    `json:"active"`
	Ready      bool      `json:"ready"`
	CheckedAt  time.Time `json:"checked_at"`
	BaselineAt time.Time `json:"baseline_at"`
	SourceAt   time.Time `json:"source_at"`
}

type blob struct {
	Name       string    `json:"name"`
	Generation string    `json:"generation"`
	Size       int64     `json:"size"`
	CRC        string    `json:"crc"`
	Updated    time.Time `json:"updated"`
}

type job struct {
	Ecosystem    string    `json:"ecosystem"`
	Full         bool      `json:"full"`
	Target       string    `json:"target"`
	StartedAt    time.Time `json:"started_at"`
	Object       blob      `json:"object"`
	Offset       int       `json:"offset"`
	Total        int       `json:"total"`
	Planned      bool      `json:"planned"`
	PlanOffset   int       `json:"plan_offset"`
	PendingTotal int       `json:"pending_total"`
}

type metadata struct {
	Ecosystems map[string]ecosystemState `json:"ecosystems"`
	Plan       []string                  `json:"plan"`
	Next       int                       `json:"next"`
	Rebuild    bool                      `json:"rebuild"`
	StartedAt  time.Time                 `json:"started_at"`
	Job        *job                      `json:"job,omitempty"`
}

type pendingRecord struct {
	ID string    `json:"id"`
	At time.Time `json:"at"`
}

type Store struct {
	db   *bolt.DB
	root *os.Root
	aead cipher.AEAD
	mu   sync.RWMutex
	meta metadata
}

func Open(dir string, aead cipher.AEAD) (*Store, error) {
	return open(dir, aead, false)
}

// OpenReadOnly opens a published catalogue without creating or changing files.
func OpenReadOnly(dir string, aead cipher.AEAD) (*Store, error) {
	return open(dir, aead, true)
}

func open(dir string, aead cipher.AEAD, readOnly bool) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(root.Name(), Filename)
	if readOnly {
		info, err := root.Lstat(Filename)
		if err != nil {
			return nil, errors.Join(err, root.Close())
		}
		if !info.Mode().IsRegular() {
			return nil, errors.Join(apperror.New("invalid_osv_metadata", "invalid OSV metadata"), root.Close())
		}
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{ReadOnly: readOnly, Timeout: time.Second, OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
		if name != path {
			return nil, apperror.New("unexpected_osv_database_path", "unexpected OSV database path")
		}

		if readOnly {
			flags &^= os.O_CREATE
		}
		return root.OpenFile(Filename, flags, mode)
	}})

	if err != nil {
		return nil, errors.Join(err, root.Close())
	}

	s := &Store{db: db, root: root, aead: aead}
	load := func(tx *bolt.Tx) error {
		for _, name := range []string{"meta", "catalogues", "pending"} {
			if readOnly {
				if tx.Bucket([]byte(name)) == nil {
					return apperror.New("invalid_osv_metadata", "invalid OSV metadata")
				}
				continue
			}
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return err
			}
		}

		raw := tx.Bucket([]byte("meta")).Get([]byte("state"))
		if raw == nil {
			if readOnly {
				return apperror.New("invalid_osv_metadata", "invalid OSV metadata")
			}
			s.meta = metadata{Ecosystems: map[string]ecosystemState{}}
			return s.writeMetadata(tx, s.meta)
		}

		if err := s.decode("metadata", raw, &s.meta); err != nil {
			return err
		}

		if s.meta.Ecosystems == nil || s.meta.Next < 0 || s.meta.Next > len(s.meta.Plan) {
			return apperror.New("invalid_osv_metadata", "invalid OSV metadata")
		}

		return nil
	}
	if readOnly {
		err = db.View(load)
	} else {
		err = db.Update(load)
	}

	if err != nil {
		return nil, errors.Join(err, db.Close(), root.Close())
	}

	return s, nil
}

func (s *Store) Close() error {
	return errors.Join(s.db.Close(), s.root.Close())
}

func (s *Store) encode(identity string, value any) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return s.aead.Seal(nonce, nonce, plain, []byte("vulman-osv-v1:"+identity)), nil
}

func (s *Store) decode(identity string, data []byte, out any) error {
	n := s.aead.NonceSize()
	if len(data) < n {
		return apperror.New("invalid_encrypted_osv_record", "invalid encrypted OSV record")
	}

	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte("vulman-osv-v1:"+identity))
	if err != nil {
		return err
	}

	return json.Unmarshal(plain, out)
}

func cloneMetadata(m metadata) metadata {
	states := make(map[string]ecosystemState, len(m.Ecosystems))
	for key, value := range m.Ecosystems {
		states[key] = value
	}

	m.Ecosystems = states
	m.Plan = slices.Clone(m.Plan)
	if m.Job != nil {
		j := *m.Job
		m.Job = &j
	}

	return m
}

func (s *Store) snapshot() metadata {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneMetadata(s.meta)
}

func (s *Store) writeMetadata(tx *bolt.Tx, m metadata) error {
	data, err := s.encode("metadata", m)
	if err != nil {
		return err
	}

	return tx.Bucket([]byte("meta")).Put([]byte("state"), data)
}

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

func catalogue(tx *bolt.Tx, ecosystem, generation string) *bolt.Bucket {
	eco := tx.Bucket([]byte("catalogues")).Bucket([]byte(ecosystem))
	if eco == nil {
		return nil
	}

	return eco.Bucket([]byte(generation))
}

func (s *Store) ensure(ecosystem string) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		parent, err := tx.Bucket([]byte("catalogues")).CreateBucketIfNotExists([]byte(ecosystem))
		if err != nil {
			return err
		}

		for _, generation := range []string{"a", "b"} {
			b, err := parent.CreateBucketIfNotExists([]byte(generation))
			if err != nil {
				return err
			}

			for _, child := range []string{"records", "index"} {
				if _, err := b.CreateBucketIfNotExists([]byte(child)); err != nil {
					return err
				}
			}
		}

		if _, exists := m.Ecosystems[ecosystem]; !exists {
			m.Ecosystems[ecosystem] = ecosystemState{Active: "a"}
		}

		return nil
	})
}

func other(active string) string {
	if active == "a" {
		return "b"
	}

	return "a"
}

func indexKey(ecosystem, name string) [32]byte {
	return sha256.Sum256([]byte(ecosystem + "\x00" + PackageName(ecosystem, name)))
}

func (s *Store) postings(b *bolt.Bucket, ecosystem string, record Record, add bool) error {
	if record.Withdrawn != "" {
		return nil
	}

	seen := map[[32]byte]bool{}
	for _, affected := range record.Affected {
		base, err := Ecosystem(affected.Package.Ecosystem)
		if err != nil || base != ecosystem || affected.Package.Name == "" {
			continue
		}

		key := indexKey(affected.Package.Ecosystem, affected.Package.Name)
		if seen[key] {
			continue
		}

		seen[key] = true
		root := b.Bucket([]byte("index"))
		posting := root.Bucket(key[:])
		if add {
			if posting == nil {
				posting, err = root.CreateBucket(key[:])
				if err != nil {
					return err
				}
			}

			if err := posting.Put([]byte(record.ID), []byte{1}); err != nil {
				return err
			}
		} else if posting != nil {
			if err := posting.Delete([]byte(record.ID)); err != nil {
				return err
			}

			if first, _ := posting.Cursor().First(); first == nil {
				if err := root.DeleteBucket(key[:]); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func (s *Store) remove(tx *bolt.Tx, ecosystem, generation, id string) error {
	b := catalogue(tx, ecosystem, generation)
	records := b.Bucket([]byte("records"))
	data := records.Get([]byte(id))
	if data == nil {
		return nil
	}

	var record Record
	if err := s.decode(ecosystem+"/"+id, data, &record); err != nil {
		return err
	}

	if err := s.postings(b, ecosystem, record, false); err != nil {
		return err
	}

	if err := records.Delete([]byte(id)); err != nil {
		return err
	}

	if records.Sequence() == 0 {
		return apperror.New("invalid_osv_record_counter", "invalid OSV record counter")
	}

	return records.SetSequence(records.Sequence() - 1)
}

func (s *Store) clear(ctx context.Context, ecosystem, generation string) error {
	for {
		done := false
		err := s.db.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			records := catalogue(tx, ecosystem, generation).Bucket([]byte("records"))
			for count, size := 0, 0; count < batchSize && size < 4<<20; count++ {
				key, data := records.Cursor().First()
				if key == nil {
					done = true
					return nil
				}

				size += len(data)
				if err := s.remove(tx, ecosystem, generation, string(key)); err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil || done {
			return err
		}
	}
}

func (s *Store) putRows(ctx context.Context, rows []json.RawMessage, offset int, pendingID string) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		j := m.Job
		if j == nil || offset < j.Offset {
			return apperror.New("invalid_osv_import_checkpoint", "invalid OSV import checkpoint")
		}

		b := catalogue(tx, j.Ecosystem, j.Target)
		records := b.Bucket([]byte("records"))
		for _, raw := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}

			var record Record
			if err := json.Unmarshal(raw, &record); err != nil {
				return err
			}

			if !recordID.MatchString(record.ID) || record.Modified.IsZero() || !supportedSchema(record.SchemaVersion) {
				return apperror.New("invalid_osv_advisory_identity_or_modification_timestamp", "invalid OSV advisory identity or modification timestamp")
			}

			if old := records.Get([]byte(record.ID)); old != nil {
				var previous Record
				if err := s.decode(j.Ecosystem+"/"+record.ID, old, &previous); err != nil {
					return err
				}

				if previous.Modified.After(record.Modified) {
					continue
				}
			}

			if err := s.remove(tx, j.Ecosystem, j.Target, record.ID); err != nil {
				return err
			}

			data, err := s.encode(j.Ecosystem+"/"+record.ID, raw)
			if err != nil {
				return err
			}

			if err := records.Put([]byte(record.ID), data); err != nil {
				return err
			}

			if _, err := records.NextSequence(); err != nil {
				return err
			}

			if err := s.postings(b, j.Ecosystem, record, true); err != nil {
				return err
			}
		}

		if pendingID != "" {
			if err := tx.Bucket([]byte("pending")).Delete([]byte(pendingID)); err != nil {
				return err
			}
		}

		j.Offset = offset
		return nil
	})
}

var ErrNotReady = apperror.New("initialize_this_osv_ecosystem_in_configuration", "initialize this OSV ecosystem in Configuration")

type QueryResult struct {
	Records   []Record
	Uncertain bool
	CheckedAt time.Time
}

func (s *Store) Query(ctx context.Context, ecosystem, name, version string) (QueryResult, error) {
	base, err := Ecosystem(ecosystem)
	if err != nil {
		return QueryResult{}, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.meta.Ecosystems[base]
	result := QueryResult{CheckedAt: state.CheckedAt, Records: []Record{}}
	if !state.Ready {
		return result, ErrNotReady
	}

	after := ""
	key := indexKey(ecosystem, name)
	for {
		if err := ctx.Err(); err != nil {
			return result, err
		}

		count := 0
		err := s.db.View(func(tx *bolt.Tx) error {
			b := catalogue(tx, base, state.Active)
			posting := b.Bucket([]byte("index")).Bucket(key[:])
			if posting == nil {
				return nil
			}

			cursor := posting.Cursor()
			id, _ := cursor.Seek([]byte(after))
			if string(id) == after {
				id, _ = cursor.Next()
			}

			for ; id != nil && count < batchSize; id, _ = cursor.Next() {
				after = string(id)
				count++
				var record Record
				if err := s.decode(base+"/"+after, b.Bucket([]byte("records")).Get(id), &record); err != nil {
					return err
				}

				matched, unknown := Match(record, ecosystem, name, version)
				if matched || unknown {
					result.Records = append(result.Records, record)
				}

				result.Uncertain = result.Uncertain || unknown
			}

			return nil
		})

		if err != nil || count < batchSize {
			return result, err
		}
	}
}

func (s *Store) finish(ctx context.Context, advance bool) error {
	return s.update(func(tx *bolt.Tx, m *metadata) error {
		if err := ctx.Err(); err != nil {
			return err
		}

		j := m.Job
		if j == nil {
			return apperror.New("missing_osv_import", "missing OSV import")
		}

		if j.Full && (j.Total <= 0 || j.Offset != j.Total) {
			return apperror.New("osv_baseline_import_is_incomplete", "OSV baseline import is incomplete")
		}

		if !j.Full {
			if key, _ := tx.Bucket([]byte("pending")).Cursor().First(); !j.Planned || key != nil {
				return apperror.New("osv_changes_remain_unprocessed", "OSV changes remain unprocessed")
			}
		}

		state := m.Ecosystems[j.Ecosystem]
		state.Active, state.Ready = j.Target, true
		state.CheckedAt, state.SourceAt = j.StartedAt, j.Object.Updated
		if j.Full {
			state.BaselineAt = j.StartedAt
			state.CheckedAt = j.Object.Updated
		}

		m.Ecosystems[j.Ecosystem] = state
		m.Job = nil
		if advance {
			m.Next++
		}

		return nil
	})
}

func (s *Store) nextPending() (pendingRecord, bool, error) {
	var record pendingRecord
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		id, data := tx.Bucket([]byte("pending")).Cursor().First()
		if id == nil {
			return nil
		}

		found = true
		return s.decode("pending/"+string(id), data, &record)
	})

	return record, found, err
}

func (s *Store) clearPending(ctx context.Context) error {
	for {
		count := 0
		err := s.db.Update(func(tx *bolt.Tx) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			b := tx.Bucket([]byte("pending"))
			for ; count < batchSize; count++ {
				id, _ := b.Cursor().First()
				if id == nil {
					return nil
				}

				if err := b.Delete(id); err != nil {
					return err
				}
			}

			return nil
		})

		if err != nil || count < batchSize {
			return err
		}
	}
}

func (s *Store) fileSize() (int64, error) {
	info, err := s.root.Stat(Filename)
	if err != nil {
		return 0, apperror.Newf("osv_size", "OSV database size: %w", err)
	}

	return info.Size(), nil
}
