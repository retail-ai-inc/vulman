package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

// Store independently encrypts workspace records at rest. The local key is owned
// by the OS account; it is not a defense against processes running as that user.
type Store struct {
	db          *bolt.DB
	root        *os.Root
	indexKey    [32]byte
	aead        cipher.AEAD
	cacheHits   atomic.Uint64
	cacheMisses atomic.Uint64
}

const (
	databaseFile = "vulman.db"
	keyFile      = "vulman.key"
	keySize      = 32
)

var ErrMissingWorkspaceFiles = apperror.New("vulman_db_and_vulman_key_must_both_exist_and_contain_data", "vulman.db and vulman.key must both exist and contain data")

type Paths struct {
	Database string `json:"database"`
	Key      string `json:"key"`
}

func (s *Store) Paths() Paths {
	return Paths{Database: s.db.Path(), Key: filepath.Join(s.root.Name(), keyFile)}
}

func Open(dir string) (*Store, error) {
	return open(dir, true)
}

// OpenExisting opens a workspace only if both files exist and its state decrypts.
func OpenExisting(dir string) (*Store, error) {
	return open(dir, false)
}

func open(dir string, create bool) (*Store, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}

	if create {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, err
		}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	s, err := openStore(root, create)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	return s, nil
}

func loadOrCreateKey(root *os.Root, create bool) ([]byte, error) {
	f, err := root.Open(keyFile)
	if err == nil {
		key, readErr := io.ReadAll(io.LimitReader(f, keySize+1))
		return key, errors.Join(readErr, f.Close())
	}
	if !create || !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	// Count even a dangling database symlink as an existing database.
	if _, err := root.Lstat(databaseFile); err == nil {
		return nil, apperror.New("workspace_key_missing", "database exists but encryption key is missing; restore vulman.key from backup")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	f, err = root.OpenFile(keyFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	_, writeErr := f.Write(key)
	return key, errors.Join(writeErr, f.Close())
}

func openStore(root *os.Root, create bool) (_ *Store, err error) {
	var db *bolt.DB
	var candidate *os.File
	if !create {
		// bbolt reads memory-mapped pages while opening and validating a workspace.
		// A corrupt page can panic before bbolt returns its database handle.
		previous := debug.SetPanicOnFault(true)
		defer debug.SetPanicOnFault(previous)
		defer func() {
			if failure := recover(); failure != nil {
				err = apperror.New("invalid_workspace_database", "invalid workspace database")
				if db != nil {
					err = errors.Join(err, db.Close())
				} else if candidate != nil {
					err = errors.Join(err, candidate.Close())
				}
			}
		}()
		for _, name := range []string{databaseFile, keyFile} {
			info, err := root.Stat(name)
			if errors.Is(err, os.ErrNotExist) || err == nil && info.Size() == 0 {
				return nil, ErrMissingWorkspaceFiles
			}
			if err != nil {
				return nil, err
			}
			if !info.Mode().IsRegular() {
				return nil, apperror.Newf("regular_file_required", "%s must be a regular file", name)
			}
		}
	}
	key, err := loadOrCreateKey(root, create)
	if err != nil {
		return nil, err
	}
	if len(key) != keySize {
		return nil, apperror.New("invalid_vulman_encryption_key_length", "invalid Vulman encryption key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	path := filepath.Join(root.Name(), databaseFile)
	db, err = bolt.Open(path, 0600, &bolt.Options{
		Timeout: time.Second,
		OpenFile: func(name string, flags int, mode os.FileMode) (*os.File, error) {
			if name != path {
				return nil, apperror.New("unexpected_database_path", "unexpected database path")
			}
			if create {
				return root.OpenFile(databaseFile, flags, mode)
			}
			file, err := root.OpenFile(databaseFile, flags&^os.O_CREATE, mode)
			if err != nil {
				return nil, err
			}
			info, err := file.Stat()
			if err == nil && (!info.Mode().IsRegular() || info.Size() == 0) {
				err = ErrMissingWorkspaceFiles
			}
			if err != nil {
				return nil, errors.Join(err, file.Close())
			}
			candidate = file
			return file, nil
		},
	})
	if err != nil {
		return nil, err
	}

	s := &Store{db: db, root: root, aead: aead}
	s.indexKey = recordIndexKey(key)
	err = s.initialize(create)
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return s, nil
}

func (s *Store) initialize(create bool) error {
	migrating := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("state")) == nil && tx.Bucket([]byte("cache-v1")) != nil {
			return errInvalidRecords
		}
		if !create {
			bucket := tx.Bucket([]byte("state"))
			if bucket == nil || bucket.Bucket([]byte(recordsBucket)) == nil && len(bucket.Get([]byte("v1"))) == 0 {
				return apperror.New("workspace_has_no_encrypted_vulman_state", "workspace has no encrypted Vulman state")
			}
		}
		if _, e := tx.CreateBucketIfNotExists([]byte("state")); e != nil {
			return e
		}

		legacy := tx.Bucket([]byte("state"))
		migrating = legacy.Bucket([]byte(recordsBucket)) == nil && len(legacy.Get([]byte("v1"))) != 0
		if err := s.migrateRecords(tx); err != nil {
			return err
		}

		cache, e := tx.CreateBucketIfNotExists([]byte("cache-v1"))
		if e != nil {
			return e
		}

		for _, name := range []string{"entries", "order", "meta"} {
			if _, e = cache.CreateBucketIfNotExists([]byte(name)); e != nil {
				return e
			}
		}

		if e = initializeCacheMetadata(cache); e != nil {
			return e
		}

		meta := cache.Bucket([]byte("meta"))
		s.cacheHits.Store(readUint(meta.Get([]byte("_hits"))))
		s.cacheMisses.Store(readUint(meta.Get([]byte("_misses"))))
		state, e := s.read(tx)
		if e != nil {
			return e
		}

		return applyCacheLimits(cache, state.Settings)
	})
	if err != nil && migrating {
		return apperror.Newf("workspace_migration_failed", "Workspace migration failed. Reopen Vulman to retry safely: %w", err)
	}
	return err
}

func (s *Store) Close() error {
	err := s.db.Update(func(tx *bolt.Tx) error {
		return s.persistCacheCounters(tx.Bucket([]byte("cache-v1")).Bucket([]byte("meta")))
	})

	return errors.Join(err, s.db.Close(), s.root.Close())
}

func (s *Store) read(tx *bolt.Tx) (model.State, error) {
	return s.readRecords(tx)
}

func (s *Store) Read() (model.State, error) {
	var state model.State
	err := s.db.View(func(tx *bolt.Tx) error { var e error; state, e = s.read(tx); return e })
	return state, err
}

// ReadSnapshot skips decryption when since identifies the current committed state.
// An empty token always returns the full snapshot.
func (s *Store) ReadSnapshot(since string) (snapshot *model.State, version string, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		version = strconv.FormatUint(tx.Bucket([]byte("state")).Sequence(), 10)
		if version == since {
			return nil
		}
		state, err := s.read(tx)
		if err != nil {
			return err
		}
		snapshot = &state
		return nil
	})
	return snapshot, version, err
}

func (s *Store) Update(fn func(*model.State) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		state, err := s.read(tx)
		if err != nil {
			return err
		}

		if err = fn(&state); err != nil {
			return err
		}

		cache := tx.Bucket([]byte("cache-v1"))
		if err := applyCacheLimits(cache, state.Settings); err != nil {
			return err
		}
		if err := s.writeRecords(tx, state); err != nil {
			return err
		}
		return s.finishUpdate(tx)
	})
}

func (s *Store) finishUpdate(tx *bolt.Tx) error {
	cache := tx.Bucket([]byte("cache-v1"))
	if cache == nil || cache.Bucket([]byte("meta")) == nil {
		return errInvalidRecords
	}
	if err := s.persistCacheCounters(cache.Bucket([]byte("meta"))); err != nil {
		return err
	}
	_, err := tx.Bucket([]byte("state")).NextSequence()
	return err
}
