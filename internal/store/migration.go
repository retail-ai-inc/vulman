package store

import (
	"crypto/rand"
	"encoding/json"

	"vulman/internal/apperror"
	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

// migrateRecords runs inside initialize's single durable transaction. bbolt
// retains the old pages until commit, so an interruption never publishes a
// partial schema. The key, API cache, and catalogue files are unchanged.
func (s *Store) migrateRecords(tx *bolt.Tx) error {
	bucket := tx.Bucket([]byte("state"))
	if root := bucket.Bucket([]byte(recordsBucket)); root != nil {
		return s.initializeRevisions(tx, root)
	}
	state, err := s.readLegacy(tx)
	if err != nil {
		return err
	}
	if _, err := bucket.CreateBucket([]byte(recordsBucket)); err != nil {
		return err
	}
	if err := s.writeRecords(tx, state); err != nil {
		return err
	}

	// Older builds decrypt v1 and expect an object. An encrypted JSON string
	// fails that validation, preventing them from loading an empty workspace or
	// writing a stale legacy snapshot over the current records.
	marker, err := json.Marshal("This workspace uses Vulman record storage format 2. Open it with a compatible Vulman version.")
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if err := bucket.Put([]byte("v1"), s.aead.Seal(nonce, nonce, marker, []byte("vulman-state-v1"))); err != nil {
		return err
	}
	_, err = bucket.NextSequence()
	return err
}

func (s *Store) readLegacy(tx *bolt.Tx) (model.State, error) {
	state := model.Defaults()
	data := tx.Bucket([]byte("state")).Get([]byte("v1"))
	if data == nil {
		return state, nil
	}
	n := s.aead.NonceSize()
	if len(data) < n+s.aead.Overhead() {
		return state, apperror.New("invalid_database_state", "invalid database state")
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte("vulman-state-v1"))
	if err != nil {
		return state, apperror.Newf("decrypt_database", "cannot decrypt database: %w", err)
	}
	if err := json.Unmarshal(plain, &state); err != nil {
		return state, errInvalidRecords
	}
	return state, nil
}
