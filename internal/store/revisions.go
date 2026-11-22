package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"

	bolt "go.etcd.io/bbolt"
)

func nextRecordRevision(tx *bolt.Tx) (uint64, error) {
	version := tx.Bucket([]byte("state")).Sequence()
	if version == math.MaxUint64 {
		return 0, errInvalidRecords
	}
	return version + 1, nil
}

func sameRecordValue(left, right any) (bool, error) {
	first, err := json.Marshal(left)
	if err != nil {
		return false, err
	}
	second, err := json.Marshal(right)
	return bytes.Equal(first, second), err
}

// Earlier record-format workspaces need only small encrypted header changes.
// The revisions and snapshot sequence publish in one transaction; payloads and
// catalogue files are untouched, and an interruption rolls back these headers.
func (s *Store) initializeRevisions(tx *bolt.Tx, root *bolt.Bucket) error {
	manifest, err := s.readManifest(root)
	if err != nil || manifest.RevisionsReady {
		return err
	}
	revision, err := nextRecordRevision(tx)
	if err != nil {
		return err
	}
	projects := root.Bucket([]byte("projects"))
	if projects == nil {
		return errInvalidRecords
	}
	for _, id := range manifest.Projects {
		key := s.projectKey(id)
		bucket := projects.Bucket(key)
		identity := fmt.Sprintf("projects/%x", key)
		record, err := s.readProject(bucket, identity, id, false)
		if err != nil {
			return err
		}
		runs := bucket.Bucket([]byte("runs"))
		if runs == nil {
			return errInvalidRecords
		}
		record.RunRevisions = nil
		for index, runID := range record.Runs {
			runBucket := runs.Bucket(uintBytes(uint64(index)))
			runIdentity := fmt.Sprintf("%s/runs/%d/metadata", identity, index)
			var run runRecord
			if err := s.readRecord(runBucket, []byte("metadata"), runIdentity, &run); err != nil {
				return err
			}
			if run.Run.ID != runID {
				return errInvalidRecords
			}
			run.Revision = revision
			if err := s.writeRecord(runBucket, []byte("metadata"), runIdentity, run); err != nil {
				return err
			}
			record.RunRevisions = append(record.RunRevisions, revision)
		}
		record.MetadataRevision, record.FindingsRevision, record.WorkflowRevision = revision, revision, revision
		if err := s.writeRecord(bucket, []byte("metadata"), identity+"/metadata", record); err != nil {
			return err
		}
	}
	manifest.RevisionsReady = true
	manifest.SettingsRevision, manifest.ProjectOrderRevision = revision, revision
	if err := s.writeRecord(root, []byte("manifest"), "manifest", manifest); err != nil {
		return err
	}
	_, err = tx.Bucket([]byte("state")).NextSequence()
	return err
}
