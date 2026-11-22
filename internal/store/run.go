package store

import (
	"fmt"
	"slices"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

var ErrRunNotFound = apperror.New("assessment_is_no_longer_active_reload_its_workflow", "assessment is no longer active; reload its workflow")

// RunProject exposes only the scheduling and activity fields a workflow update
// may change. Findings, inventory, credentials, and other runs are never read.
type RunProject struct {
	Syncing  bool
	Schedule string
	NextRun  time.Time
}

// UpdateRun commits the exact run, its logs, project activity, and snapshot
// sequence together. It shares bbolt's writer lock with full-state transactions
// so a late progress event cannot resurrect a deleted project or run.
func (s *Store) UpdateRun(projectID, runID string, fn func(*RunProject, *model.Run) error) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		root := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))
		manifest, err := s.readManifest(root)
		if err != nil {
			return err
		}
		if !slices.Contains(manifest.Projects, projectID) {
			return ErrRunNotFound
		}
		projects := root.Bucket([]byte("projects"))
		if projects == nil {
			return errInvalidRecords
		}
		key := s.projectKey(projectID)
		bucket := projects.Bucket(key)
		identity := fmt.Sprintf("projects/%x", key)
		record, err := s.readProject(bucket, identity, projectID, false)
		if err != nil {
			return err
		}
		index := slices.Index(record.Runs, runID)
		if index < 0 {
			return ErrRunNotFound
		}
		runs := bucket.Bucket([]byte("runs"))
		if runs == nil {
			return errInvalidRecords
		}
		runBucket := runs.Bucket(uintBytes(uint64(index)))
		runIdentity := fmt.Sprintf("%s/runs/%d", identity, index)
		run, err := s.readRun(runBucket, runIdentity, runID)
		if err != nil {
			return err
		}
		project := RunProject{Syncing: record.Project.Syncing, Schedule: record.Project.Schedule, NextRun: record.Project.NextRun}
		if err := fn(&project, &run); err != nil {
			return err
		}
		if run.ID != runID {
			return errInvalidRecords
		}
		projectChanged := project != (RunProject{Syncing: record.Project.Syncing, Schedule: record.Project.Schedule, NextRun: record.Project.NextRun})
		record.Project.Syncing, record.Project.Schedule, record.Project.NextRun = project.Syncing, project.Schedule, project.NextRun
		if projectChanged {
			record.MetadataRevision, err = nextRecordRevision(tx)
			if err != nil {
				return err
			}
		}
		runRevision, dirtyRun, err := s.writeRun(runBucket, runIdentity, run)
		if err != nil {
			return err
		}
		if dirtyRun {
			record.WorkflowRevision = runRevision
			if len(record.RunRevisions) != len(record.Runs) {
				return errInvalidRecords
			}
			record.RunRevisions[index] = runRevision
		}
		if err := s.writeRecord(bucket, []byte("metadata"), identity+"/metadata", record); err != nil {
			return err
		}
		return s.finishUpdate(tx)
	})
}
