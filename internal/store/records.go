package store

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"slices"
	"unicode/utf8"

	"vulman/internal/apperror"
	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

const (
	recordsBucket    = "records-v2"
	recordsSchema    = 2
	findingChunkSize = 256
	logChunkSize     = 64
)

var errInvalidRecords = apperror.New("invalid_workspace_records", "Encrypted workspace records are incomplete or invalid. Restore the database and key from a backup.")

// The manifest, ordering, credentials, metadata and payloads are encrypted.
// HMAC bucket identities reveal neither project names nor caller-supplied IDs.
// Each payload authenticates its complete record location as associated data.
type recordManifest struct {
	Schema               int      `json:"schema"`
	Projects             []string `json:"projects"`
	RevisionsReady       bool     `json:"revisions_ready,omitempty"`
	SettingsRevision     uint64   `json:"settings_revision,omitempty"`
	ProjectOrderRevision uint64   `json:"project_order_revision,omitempty"`
}

type projectRecord struct {
	Project          model.Project `json:"project"`
	Findings         int           `json:"findings"`
	FindingsNil      bool          `json:"findings_nil"`
	Runs             []string      `json:"runs"`
	RunsNil          bool          `json:"runs_nil"`
	MetadataRevision uint64        `json:"metadata_revision,omitempty"`
	FindingsRevision uint64        `json:"findings_revision,omitempty"`
	WorkflowRevision uint64        `json:"workflow_revision,omitempty"`
	RunRevisions     []uint64      `json:"run_revisions,omitempty"`
}

type runRecord struct {
	Run      model.Run `json:"run"`
	Logs     int       `json:"logs"`
	LogsNil  bool      `json:"logs_nil"`
	Revision uint64    `json:"revision,omitempty"`
}

func recordIndexKey(key []byte) (derived [32]byte) {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("vulman-record-index-v2"))
	copy(derived[:], mac.Sum(nil))
	return derived
}

func (s *Store) projectKey(id string) []byte {
	mac := hmac.New(sha256.New, s.indexKey[:])
	_, _ = mac.Write([]byte(id))
	return mac.Sum(nil)
}

func (s *Store) sealRecord(identity string, plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, []byte("vulman-record-v2:"+identity)), nil
}

func (s *Store) openRecord(identity string, data []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(data) < n+s.aead.Overhead() {
		return nil, errInvalidRecords
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte("vulman-record-v2:"+identity))
	if err != nil {
		return nil, apperror.Newf("decrypt_database", "cannot decrypt database: %w", err)
	}
	return plain, nil
}

func (s *Store) readRecord(bucket *bolt.Bucket, key []byte, identity string, value any) error {
	if bucket == nil {
		return errInvalidRecords
	}
	plain, err := s.openRecord(identity, bucket.Get(key))
	if err != nil {
		return err
	}
	if json.Unmarshal(plain, value) != nil {
		return errInvalidRecords
	}
	return nil
}

// Unchanged records retain their nonce and ciphertext; no bbolt Put is issued.
func (s *Store) writeRecord(bucket *bolt.Bucket, key []byte, identity string, value any) error {
	_, err := s.writeRecordChanged(bucket, key, identity, value)
	return err
}

func (s *Store) writeRecordChanged(bucket *bolt.Bucket, key []byte, identity string, value any) (bool, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	if old := bucket.Get(key); old != nil {
		previous, err := s.openRecord(identity, old)
		if err != nil {
			return false, err
		}
		if bytes.Equal(previous, plain) {
			return false, nil
		}
	}
	data, err := s.sealRecord(identity, plain)
	if err != nil {
		return false, err
	}
	return true, bucket.Put(key, data)
}

func (s *Store) readManifest(root *bolt.Bucket) (recordManifest, error) {
	var manifest recordManifest
	if err := s.readRecord(root, []byte("manifest"), "manifest", &manifest); err != nil {
		return manifest, err
	}
	if manifest.Schema != recordsSchema {
		return manifest, apperror.New("workspace_schema_unsupported", "This workspace requires a compatible Vulman version. Its data was not changed.")
	}
	seen := make(map[string]bool, len(manifest.Projects))
	for _, id := range manifest.Projects {
		if seen[id] {
			return manifest, errInvalidRecords
		}
		seen[id] = true
	}
	return manifest, nil
}

func readChunks[T any](s *Store, bucket *bolt.Bucket, identity string, count, size int, nilSlice bool) ([]T, error) {
	if bucket == nil || count < 0 || size <= 0 || nilSlice && count != 0 {
		return nil, errInvalidRecords
	}
	last, _ := bucket.Cursor().Last()
	if count == 0 {
		if last != nil {
			return nil, errInvalidRecords
		}
	} else {
		chunks := (uint64(count) - 1) / uint64(size)
		if !bytes.Equal(last, uintBytes(chunks)) {
			return nil, errInvalidRecords
		}
	}
	if nilSlice {
		return nil, nil
	}
	values := make([]T, 0, count)
	for offset, index := 0, uint64(0); offset < count; index++ {
		var chunk []T
		if err := s.readRecord(bucket, uintBytes(index), fmt.Sprintf("%s/%d", identity, index), &chunk); err != nil {
			return nil, err
		}
		if len(chunk) != min(size, count-offset) {
			return nil, errInvalidRecords
		}
		values = append(values, chunk...)
		offset += len(chunk)
	}
	return values, nil
}

func writeChunks[T any](s *Store, bucket *bolt.Bucket, identity string, values []T, size int) (bool, error) {
	var index uint64
	changed := false
	for offset := 0; offset < len(values); offset += size {
		chunk := values[offset:min(offset+size, len(values))]
		dirty, err := s.writeRecordChanged(bucket, uintBytes(index), fmt.Sprintf("%s/%d", identity, index), chunk)
		if err != nil {
			return false, err
		}
		changed = changed || dirty
		index++
	}
	if key, _ := bucket.Cursor().Seek(uintBytes(index)); key != nil {
		changed = true
	}
	return changed, pruneRecords(bucket, uintBytes(index), false)
}

// Cursor keys and values never escape their owning transaction. Seek again
// after deletion rather than advancing a cursor across a shifted leaf page.
func pruneRecords(bucket *bolt.Bucket, from []byte, nested bool) error {
	cursor := bucket.Cursor()
	for key, _ := cursor.Seek(from); key != nil; key, _ = cursor.Seek(from) {
		var err error
		if nested {
			err = bucket.DeleteBucket(key)
		} else {
			err = cursor.Delete()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) readRun(bucket *bolt.Bucket, identity, id string) (model.Run, error) {
	var record runRecord
	if err := s.readRecord(bucket, []byte("metadata"), identity+"/metadata", &record); err != nil {
		return model.Run{}, err
	}
	if record.Run.ID != id || record.Run.Logs != nil {
		return model.Run{}, errInvalidRecords
	}
	logs, err := readChunks[model.SyncLog](s, bucket.Bucket([]byte("logs")), identity+"/logs", record.Logs, logChunkSize, record.LogsNil)
	record.Run.Logs = logs
	return record.Run, err
}

func (s *Store) writeRun(bucket *bolt.Bucket, identity string, run model.Run) (uint64, bool, error) {
	var old runRecord
	if bucket.Get([]byte("metadata")) != nil {
		if err := s.readRecord(bucket, []byte("metadata"), identity+"/metadata", &old); err != nil {
			return 0, false, err
		}
	}
	logs, err := bucket.CreateBucketIfNotExists([]byte("logs"))
	if err != nil {
		return 0, false, err
	}
	record := runRecord{Run: run, Logs: len(run.Logs), LogsNil: run.Logs == nil, Revision: old.Revision}
	record.Run.Logs = nil
	dirty, err := writeChunks(s, logs, identity+"/logs", run.Logs, logChunkSize)
	if err != nil {
		return 0, false, err
	}
	equal, err := sameRecordValue(old, record)
	if err != nil {
		return 0, false, err
	}
	changed := dirty || !equal || old.Revision == 0
	if changed {
		record.Revision, err = nextRecordRevision(bucket.Tx())
		if err != nil {
			return 0, false, err
		}
	}
	err = s.writeRecord(bucket, []byte("metadata"), identity+"/metadata", record)
	return record.Revision, changed, err
}

func (s *Store) readProject(bucket *bolt.Bucket, identity, id string, withResults bool) (projectRecord, error) {
	var record projectRecord
	if err := s.readRecord(bucket, []byte("metadata"), identity+"/metadata", &record); err != nil {
		return record, err
	}
	if record.Project.ID != id || record.Project.Findings != nil || record.Project.Runs != nil || record.Findings < 0 ||
		record.FindingsNil && record.Findings != 0 || record.RunsNil && len(record.Runs) != 0 {
		return record, errInvalidRecords
	}
	if !withResults {
		return record, nil
	}
	findings, err := readChunks[model.Finding](s, bucket.Bucket([]byte("findings")), identity+"/findings", record.Findings, findingChunkSize, record.FindingsNil)
	if err != nil {
		return record, err
	}
	record.Project.Findings = findings
	if !record.RunsNil {
		record.Project.Runs = make([]model.Run, 0, len(record.Runs))
	}
	runs := bucket.Bucket([]byte("runs"))
	if runs == nil {
		return record, errInvalidRecords
	}
	for index, runID := range record.Runs {
		run, err := s.readRun(runs.Bucket(uintBytes(uint64(index))), fmt.Sprintf("%s/runs/%d", identity, index), runID)
		if err != nil {
			return record, err
		}
		record.Project.Runs = append(record.Project.Runs, run)
	}
	return record, nil
}

func (s *Store) writeProject(bucket *bolt.Bucket, identity string, project model.Project) error {
	var old projectRecord
	if bucket.Get([]byte("metadata")) != nil {
		if err := s.readRecord(bucket, []byte("metadata"), identity+"/metadata", &old); err != nil {
			return err
		}
	}
	revision, err := nextRecordRevision(bucket.Tx())
	if err != nil {
		return err
	}
	findings, err := bucket.CreateBucketIfNotExists([]byte("findings"))
	if err != nil {
		return err
	}
	runs, err := bucket.CreateBucketIfNotExists([]byte("runs"))
	if err != nil {
		return err
	}
	record := projectRecord{Project: project, Findings: len(project.Findings), FindingsNil: project.Findings == nil, RunsNil: project.Runs == nil,
		MetadataRevision: old.MetadataRevision, FindingsRevision: old.FindingsRevision, WorkflowRevision: old.WorkflowRevision}
	record.Project.Findings, record.Project.Runs = nil, nil
	dirtyFindings, err := writeChunks(s, findings, identity+"/findings", project.Findings, findingChunkSize)
	if err != nil {
		return err
	}
	if dirtyFindings || old.Findings != record.Findings || old.FindingsNil != record.FindingsNil || old.FindingsRevision == 0 {
		record.FindingsRevision = revision
	}
	dirtyRuns := old.RunsNil != record.RunsNil
	for index, run := range project.Runs {
		record.Runs = append(record.Runs, run.ID)
		bucket, err := runs.CreateBucketIfNotExists(uintBytes(uint64(index)))
		if err != nil {
			return err
		}
		runRevision, dirty, err := s.writeRun(bucket, fmt.Sprintf("%s/runs/%d", identity, index), run)
		if err != nil {
			return err
		}
		record.RunRevisions = append(record.RunRevisions, runRevision)
		dirtyRuns = dirtyRuns || dirty
	}
	if err := pruneRecords(runs, uintBytes(uint64(len(project.Runs))), true); err != nil {
		return err
	}
	if dirtyRuns || !slices.Equal(old.Runs, record.Runs) || old.WorkflowRevision == 0 {
		record.WorkflowRevision = revision
	}
	equal, err := sameRecordValue(old.Project, record.Project)
	if err != nil {
		return err
	}
	if !equal || old.MetadataRevision == 0 {
		record.MetadataRevision = revision
	}
	return s.writeRecord(bucket, []byte("metadata"), identity+"/metadata", record)
}

func (s *Store) readRecords(tx *bolt.Tx) (model.State, error) {
	state := model.Defaults()
	root := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))
	manifest, err := s.readManifest(root)
	if err != nil {
		return state, err
	}
	if err := s.readRecord(root, []byte("settings"), "settings", &state.Settings); err != nil {
		return state, err
	}
	projects := root.Bucket([]byte("projects"))
	if projects == nil {
		return state, errInvalidRecords
	}
	state.Projects = nil
	if manifest.Projects != nil {
		state.Projects = make([]model.Project, 0, len(manifest.Projects))
	}
	for _, id := range manifest.Projects {
		key := s.projectKey(id)
		record, err := s.readProject(projects.Bucket(key), fmt.Sprintf("projects/%x", key), id, true)
		if err != nil {
			return state, err
		}
		state.Projects = append(state.Projects, record.Project)
	}
	return state, nil
}

func (s *Store) writeRecords(tx *bolt.Tx, state model.State) error {
	root := tx.Bucket([]byte("state")).Bucket([]byte(recordsBucket))
	projects, err := root.CreateBucketIfNotExists([]byte("projects"))
	if err != nil {
		return err
	}
	var previous recordManifest
	if root.Get([]byte("manifest")) != nil {
		previous, err = s.readManifest(root)
		if err != nil {
			return err
		}
	}
	revision, err := nextRecordRevision(tx)
	if err != nil {
		return err
	}
	manifest := recordManifest{Schema: recordsSchema, RevisionsReady: true, SettingsRevision: previous.SettingsRevision, ProjectOrderRevision: previous.ProjectOrderRevision}
	if state.Projects != nil {
		manifest.Projects = make([]string, 0, len(state.Projects))
	}
	retained := make(map[string]bool, len(state.Projects))
	for _, project := range state.Projects {
		// JSON replaces invalid UTF-8. Reject IDs that would no longer address
		// the same HMAC bucket after the manifest is decoded on reopening.
		if !utf8.ValidString(project.ID) {
			return errInvalidRecords
		}
		key := s.projectKey(project.ID)
		if retained[string(key)] {
			return errInvalidRecords
		}
		retained[string(key)] = true
		manifest.Projects = append(manifest.Projects, project.ID)
		bucket, err := projects.CreateBucketIfNotExists(key)
		if err != nil {
			return err
		}
		if err := s.writeProject(bucket, fmt.Sprintf("projects/%x", key), project); err != nil {
			return err
		}
	}
	var removed [][]byte
	if err := projects.ForEach(func(key, value []byte) error {
		if value != nil {
			return errInvalidRecords
		}
		if !retained[string(key)] {
			removed = append(removed, slices.Clone(key))
		}
		return nil
	}); err != nil {
		return err
	}
	for _, key := range removed {
		if err := projects.DeleteBucket(key); err != nil {
			return err
		}
	}
	dirtySettings, err := s.writeRecordChanged(root, []byte("settings"), "settings", state.Settings)
	if err != nil {
		return err
	}
	if dirtySettings || previous.SettingsRevision == 0 {
		manifest.SettingsRevision = revision
	}
	if !slices.Equal(previous.Projects, manifest.Projects) || (previous.Projects == nil) != (manifest.Projects == nil) || previous.ProjectOrderRevision == 0 {
		manifest.ProjectOrderRevision = revision
	}
	return s.writeRecord(root, []byte("manifest"), "manifest", manifest)
}
