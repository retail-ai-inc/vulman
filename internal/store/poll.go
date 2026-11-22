package store

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"vulman/internal/model"

	bolt "go.etcd.io/bbolt"
)

type changedRun struct {
	Index int       `json:"index"`
	Run   model.Run `json:"run"`
}

type WorkflowDelta struct {
	Order   []string     `json:"order"`
	Updated []changedRun `json:"updated"`
}

type ProjectDelta struct {
	ID        string           `json:"id"`
	Metadata  *model.Project   `json:"metadata,omitempty"`
	Findings  *[]model.Finding `json:"findings,omitempty"`
	Workflows *WorkflowDelta   `json:"workflows,omitempty"`
}

type WorkspaceDelta struct {
	Settings     *model.Settings `json:"settings,omitempty"`
	ProjectOrder *[]string       `json:"project_order,omitempty"`
	Projects     []ProjectDelta  `json:"projects,omitempty"`
}

// View supplies desktop-derived labels and credential status. Incremental
// responses use a metadata-only view; full responses share Full. This internal
// field is never serialized separately across the bridge.
type ChangeSet struct {
	Full        *model.State
	View        *model.State `json:"-"`
	Delta       *WorkspaceDelta
	Version     string
	BaseVersion string
}

type projectCursor struct {
	ID       string `json:"i"`
	Metadata uint64 `json:"m"`
	Findings uint64 `json:"f"`
	Workflow uint64 `json:"w"`
}

type pollCursor struct {
	Sequence uint64          `json:"v"`
	Settings uint64          `json:"s"`
	Order    uint64          `json:"o"`
	Projects []projectCursor `json:"p"`
}

func (s *Store) cursorMAC(data []byte) []byte {
	mac := hmac.New(sha256.New, s.indexKey[:])
	_, _ = mac.Write([]byte("vulman-poll-signing-key-v1"))
	signature := hmac.New(sha256.New, mac.Sum(nil))
	_, _ = signature.Write(data)
	return signature.Sum(nil)
}

func (s *Store) encodeCursor(cursor pollCursor) (string, error) {
	data, err := json.Marshal(cursor)
	if err != nil {
		return "", err
	}
	return "p1." + base64.RawURLEncoding.EncodeToString(data) + "." + base64.RawURLEncoding.EncodeToString(s.cursorMAC(data)), nil
}

func (s *Store) decodeCursor(token string) (pollCursor, bool) {
	var cursor pollCursor
	if len(token) > 1<<20 {
		return cursor, false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != "p1" {
		return cursor, false
	}
	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return cursor, false
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(signature, s.cursorMAC(data)) {
		return cursor, false
	}
	if json.Unmarshal(data, &cursor) != nil {
		return cursor, false
	}
	return cursor, true
}

// ReadChanges reads revisions and requested records in one bbolt snapshot. A
// workflow-only update never decrypts settings, findings, or unchanged runs.
// Malformed, foreign, legacy, or future cursors receive a complete snapshot.
func (s *Store) ReadChanges(since string) (changes ChangeSet, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		state := tx.Bucket([]byte("state"))
		sequence := state.Sequence()
		previous, valid := s.decodeCursor(since)
		if valid && previous.Sequence == sequence {
			changes.Version = since
			return nil
		}
		root := state.Bucket([]byte(recordsBucket))
		manifest, err := s.readManifest(root)
		if err != nil {
			return err
		}
		if !manifest.RevisionsReady || manifest.SettingsRevision == 0 || manifest.ProjectOrderRevision == 0 ||
			manifest.SettingsRevision > sequence || manifest.ProjectOrderRevision > sequence {
			return errInvalidRecords
		}
		if previous.Sequence > sequence || previous.Settings > manifest.SettingsRevision || previous.Order > manifest.ProjectOrderRevision {
			valid = false
		}
		old := make(map[string]projectCursor, len(previous.Projects))
		for _, project := range previous.Projects {
			old[project.ID] = project
		}
		projects := root.Bucket([]byte("projects"))
		if projects == nil {
			return errInvalidRecords
		}
		current := pollCursor{Sequence: sequence, Settings: manifest.SettingsRevision, Order: manifest.ProjectOrderRevision}
		headers := make([]projectRecord, 0, len(manifest.Projects))
		for _, id := range manifest.Projects {
			key := s.projectKey(id)
			record, err := s.readProject(projects.Bucket(key), fmt.Sprintf("projects/%x", key), id, false)
			if err != nil {
				return err
			}
			if record.MetadataRevision == 0 || record.FindingsRevision == 0 || record.WorkflowRevision == 0 ||
				record.MetadataRevision > sequence || record.FindingsRevision > sequence || record.WorkflowRevision > sequence || len(record.RunRevisions) != len(record.Runs) {
				return errInvalidRecords
			}
			for _, revision := range record.RunRevisions {
				if revision == 0 || revision > record.WorkflowRevision {
					return errInvalidRecords
				}
			}
			prior, exists := old[id]
			if exists && (prior.Metadata > record.MetadataRevision || prior.Findings > record.FindingsRevision || prior.Workflow > record.WorkflowRevision) {
				valid = false
			}
			current.Projects = append(current.Projects, projectCursor{ID: id, Metadata: record.MetadataRevision, Findings: record.FindingsRevision, Workflow: record.WorkflowRevision})
			headers = append(headers, record)
		}
		changes.Version, err = s.encodeCursor(current)
		if err != nil {
			return err
		}
		if !valid {
			full, err := s.readRecords(tx)
			if err != nil {
				return err
			}
			changes.Full, changes.View = &full, &full
			return nil
		}
		changes.BaseVersion = since
		delta := &WorkspaceDelta{}
		changes.Delta = delta
		metadataChanged := previous.Settings != current.Settings || previous.Order != current.Order
		if previous.Order != current.Order {
			order := slices.Clone(manifest.Projects)
			delta.ProjectOrder = &order
		}
		for index, revision := range current.Projects {
			record := headers[index]
			prior, exists := old[revision.ID]
			if exists && prior == revision {
				continue
			}
			patch := ProjectDelta{ID: revision.ID}
			key := s.projectKey(revision.ID)
			bucket := projects.Bucket(key)
			identity := fmt.Sprintf("projects/%x", key)
			if !exists || prior.Metadata != revision.Metadata {
				project := record.Project
				patch.Metadata = &project
				metadataChanged = true
			}
			if !exists || prior.Findings != revision.Findings {
				findings, err := readChunks[model.Finding](s, bucket.Bucket([]byte("findings")), identity+"/findings", record.Findings, findingChunkSize, record.FindingsNil)
				if err != nil {
					return err
				}
				patch.Findings = &findings
			}
			if !exists || prior.Workflow != revision.Workflow {
				workflow := &WorkflowDelta{}
				if !record.RunsNil {
					workflow.Order = append([]string{}, record.Runs...)
				}
				runs := bucket.Bucket([]byte("runs"))
				if runs == nil {
					return errInvalidRecords
				}
				for slot, id := range record.Runs {
					if exists && record.RunRevisions[slot] <= prior.Workflow {
						continue
					}
					run, err := s.readRun(runs.Bucket(uintBytes(uint64(slot))), fmt.Sprintf("%s/runs/%d", identity, slot), id)
					if err != nil {
						return err
					}
					workflow.Updated = append(workflow.Updated, changedRun{Index: slot, Run: run})
				}
				patch.Workflows = workflow
			}
			delta.Projects = append(delta.Projects, patch)
		}
		if metadataChanged {
			view := model.Defaults()
			if err := s.readRecord(root, []byte("settings"), "settings", &view.Settings); err != nil {
				return err
			}
			for _, record := range headers {
				view.Projects = append(view.Projects, record.Project)
			}
			changes.View = &view
			if previous.Settings != current.Settings {
				delta.Settings = &view.Settings
			}
		}
		return nil
	})
	return changes, err
}
