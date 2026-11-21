package osvdb

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"vulman/internal/apperror"
)

type EcosystemStats struct {
	Ecosystem    string            `json:"ecosystem"`
	Records      uint64            `json:"records"`
	Initialized  bool              `json:"initialized"`
	CheckedAt    time.Time         `json:"checked_at"`
	SourceAt     time.Time         `json:"source_at"`
	Running      bool              `json:"running"`
	Phase        string            `json:"phase"`
	ErrorMessage *apperror.Message `json:"error_message,omitempty"`
	Error        string            `json:"error,omitempty"`
}

type Stats struct {
	Path          string            `json:"path"`
	Bytes         int64             `json:"bytes"`
	Records       uint64            `json:"records"`
	Initialized   bool              `json:"initialized"`
	Resumable     bool              `json:"resumable"`
	Running       bool              `json:"running"`
	Phase         string            `json:"phase"`
	ErrorMessage  *apperror.Message `json:"error_message,omitempty"`
	Error         string            `json:"error,omitempty"`
	Feed          string            `json:"feed,omitempty"`
	FeedsDone     int               `json:"feeds_done"`
	FeedsTotal    int               `json:"feeds_total"`
	Imported      int               `json:"imported"`
	ImportTotal   int               `json:"import_total"`
	Downloaded    int64             `json:"downloaded"`
	DownloadTotal int64             `json:"download_total"`
	Ecosystems    []EcosystemStats  `json:"ecosystems"`
}

type Updater struct {
	store            *Store
	HTTP             *http.Client
	baseURL          string
	mu               sync.Mutex
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	closed           bool
	stage, lastError string
	lastFailure      error

	downloaded, total int64
	importTotal       int
	wanted            []string
}

func NewUpdater(s *Store) *Updater {
	return &Updater{store: s, baseURL: "https://storage.googleapis.com/osv-vulnerabilities", HTTP: &http.Client{Timeout: 20 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.Host != "storage.googleapis.com" || req.URL.User != nil || !strings.HasPrefix(req.URL.Path, "/osv-vulnerabilities/") {
			return apperror.New("unexpected_osv_download_redirect", "unexpected OSV download redirect")
		}

		return nil
	}}}
}

func NormalizeEcosystems(values []string) ([]string, error) {
	if len(values) > 64 {
		return nil, apperror.New("select_at_most_64_osv_ecosystems", "select at most 64 OSV ecosystems")
	}

	var result []string
	for _, value := range values {
		ecosystem, err := Ecosystem(value)
		if err != nil {
			return nil, err
		}

		if !slices.Contains(result, ecosystem) {
			result = append(result, ecosystem)
		}
	}

	sort.Strings(result)
	return result, nil
}

func (u *Updater) phase(phase string, downloaded, total int64, importedTotal int) {
	u.mu.Lock()
	u.stage, u.downloaded, u.total, u.importTotal = phase, downloaded, total, importedTotal
	u.mu.Unlock()
}

func (u *Updater) Stats() (Stats, error) {
	u.mu.Lock()
	stats := Stats{ErrorMessage: apperror.Public(u.lastFailure), Path: u.store.db.Path(), Running: u.cancel != nil, Phase: u.stage, Error: u.lastError, Downloaded: u.downloaded, DownloadTotal: u.total, ImportTotal: u.importTotal, Ecosystems: []EcosystemStats{}}
	wanted := slices.Clone(u.wanted)
	u.mu.Unlock()
	u.store.mu.RLock()

	defer u.store.mu.RUnlock()

	m := cloneMetadata(u.store.meta)

	stats.FeedsDone, stats.FeedsTotal, stats.Resumable = m.Next, len(m.Plan), m.Next < len(m.Plan)
	if stats.Resumable {
		stats.Feed = m.Plan[m.Next]
		if !stats.Running && stats.Error == "" {
			stats.Phase = "interrupted"
		}
	}

	if m.Job != nil {
		stats.Imported = m.Job.Offset
		if !m.Job.Full && m.Job.Planned {
			stats.ImportTotal = m.Job.PendingTotal
		}
	}

	keys := slices.Clone(m.Plan)
	for _, ecosystem := range wanted {
		if !slices.Contains(keys, ecosystem) {
			keys = append(keys, ecosystem)
		}
	}

	for ecosystem := range m.Ecosystems {
		if !slices.Contains(keys, ecosystem) {
			keys = append(keys, ecosystem)
		}
	}

	sort.Strings(keys)
	err := u.store.db.View(func(tx *bolt.Tx) error {
		for _, ecosystem := range keys {
			state := m.Ecosystems[ecosystem]
			entry := EcosystemStats{Ecosystem: ecosystem, Initialized: state.Ready, CheckedAt: state.CheckedAt, SourceAt: state.SourceAt, Phase: "idle"}
			if state.Ready {
				entry.Phase = "complete"
				entry.Records = catalogue(tx, ecosystem, state.Active).Bucket([]byte("records")).Sequence()
				stats.Initialized = true
				stats.Records += entry.Records
			}

			if index := slices.Index(m.Plan, ecosystem); index >= m.Next && index >= 0 {
				entry.Running, entry.Phase = stats.Running, "queued"
				if index == m.Next || !stats.Running {
					entry.Phase, entry.Error = stats.Phase, stats.Error
					entry.ErrorMessage = stats.ErrorMessage
				}
			}

			if stats.Running && (!slices.Equal(wanted, m.Plan) || m.Next >= len(m.Plan)) && slices.Contains(wanted, ecosystem) {
				entry.Running, entry.Phase, entry.Error = true, "queued", ""
			}

			stats.Ecosystems = append(stats.Ecosystems, entry)
		}

		return nil
	})

	if err == nil {
		stats.Bytes, err = u.store.fileSize()
	}

	return stats, err
}

func (u *Updater) Start(ctx context.Context, ecosystems []string) error {
	return u.start(ctx, ecosystems, false)
}

func (u *Updater) Rebuild(ctx context.Context, ecosystems []string) error {
	return u.start(ctx, ecosystems, true)
}

func (u *Updater) start(parent context.Context, ecosystems []string, rebuild bool) error {
	selected, err := NormalizeEcosystems(ecosystems)
	if err != nil || len(selected) == 0 {
		return apperror.New("select_at_least_one_valid_osv_ecosystem_in_configuration", "select at least one valid OSV ecosystem in Configuration")
	}

	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || u.cancel != nil {
		return apperror.New("osv_update_is_already_running_or_the_application_is_closing", "OSV update is already running or the application is closing")
	}

	ctx, cancel := context.WithCancel(parent)
	u.cancel, u.stage, u.lastError = cancel, "checking", ""
	u.lastFailure = nil
	u.downloaded, u.total, u.importTotal = 0, 0, 0
	u.wanted = slices.Clone(selected)
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer cancel()
		err := u.sync(ctx, selected, rebuild)
		u.mu.Lock()
		defer u.mu.Unlock()
		u.cancel, u.stage = nil, "complete"
		if errors.Is(err, context.Canceled) {
			u.stage = "interrupted"
		} else if err != nil {
			u.stage, u.lastError = "failed", apperror.Public(err).English()
			u.lastFailure = err
		}
	}()

	return nil
}

func (u *Updater) Stop() {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cancel != nil {
		u.cancel()
	}
}

func (u *Updater) Close() error {
	u.mu.Lock()
	u.closed = true

	if u.cancel != nil {
		u.cancel()
	}

	u.mu.Unlock()
	u.wg.Wait()
	return u.store.Close()
}

func (u *Updater) sync(ctx context.Context, selected []string, rebuild bool) error {
	m := u.store.snapshot()
	if rebuild || !slices.Equal(m.Plan, selected) || m.Next >= len(m.Plan) {
		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error {
			m.Plan, m.Next, m.Rebuild, m.Job = slices.Clone(selected), 0, rebuild, nil
			m.StartedAt = time.Now().UTC()
			return nil
		}); err != nil {
			return err
		}
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		m = u.store.snapshot()
		if m.Next >= len(m.Plan) {
			return nil
		}

		ecosystem := m.Plan[m.Next]
		if err := u.syncEcosystem(ctx, ecosystem); err != nil {
			return apperror.Newf("osv_ecosystem_error", "OSV %s: %w", ecosystem, err)
		}
	}
}

func (u *Updater) syncEcosystem(ctx context.Context, ecosystem string) error {
	if err := u.store.ensure(ecosystem); err != nil {
		return err
	}

	m := u.store.snapshot()
	state := m.Ecosystems[ecosystem]
	if m.Job != nil && time.Since(m.Job.StartedAt) > 48*time.Hour {
		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error {
			m.Job = nil
			m.Rebuild = true
			m.StartedAt = time.Now().UTC()
			return nil
		}); err != nil {
			return err
		}

		m = u.store.snapshot()
	}

	if m.Job == nil {
		full := !state.Ready || time.Since(state.BaselineAt) >= 7*24*time.Hour || m.Rebuild && state.BaselineAt.Before(m.StartedAt)
		name, limit := ecosystem+"/modified_id.csv", maxIndexSize
		target := state.Active
		if full {
			name, limit, target = ecosystem+"/all.zip", maxArchiveSize, other(state.Active)
		}

		u.phase("checking", 0, 0, 0)
		object, err := u.head(ctx, name, limit)
		if err != nil {
			return err
		}

		if full {
			if err := u.store.clear(ctx, ecosystem, target); err != nil {
				return err
			}
		}

		if err := u.store.clearPending(ctx); err != nil {
			return err
		}

		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error {
			m.Job = &job{Ecosystem: ecosystem, Full: full, Target: target, StartedAt: time.Now().UTC(), Object: object}
			return nil
		}); err != nil {
			return err
		}
	}

	j := u.store.snapshot().Job
	filename := indexFile
	if j.Full {
		filename = archiveFile
	}

	if err := u.download(ctx, j.Object, filename); err != nil {
		// Old object generations are not guaranteed to remain downloadable.
		var status httpError
		if errors.As(err, &status) && (int(status) == 404 || int(status) == 410 || int(status) == 412) {
			if resetErr := u.store.update(func(_ *bolt.Tx, m *metadata) error {
				m.Job = nil
				m.Rebuild = true
				m.StartedAt = time.Now().UTC()
				return nil
			}); resetErr != nil {
				return errors.Join(err, resetErr)
			}
		}

		return err
	}

	if j.Full {
		if err := u.importZIP(ctx); err != nil {
			return err
		}
	} else {
		if !j.Planned {
			if err := u.planChanges(ctx); err != nil {
				return err
			}
		}

		if err := u.applyChanges(ctx); err != nil {
			return err
		}
	}

	// A baseline is immediately followed by a fresh incremental catch-up before
	// the ecosystem is marked finished in the request's queue.
	if err := u.store.finish(ctx, !j.Full); err != nil {
		return err
	}

	_ = u.store.root.Remove(filename)
	if j.Full {
		u.phase("cleaning", 0, 0, 0)
		if err := u.store.clear(ctx, ecosystem, other(j.Target)); err != nil {
			return err
		}

	}

	return nil
}

func (u *Updater) importZIP(ctx context.Context) error {
	j := u.store.snapshot().Job
	f, err := u.store.root.Open(archiveFile)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	z, err := zip.NewReader(f, j.Object.Size)
	if err != nil {
		return err
	}

	var size uint64
	files := make([]*zip.File, 0, len(z.File))
	for _, member := range z.File {
		if member.UncompressedSize64 > uint64(16<<30)-size {
			return apperror.New("expanded_osv_archive_exceeds_size_limit", "expanded OSV archive exceeds size limit")
		}

		size += member.UncompressedSize64
		if strings.HasSuffix(member.Name, ".json") {
			files = append(files, member)
		}
	}

	if len(files) == 0 || j.Offset > len(files) {
		return apperror.New("empty_osv_archive_or_invalid_saved_checkpoint", "empty OSV archive or invalid saved checkpoint")
	}

	if err := u.store.update(func(_ *bolt.Tx, m *metadata) error { m.Job.Total = len(files); return nil }); err != nil {
		return err
	}

	u.phase("importing", j.Object.Size, j.Object.Size, len(files))
	batch := make([]json.RawMessage, 0, batchSize)
	batchBytes := 0
	for index := j.Offset; index < len(files); index++ {
		if err := ctx.Err(); err != nil {
			return err
		}

		member := files[index]
		if member.UncompressedSize64 > uint64(maxRecordSize) {
			return apperror.New("osv_archive_record_exceeds_size_limit", "OSV archive record exceeds size limit")
		}

		reader, err := member.Open()
		if err != nil {
			return err
		}

		data, readErr := io.ReadAll(io.LimitReader(&contextReader{ctx: ctx, reader: reader}, maxRecordSize+1))
		if err := errors.Join(readErr, reader.Close()); err != nil {
			return err
		}

		if int64(len(data)) > maxRecordSize {
			return apperror.New("osv_record_exceeds_size_limit", "OSV record exceeds size limit")
		}

		batch, batchBytes = append(batch, data), batchBytes+len(data)
		if len(batch) >= batchSize || batchBytes >= 4<<20 || index == len(files)-1 {
			if err := u.store.putRows(ctx, batch, index+1, ""); err != nil {
				return err
			}

			clear(batch)
			batch, batchBytes = batch[:0], 0
		}
	}

	return nil
}

func (u *Updater) planChanges(ctx context.Context) error {
	j := u.store.snapshot().Job
	state := u.store.snapshot().Ecosystems[j.Ecosystem]
	cutoff := state.CheckedAt.Add(-48 * time.Hour)
	f, err := u.store.root.Open(indexFile)
	if err != nil {
		return err
	}

	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(&contextReader{ctx: ctx, reader: f})
	scanner.Buffer(make([]byte, 4096), 64<<10)
	rows := []pendingRecord{}
	offset := 0
	u.phase("planning", j.Object.Size, j.Object.Size, 0)
	flush := func(complete bool) error {
		return u.store.update(func(tx *bolt.Tx, m *metadata) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			b := tx.Bucket([]byte("pending"))
			for _, row := range rows {
				if data := b.Get([]byte(row.ID)); data == nil {
					m.Job.PendingTotal++
				} else {
					var previous pendingRecord
					if err := u.store.decode("pending/"+row.ID, data, &previous); err != nil {
						return err
					}

					if previous.At.After(row.At) {
						continue
					}
				}

				data, err := u.store.encode("pending/"+row.ID, row)
				if err != nil {
					return err
				}

				if err := b.Put([]byte(row.ID), data); err != nil {
					return err
				}
			}

			m.Job.PlanOffset, m.Job.Planned = offset, complete
			return nil
		})
	}

	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			return flush(true)
		}

		reader := csv.NewReader(strings.NewReader(scanner.Text()))
		reader.FieldsPerRecord = 2
		fields, err := reader.Read()
		if err != nil {
			return err
		}

		offset++
		if offset <= j.PlanOffset {
			continue
		}

		at, err := time.Parse(time.RFC3339Nano, fields[0])
		if err != nil || !recordID.MatchString(fields[1]) {
			return apperror.New("malformed_osv_modification_index", "malformed OSV modification index")
		}

		if !at.Before(cutoff) {
			rows = append(rows, pendingRecord{ID: fields[1], At: at})
		}

		// Scan the complete bounded snapshot instead of relying on ordering for
		// correctness when equal timestamps or delayed exports appear.
		if offset%batchSize == 0 {
			if err := flush(false); err != nil {
				return err
			}

			rows = rows[:0]
		}
	}
}

func (u *Updater) applyChanges(ctx context.Context) error {
	j := u.store.snapshot().Job
	u.phase("importing", 0, 0, j.PendingTotal)
	for {
		pending, found, err := u.store.nextPending()
		if err != nil || !found {
			return err
		}

		if err := wait(ctx, 50*time.Millisecond); err != nil {
			return err
		}

		var raw json.RawMessage
		err = u.request(ctx, http.MethodGet, u.endpoint(j.Ecosystem+"/"+pending.ID+".json"), func(resp *http.Response) error {
			var err error
			raw, err = io.ReadAll(io.LimitReader(resp.Body, maxRecordSize+1))
			if err != nil || int64(len(raw)) > maxRecordSize {
				return apperror.New("osv_record_download_failed_or_exceeds_its_size_limit", "OSV record download failed or exceeds its size limit")
			}

			expected, err := checksum(resp.Header)
			if err != nil {
				return err
			}

			return matchesChecksum(bytes.NewReader(raw), expected)
		})

		if err != nil {
			return err
		}

		var record Record
		if err := json.Unmarshal(raw, &record); err != nil || record.ID != pending.ID || record.Modified.Before(pending.At) {
			return apperror.New("osv_index_out_of_date", "OSV exported record does not yet agree with its change index; retry later")
		}

		u.phase("importing", 0, 0, j.PendingTotal)

		offset := u.store.snapshot().Job.Offset
		if err := u.store.putRows(ctx, []json.RawMessage{raw}, offset+1, pending.ID); err != nil {
			return err
		}
	}
}
