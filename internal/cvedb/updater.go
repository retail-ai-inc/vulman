package cvedb

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

const (
	releasesURL             = "https://api.github.com/repos/CVEProject/cvelistV5/releases"
	maxArchiveBytes  int64  = 2 << 30
	maxExpandedBytes uint64 = 16 << 30
	downloadFile            = ".vulman-cve-download.zip"
	innerFile               = ".vulman-cve-inner.zip"
)

type release struct {
	Tag        string `json:"tag_name"`
	Draft      bool   `json:"draft"`
	Prerelease bool   `json:"prerelease"`
	Assets     []struct {
		Name   string `json:"name"`
		URL    string `json:"browser_download_url"`
		Size   int64  `json:"size"`
		Digest string `json:"digest"`
	} `json:"assets"`
}

func (r release) at() (time.Time, error) {
	return time.Parse("cve_2006-01-02_1504Z", r.Tag)
}

func (r release) archive(base bool) (Archive, error) {
	at, err := r.at()
	if err != nil || r.Draft || r.Prerelease {
		return Archive{}, errors.New("invalid CVE release")
	}
	marker := "_delta_CVEs_at_"
	if base {
		marker = "_all_CVEs_at_midnight.zip"
		at = at.Truncate(24 * time.Hour)
	}
	for _, asset := range r.Assets {
		if !strings.Contains(asset.Name, marker) || !strings.HasSuffix(asset.Name, ".zip") {
			continue
		}
		u, err := url.Parse(asset.URL)
		if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/CVEProject/cvelistV5/releases/download/") {
			return Archive{}, errors.New("unexpected CVE archive URL")
		}
		digest, err := hex.DecodeString(strings.TrimPrefix(asset.Digest, "sha256:"))
		if !strings.HasPrefix(asset.Digest, "sha256:") || err != nil || len(digest) != sha256.Size || asset.Size <= 0 || asset.Size > maxArchiveBytes {
			return Archive{}, errors.New("CVE archive has invalid size or SHA-256 digest")
		}
		return Archive{Name: asset.Name, URL: asset.URL, Digest: asset.Digest, Size: asset.Size, At: at, Base: base}, nil
	}
	return Archive{}, errors.New("CVE release archive is unavailable")
}

// Updater runs independently of project assessments. Its context is owned by
// the engine so closing or switching a workspace cancels and joins its work.
type Updater struct {
	store             *Store
	HTTP              *http.Client
	apiURL            string
	mu                sync.Mutex
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	closed            bool
	phase             string
	downloaded, total int64
	importTotal       int
	lastError         string
}

func NewUpdater(s *Store) *Updater {
	return &Updater{store: s, apiURL: releasesURL, HTTP: &http.Client{
		Timeout: 20 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil {
				return errors.New("unsafe CVE download redirect")
			}
			host := req.URL.Hostname()
			if host != "github.com" && host != "api.github.com" && host != "release-assets.githubusercontent.com" && host != "objects.githubusercontent.com" {
				return errors.New("unexpected CVE download host")
			}
			return nil
		},
	}}
}

func (u *Updater) progress(phase string, downloaded, total int64) {
	u.mu.Lock()
	u.phase, u.downloaded, u.total = phase, downloaded, total
	if phase != "importing" {
		u.importTotal = 0
	}

	u.mu.Unlock()
}

func (u *Updater) importProgress(total int) {
	u.mu.Lock()
	u.importTotal = total
	u.mu.Unlock()
}

func (u *Updater) Stats() (Stats, error) {
	s, err := u.store.Stats()
	u.mu.Lock()
	s.Running, s.Phase = u.cancel != nil, u.phase
	s.Downloaded, s.DownloadTotal, s.Error = u.downloaded, u.total, u.lastError
	s.ImportTotal = u.importTotal
	u.mu.Unlock()
	if !s.Running && s.Resumable && s.Error == "" {
		s.Phase = "interrupted"
	}
	return s, err
}

func (u *Updater) Start(parent context.Context) error {
	return u.start(parent, false)
}

func (u *Updater) Rebuild(parent context.Context) error {
	return u.start(parent, true)
}

func (u *Updater) start(parent context.Context, rebuild bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return errors.New("CVE database is closing")
	}
	if u.cancel != nil {
		return errors.New("CVE database update is already running")
	}
	ctx, cancel := context.WithCancel(parent)
	u.cancel, u.phase, u.lastError = cancel, "checking", ""
	u.downloaded, u.total = 0, 0
	u.importTotal = 0
	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		defer cancel()
		err := u.sync(ctx, rebuild)
		u.mu.Lock()
		defer u.mu.Unlock()
		u.cancel = nil
		u.phase = "complete"
		if errors.Is(err, context.Canceled) {
			u.phase = "interrupted"
		} else if err != nil {
			u.phase, u.lastError = "failed", err.Error()
		}
	}()
	return nil
}

func (u *Updater) Stop() {
	u.mu.Lock()
	if u.cancel != nil {
		u.cancel()
	}
	u.mu.Unlock()
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

// HTTP retries are bounded and honor provider cooldowns. A long cooldown leaves
// the durable checkpoint intact for the next manual or scheduled attempt.
func (u *Updater) get(ctx context.Context, endpoint string, consume func(*http.Response) error) error {
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return err
		}
		req.Header.Set("User-Agent", "Vulman-CVE-Sync/1.0")
		resp, err := u.HTTP.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusOK {
			err = consume(resp)
			return errors.Join(err, resp.Body.Close())
		}
		status := resp.StatusCode
		delay := time.Duration(1<<attempt) * time.Second
		if seconds, parseErr := strconv.Atoi(resp.Header.Get("Retry-After")); parseErr == nil && seconds > 0 {
			if seconds > 30 {
				_ = resp.Body.Close()
				return errors.New("CVE download rate limited; retry later")
			}
			delay = time.Duration(seconds) * time.Second
		} else if until, parseErr := http.ParseTime(resp.Header.Get("Retry-After")); parseErr == nil && time.Until(until) > delay {
			delay = time.Until(until)
		}
		if err := resp.Body.Close(); err != nil {
			return err
		}
		if delay > 30*time.Second || attempt == 2 || (status != 429 && status != 502 && status != 503 && status != 504) {
			return fmt.Errorf("CVE download returned HTTP %d; retry later", status)
		}
		u.progress("waiting", 0, 0)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("CVE download failed")
}

func (u *Updater) readJSON(ctx context.Context, endpoint string, out any) error {
	return u.get(ctx, endpoint, func(resp *http.Response) error {
		data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<20)+1))
		if err != nil {
			return err
		}
		if len(data) > 16<<20 {
			return errors.New("CVE release metadata exceeds size limit")
		}
		return json.Unmarshal(data, out)
	})
}

// plan requires a continuous sequence of hourly releases. Missing history
// causes a fresh baseline import, preventing a false claim of full coverage.
func (u *Updater) plan(ctx context.Context, latest release, since time.Time) ([]Archive, error) {
	latestAt, err := latest.at()
	if err != nil {
		return nil, err
	}
	if !latestAt.After(since) {
		return nil, nil
	}
	base := since.IsZero() || latestAt.Sub(since) > 7*24*time.Hour
	if base {
		since = latestAt.Truncate(24 * time.Hour)
	}
	var history []release
	for page := 1; page <= 3; page++ {
		var items []release
		if err := u.readJSON(ctx, fmt.Sprintf("%s?per_page=100&page=%d", u.apiURL, page), &items); err != nil {
			return nil, err
		}
		history = append(history, items...)
		if len(items) < 100 {
			break
		}
		lastAt, err := items[len(items)-1].at()
		if err == nil && !lastAt.After(since) {
			break
		}
	}
	// Include the release selected before pagination if a new release appeared.
	history = append(history, latest)
	slices.SortFunc(history, func(a, b release) int {
		x, _ := a.at()
		y, _ := b.at()
		return x.Compare(y)
	})
	build := func(start time.Time) ([]Archive, bool) {
		var archives []Archive
		at := start
		for _, r := range history {
			t, err := r.at()
			if err != nil || !t.After(at) || t.After(latestAt) {
				continue
			}
			if t.Sub(at) != time.Hour {
				return nil, false
			}
			a, err := r.archive(false)
			if err != nil {
				return nil, false
			}
			archives = append(archives, a)
			at = t
		}
		return archives, at.Equal(latestAt)
	}
	archives, complete := build(since)
	if !complete && !base {
		base = true
		since = latestAt.Truncate(24 * time.Hour)
		archives, complete = build(since)
	}
	if !complete {
		return nil, errors.New("CVE release history has a gap; retry when complete archives are available")
	}
	if base {
		a, err := latest.archive(true)
		if err != nil {
			return nil, err
		}
		archives = append([]Archive{a}, archives...)
	}
	return archives, nil
}

func (u *Updater) sync(ctx context.Context, rebuild bool) error {
	// A killed process can leave the temporary inner ZIP open. It is derived
	// from the verified outer download and can always be recreated on resume.
	if err := u.store.root.Remove(innerFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if rebuild {
		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error {
			m.Pending = nil
			return nil
		}); err != nil {
			return err
		}
	}
	if p := u.store.snapshot().Pending; p != nil {
		if err := u.importArchive(ctx, p.Archive); err != nil {
			return err
		}
	}
	var latest release
	if err := u.readJSON(ctx, u.apiURL+"/latest", &latest); err != nil {
		return err
	}
	m := u.store.snapshot()
	since := m.SourceAt
	if !m.Initialized || rebuild {
		since = time.Time{}
	}
	archives, err := u.plan(ctx, latest, since)
	if err != nil {
		return err
	}
	for _, a := range archives {
		if err := u.importArchive(ctx, a); err != nil {
			return err
		}
	}
	// A successful check is recorded even if the latest release was already used.
	return u.store.update(func(_ *bolt.Tx, m *metadata) error {
		m.CheckedAt = time.Now().UTC()
		return nil
	})
}

func (u *Updater) validDownload(ctx context.Context, a Archive) bool {
	f, err := u.store.root.Open(downloadFile)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || info.Size() != a.Size {
		return false
	}
	hash := sha256.New()
	_, err = io.Copy(hash, &contextReader{ctx: ctx, reader: f})
	return err == nil && "sha256:"+hex.EncodeToString(hash.Sum(nil)) == a.Digest
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
	read   int64
	report func(int64)
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	r.read += int64(n)
	if r.report != nil {
		r.report(r.read)
	}
	return n, err
}

func (u *Updater) download(ctx context.Context, a Archive) error {
	u.progress("downloading", 0, a.Size)
	if u.validDownload(ctx, a) {
		return nil
	}
	return u.get(ctx, a.URL, func(resp *http.Response) error {
		f, err := u.store.root.OpenFile(downloadFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		hash := sha256.New()
		r := &contextReader{ctx: ctx, reader: resp.Body, report: func(n int64) { u.progress("downloading", n, a.Size) }}
		n, copyErr := io.Copy(io.MultiWriter(f, hash), io.LimitReader(r, a.Size+1))
		if copyErr == nil && (n != a.Size || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != a.Digest) {
			copyErr = errors.New("CVE archive size or SHA-256 verification failed")
		}
		if copyErr == nil {
			copyErr = f.Sync()
		}
		return errors.Join(copyErr, f.Close())
	})
}

// openZIP supports the official baseline's nested .zip.zip packaging. Members
// are never extracted by name, so archive paths cannot escape the workspace.
func (u *Updater) openZIP(ctx context.Context) (*zip.Reader, func(), error) {
	f, err := u.store.root.Open(downloadFile)
	if err != nil {
		return nil, nil, err
	}
	closeOuter := func() { _ = f.Close() }
	info, err := f.Stat()
	if err != nil {
		closeOuter()
		return nil, nil, err
	}
	z, err := zip.NewReader(f, info.Size())
	if err != nil {
		closeOuter()
		return nil, nil, err
	}
	for _, member := range z.File {
		if strings.HasSuffix(member.Name, ".json") {
			return z, closeOuter, nil
		}
	}
	if len(z.File) != 1 || !strings.HasSuffix(z.File[0].Name, ".zip") || z.File[0].UncompressedSize64 > uint64(maxArchiveBytes) {
		closeOuter()
		return nil, nil, errors.New("Unsupported CVE archive layout") // nolint:staticcheck
	}
	r, err := z.File[0].Open()
	if err != nil {
		closeOuter()
		return nil, nil, err
	}
	inner, err := u.store.root.OpenFile(innerFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0600)
	if err != nil {
		_ = r.Close()
		closeOuter()
		return nil, nil, err
	}
	n, copyErr := io.Copy(inner, io.LimitReader(&contextReader{ctx: ctx, reader: r}, maxArchiveBytes+1))
	err = errors.Join(copyErr, r.Close())
	closeOuter()
	closeInner := func() { _ = inner.Close(); _ = u.store.root.Remove(innerFile) }
	if err == nil && n > maxArchiveBytes {
		err = errors.New("nested CVE archive exceeds size limit")
	}
	if err == nil {
		z, err = zip.NewReader(inner, n)
	}
	if err != nil {
		closeInner()
		return nil, nil, err
	}
	return z, closeInner, nil
}

func (u *Updater) importArchive(ctx context.Context, a Archive) error {
	if err := u.store.begin(ctx, a); err != nil {
		return err
	}
	if err := u.download(ctx, a); err != nil {
		return err
	}
	u.progress("importing", a.Size, a.Size)
	z, closeZIP, err := u.openZIP(ctx)
	if err != nil {
		return err
	}
	defer closeZIP()
	var expanded uint64
	for _, f := range z.File {
		if f.UncompressedSize64 > maxExpandedBytes-expanded {
			return errors.New("expanded CVE archive exceeds size limit")
		}
		expanded += f.UncompressedSize64
	}
	pending := u.store.snapshot().Pending
	if pending.Next > len(z.File) {
		return errors.New("CVE archive does not match saved import checkpoint")
	}

	// The durable checkpoint counts ZIP entries, including non-record members.
	u.importProgress(len(z.File))
	batch := make([]Record, 0, batchSize)
	var batchBytes uint64
	for i := pending.Next; i < len(z.File); i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		f := z.File[i]
		id := strings.TrimSuffix(path.Base(f.Name), ".json")
		if validID.MatchString(id) && strings.HasSuffix(f.Name, ".json") {
			r, err := readRecord(f)
			if err != nil {
				return fmt.Errorf("%s: %w", id, err)
			}
			if r.ID != id {
				return errors.New("CVE archive record identity mismatch")
			}
			batch = append(batch, r)
			batchBytes += f.UncompressedSize64
		}
		if len(batch) == batchSize || batchBytes >= 4<<20 || i == len(z.File)-1 {
			if err := u.store.commitBatch(ctx, batch, i+1); err != nil {
				return err
			}
			clear(batch)
			batch = batch[:0]
			batchBytes = 0
		}
	}
	if err := u.store.finish(ctx); err != nil {
		return err
	}

	u.progress("cleaning", 0, 0)
	// The import is already durable. A leftover download is harmless and reused
	// or overwritten on the next update if cleanup is interrupted.
	_ = u.store.root.Remove(downloadFile)
	if a.Base {
		inactive := "base-a"
		if u.store.snapshot().Active == inactive {
			inactive = "base-b"
		}
		// Reclaim old generations in short transactions after the atomic switch.
		// bbolt reuses these pages for later updates and rebuilds.
		if err := u.store.clearBucket(ctx, inactive); err != nil {
			return err
		}
	}
	return nil
}

func readRecord(f *zip.File) (Record, error) {
	if f.UncompressedSize64 > 8<<20 {
		return Record{}, errors.New("CVE record exceeds size limit")
	}
	r, err := f.Open()
	if err != nil {
		return Record{}, err
	}
	data, readErr := io.ReadAll(io.LimitReader(r, (8<<20)+1))
	if err := errors.Join(readErr, r.Close()); err != nil {
		return Record{}, err
	}
	if len(data) > 8<<20 {
		return Record{}, errors.New("CVE record exceeds size limit")
	}
	return Parse(data)
}
