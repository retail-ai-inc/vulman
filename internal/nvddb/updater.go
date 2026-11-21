package nvddb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"

	"vulman/internal/apperror"
)

type Updater struct {
	store            *Store
	HTTP             *http.Client
	feedBase         string
	mu               sync.Mutex
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	closed           bool
	phase, lastError string
	lastFailure      error

	downloaded, total int64
	importTotal       int
}

func NewUpdater(s *Store) *Updater {
	return &Updater{store: s, feedBase: "https://nvd.nist.gov/feeds/json", HTTP: &http.Client{Timeout: 20 * time.Minute,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 || req.URL.Scheme != "https" || req.URL.User != nil || req.URL.Hostname() != "nvd.nist.gov" {
				return apperror.New("unexpected_nvd_download_redirect", "unexpected NVD download redirect")
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
	s.ErrorMessage = apperror.Public(u.lastFailure)
	s.ImportTotal = u.importTotal
	u.mu.Unlock()
	if !s.Running && s.Resumable && s.Error == "" {
		s.Phase = "interrupted"
	}
	return s, err
}
func (u *Updater) Start(ctx context.Context) error   { return u.start(ctx, false) }
func (u *Updater) Rebuild(ctx context.Context) error { return u.start(ctx, true) }
func (u *Updater) start(parent context.Context, rebuild bool) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return apperror.New("nvd_catalogue_is_closing", "NVD catalogue is closing")
	}
	if u.cancel != nil {
		return apperror.New("nvd_update_is_already_running", "NVD update is already running")
	}
	ctx, cancel := context.WithCancel(parent)
	u.cancel = cancel
	u.phase = "checking"
	u.lastError = ""
	u.lastFailure = nil
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
			u.phase = "failed"
			u.lastError = apperror.Public(err).English()
			u.lastFailure = err
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

func (u *Updater) feeds(full bool) []Feed {
	var feeds []Feed
	if full {
		for year := 2002; year <= time.Now().UTC().Year()+1; year++ {
			base := fmt.Sprintf("%s/cve/2.0/nvdcve-2.0-%d", u.feedBase, year)
			feeds = append(feeds, Feed{Kind: "nvd", ID: fmt.Sprint(year), MetaURL: base + ".meta", URL: base + ".json.gz", Optional: year > time.Now().UTC().Year()})
		}
	}
	base := u.feedBase + "/cve/2.0/nvdcve-2.0-modified"
	feeds = append(feeds, Feed{Kind: "nvd", ID: "modified", MetaURL: base + ".meta", URL: base + ".json.gz"})
	base = u.feedBase + "/cpe/2.0/nvdcpe-2.0"
	return append(feeds, Feed{Kind: "cpe", ID: "dictionary", MetaURL: base + ".meta", URL: base + ".zip"})
}

func (u *Updater) sync(ctx context.Context, rebuild bool) error {
	m := u.store.snapshot()
	if rebuild || m.Job != nil && time.Since(m.Job.StartedAt) > 7*24*time.Hour {
		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error { m.Job = nil; return nil }); err != nil {
			return err
		}
		m = u.store.snapshot()
		rebuild = true
	}
	if m.Job == nil {
		full := rebuild || !m.Ready || time.Since(m.NVDAt) > 7*24*time.Hour
		if err := u.store.begin(ctx, full, u.feeds(full)); err != nil {
			return err
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m = u.store.snapshot()
		j := m.Job
		if j.Feed >= len(j.Feeds) {
			break
		}
		pending := j.Feeds[j.Feed]
		u.progress("checking", 0, 0)
		feed, err := u.metadata(ctx, pending)
		if err != nil {
			var status statusError
			if pending.Optional && errors.As(err, &status) && int(status) == 404 {
				if err := u.store.finishFeed(ctx, pending, false); err != nil {
					return err
				}
				continue
			}
			return apperror.Newf("context", "%s: %w", pending.ID, err)
		}
		if !j.Full && j.Offset == 0 && m.Hashes[feed.ID] == feed.SHA {
			if err := u.store.finishFeed(ctx, feed, false); err != nil {
				return err
			}
			continue
		}
		if pending.SHA != "" && pending.SHA != feed.SHA && j.Offset > 0 {
			// NVD files are mutable. A changed archive restarts this feed while
			// retaining completed years and the previous published catalogue.
			if feed.Kind == "cpe" {
				if err := u.store.clear(ctx, j.CPETarget, "cpe", ""); err != nil {
					return err
				}
			} else if j.Full && feed.ID != "modified" {
				prefix := "CVE-" + feed.ID + "-"
				if feed.ID == "2002" {
					prefix = ""
				}
				if err := u.store.clear(ctx, j.NVDTarget, "nvd", prefix); err != nil {
					return err
				}
			}
			j.Offset = 0
		}
		if err := u.store.update(func(_ *bolt.Tx, m *metadata) error {
			m.Job.Feeds[m.Job.Feed] = feed
			m.Job.Offset = j.Offset
			return nil
		}); err != nil {
			return err
		}
		if err := u.download(ctx, feed); err != nil {
			return apperror.Newf("context", "%s: %w", feed.ID, err)
		}
		u.progress("importing", feed.Compressed, feed.Compressed)
		if err := u.importFeed(ctx, feed); err != nil {
			return apperror.Newf("context", "%s: %w", feed.ID, err)
		}
		if err := u.store.finishFeed(ctx, feed, true); err != nil {
			return err
		}
		_ = u.store.root.Remove(downloadFile)
	}
	if err := u.store.publish(ctx); err != nil {
		return err
	}
	// Old generations are reclaimed only after the atomic publication.
	m = u.store.snapshot()
	u.progress("cleaning", 0, 0)
	if err := u.store.clear(ctx, other(m.NVD), "nvd", ""); err != nil {
		return err
	}
	return u.store.clear(ctx, other(m.CPE), "cpe", "")
}

func (u *Updater) importFeed(ctx context.Context, feed Feed) error {
	j := u.store.snapshot().Job
	offset := j.Offset
	processed := 0
	limit := batchLimit(feed.Kind)
	batch := make([]json.RawMessage, 0, limit)
	bytes := 0
	total := -1
	flush := func() error {
		if err := u.store.batch(ctx, batch, processed); err != nil {
			return err
		}
		clear(batch)
		batch = batch[:0]
		bytes = 0
		return nil
	}
	err := u.streams(ctx, feed, func(reader io.Reader) error {
		key := "vulnerabilities"
		if feed.Kind == "cpe" {
			key = "products"
		}
		var info arrayInfo
		reportedTotal := false
		err := readArray(reader, key, &info, func(raw json.RawMessage) error {
			if err := ctx.Err(); err != nil {
				return err
			}

			if !reportedTotal && info.Total != nil {
				u.importProgress(*info.Total)
				reportedTotal = true
			}

			processed++
			if processed <= offset {
				return nil
			}
			var item map[string]json.RawMessage
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			field := "cve"
			if feed.Kind == "cpe" {
				field = "cpe"
			}
			value := item[field]
			if len(value) == 0 {
				return apperror.New("nvd_feed_record_has_no_payload", "NVD feed record has no payload")
			}
			batch = append(batch, value)
			bytes += len(value)
			if len(batch) == limit || bytes >= 4<<20 {
				return flush()
			}
			return nil
		})
		if err != nil {
			return err
		}
		if total >= 0 && total != *info.Total {
			return apperror.New("cpe_dictionary_chunks_disagree_on_their_total_count", "CPE dictionary chunks disagree on their total count")
		}
		total = *info.Total
		u.importProgress(total)
		return nil
	})
	if err != nil {
		return err
	}
	if processed < offset {
		return apperror.New("nvd_stream_does_not_match_its_saved_checkpoint", "NVD stream does not match its saved checkpoint")
	}
	if processed != total {
		return apperror.New("nvd_feed_is_missing_records_or_dictionary_chunks", "NVD feed is missing records or dictionary chunks")
	}
	if processed == 0 && !strings.EqualFold(feed.ID, "modified") {
		return apperror.New("empty_nvd_source_feed", "empty NVD source feed")
	}
	return flush()
}
