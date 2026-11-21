package nvddb

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func envelope(t testing.TB, kind string, rows []json.RawMessage, total int) []byte {
	t.Helper()
	items := make([]map[string]json.RawMessage, 0, len(rows))
	field, key := "cve", "vulnerabilities"
	if kind == "cpe" {
		field, key = "cpe", "products"
	}
	for _, row := range rows {
		items = append(items, map[string]json.RawMessage{field: row})
	}
	data, err := json.Marshal(map[string]any{"resultsPerPage": len(rows), "totalResults": total, key: items})
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func fixture(t testing.TB, kind string, chunks ...[]byte) (Feed, []byte) {
	t.Helper()
	var out bytes.Buffer
	if kind == "nvd" {
		w := gzip.NewWriter(&out)
		for _, data := range chunks {
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
	} else {
		z := zip.NewWriter(&out)
		for i, data := range chunks {
			w, err := z.Create(fmt.Sprintf("chunks/chunk-%05d.json", i+1))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := w.Write(data); err != nil {
				t.Fatal(err)
			}
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
	}
	hash := sha256.New()
	size := 0
	for _, chunk := range chunks {
		if _, err := hash.Write(chunk); err != nil {
			t.Fatal(err)
		}
		size += len(chunk)
	}
	id := "modified"
	if kind == "cpe" {
		id = "dictionary"
	}
	return Feed{Kind: kind, ID: id, MetaURL: "https://nvd.nist.gov/test/" + id + ".meta", URL: "https://nvd.nist.gov/test/" + id, SHA: hex.EncodeToString(hash.Sum(nil)), Size: int64(size), Compressed: int64(out.Len()), At: time.Now().UTC()}, out.Bytes()
}
func metaText(f Feed) string {
	return fmt.Sprintf("lastModifiedDate:%s\nsize:%d\ngzSize:%d\nzipSize:%d\nsha256:%s\n", f.At.Format(time.RFC3339Nano), f.Size, f.Compressed, f.Compressed, strings.ToUpper(f.SHA))
}

func TestImportVerifiesAllDictionaryChunksAndPublishesBothDatasets(t *testing.T) {
	s := testStore(t)
	u := NewUpdater(s)
	ctx := context.Background()
	nvd, data := fixture(t, "nvd", envelope(t, "nvd", []json.RawMessage{advisory("CVE-2026-0001", "Go test vulnerability", testCPE)}, 1))
	cpe, cpeData := fixture(t, "cpe", envelope(t, "cpe", []json.RawMessage{dictionary("first", testCPE)}, 2), envelope(t, "cpe", []json.RawMessage{dictionary("second", "cpe:2.3:a:golang:go:1.27.0:*:*:*:*:*:*:*")}, 2))
	feeds := []Feed{nvd, cpe}
	if err := s.begin(ctx, true, feeds); err != nil {
		t.Fatal(err)
	}
	requests := 0
	u.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		body := data
		switch r.URL.String() {
		case nvd.MetaURL:
			body = []byte(metaText(nvd))
		case cpe.MetaURL:
			body = []byte(metaText(cpe))
		case cpe.URL:
			body = cpeData
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})
	if err := u.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Stats()
	if err != nil || !stats.Initialized || stats.Records != 1 || stats.CPEs != 2 || stats.Resumable {
		t.Fatalf("partial dictionary or baseline published: %+v %v", stats, err)
	}
	if requests != 4 {
		t.Fatalf("unexpected downloads: %d", requests)
	}
	if err := s.begin(ctx, false, feeds); err != nil {
		t.Fatal(err)
	}
	if err := u.sync(ctx, false); err != nil {
		t.Fatal(err)
	}
	if requests != 6 {
		t.Fatal("unchanged metadata triggered another download")
	}
	result, err := s.Query(ctx, "", testCPE)
	if err != nil || len(result.Records) != 1 || result.Uncertain {
		t.Fatalf("indexed CPE match failed: %+v %v", result, err)
	}
}

func TestCorruptFeedsAndIncompleteEnvelopesNeverPublish(t *testing.T) {
	s := testStore(t)
	u := NewUpdater(s)
	ctx := context.Background()
	nvd, data := fixture(t, "nvd", envelope(t, "nvd", []json.RawMessage{advisory("CVE-2026-0001", "Go", testCPE)}, 1))
	if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	bad := nvd
	bad.SHA = strings.Repeat("0", 64)
	if err := u.verify(ctx, bad); err == nil {
		t.Fatal("bad uncompressed checksum accepted")
	}
	if err := s.begin(ctx, true, []Feed{nvd}); err != nil {
		t.Fatal(err)
	}
	// Valid compression and checksum cannot make a logically incomplete feed
	// complete. No activation or source timestamp may advance on this failure.
	raw := envelope(t, "nvd", []json.RawMessage{advisory("CVE-2026-0001", "Go", testCPE)}, 2)
	broken, compressed := fixture(t, "nvd", raw)
	if err := s.root.WriteFile(downloadFile, compressed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := u.importFeed(ctx, broken); err == nil {
		t.Fatal("incomplete NVD envelope accepted")
	}
	stats, err := s.Stats()
	if err != nil || stats.Initialized || !stats.SourceAt.IsZero() {
		t.Fatalf("failed feed advanced readiness: %+v %v", stats, err)
	}
}

func TestCPEImportResumesAcrossChunksAndRestartsChangedFeeds(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(fmt.Sprint(changed), func(t *testing.T) {
			s := testStore(t)
			u := NewUpdater(s)
			ctx := context.Background()
			var rows []json.RawMessage
			for i := 0; i < 600; i++ {
				rows = append(rows, dictionary(fmt.Sprintf("cpe-%d", i), testCPE))
			}
			feed, data := fixture(t, "cpe", envelope(t, "cpe", rows[:200], 600), envelope(t, "cpe", rows[200:400], 600), envelope(t, "cpe", rows[400:], 600))
			pending := feed
			if changed {
				pending.SHA = strings.Repeat("f", 64)
			}
			feeds := []Feed{{Kind: "nvd", ID: "modified", At: time.Now().UTC()}, pending}
			if err := s.begin(ctx, true, feeds); err != nil {
				t.Fatal(err)
			}
			if err := s.batch(ctx, []json.RawMessage{advisory("CVE-2026-0001", "Go", testCPE)}, 1); err != nil {
				t.Fatal(err)
			}
			if err := s.finishFeed(ctx, feeds[0], true); err != nil {
				t.Fatal(err)
			}
			partial := rows[:256]
			if changed {
				partial = nil
				for i := 0; i < 256; i++ {
					partial = append(partial, dictionary(fmt.Sprintf("obsolete-%d", i), testCPE))
				}
			}
			if err := s.batch(ctx, partial, 256); err != nil {
				t.Fatal(err)
			}
			if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			u.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
				if r.URL.String() != feed.MetaURL {
					return nil, errors.New("verified download was fetched again")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(metaText(feed)))}, nil
			})
			if err := u.sync(ctx, false); err != nil {
				t.Fatal(err)
			}
			stats, err := s.Stats()
			if err != nil || !stats.Initialized || stats.CPEs != 600 {
				t.Fatalf("resume skipped or duplicated dictionary entries: %+v %v", stats, err)
			}
		})
	}
}

func TestDictionaryImportProgressUsesGlobalTotalAndResumedCommittedOffset(t *testing.T) {
	s := testStore(t)
	u := NewUpdater(s)
	ctx := context.Background()
	var rows []json.RawMessage
	for i := 0; i < 600; i++ {
		rows = append(rows, dictionary(fmt.Sprintf("cpe-%d", i), testCPE))
	}

	rows[300] = dictionary("", testCPE)
	feed, data := fixture(t, "cpe", envelope(t, "cpe", rows[:200], 600), envelope(t, "cpe", rows[200:400], 600), envelope(t, "cpe", rows[400:], 600))
	if err := s.begin(ctx, true, []Feed{feed}); err != nil {
		t.Fatal(err)
	}

	if err := s.batch(ctx, rows[:256], 256); err != nil {
		t.Fatal(err)
	}

	if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
		t.Fatal(err)
	}

	u.progress("importing", feed.Compressed, feed.Compressed)
	if err := u.importFeed(ctx, feed); err == nil {
		t.Fatal("invalid dictionary identity was accepted")
	}

	stats, err := u.Stats()
	if err != nil || stats.ImportTotal != 600 || stats.Imported != 256 || stats.Initialized {
		t.Fatalf("progress used a chunk count or advanced past a rolled-back batch: %+v %v", stats, err)
	}
}

func TestStopCancelsNetworkAndPreventsOverlappingNVDUpdates(t *testing.T) {
	s := testStore(t)
	u := NewUpdater(s)
	started := make(chan struct{})
	u.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if err := u.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	<-started
	if err := u.Start(context.Background()); err == nil {
		t.Fatal("overlapping updates accepted")
	}
	u.Stop()
	u.wg.Wait()
	stats, err := u.Stats()
	if err != nil || stats.Running || stats.Phase != "interrupted" {
		t.Fatalf("stop did not finish: %+v %v", stats, err)
	}
}

func TestOfficialNVDAndCPEFixtures(t *testing.T) {
	dir := os.Getenv("VULMAN_NVD_FIXTURES")
	if dir == "" {
		t.Skip("set VULMAN_NVD_FIXTURES to verify independently downloaded official feeds")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	s := testStore(t)
	u := NewUpdater(s)
	ctx := context.Background()
	for _, spec := range []struct{ kind, meta, file string }{{"nvd", "vulman-nvd-2003.meta", "vulman-nvd-2003.json.gz"}, {"cpe", "vulman-cpe.meta", "vulman-cpe.zip"}} {
		meta, err := root.ReadFile(spec.meta)
		if err != nil {
			t.Fatal(err)
		}
		feed, err := parseMeta(meta, Feed{Kind: spec.kind, ID: spec.kind})
		if err != nil {
			t.Fatal(err)
		}
		source, err := root.Open(spec.file)
		if err != nil {
			t.Fatal(err)
		}
		dest, err := s.root.OpenFile(downloadFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			_ = source.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(dest, source)
		if err := errors.Join(copyErr, source.Close(), dest.Close()); err != nil {
			t.Fatal(err)
		}
		if err := u.verify(ctx, feed); err != nil {
			t.Fatal(err)
		}
		processed, total := 0, -1
		err = u.streams(ctx, feed, func(r io.Reader) error {
			key, field := "vulnerabilities", "cve"
			if spec.kind == "cpe" {
				key, field = "products", "cpe"
			}
			var info arrayInfo
			err := readArray(r, key, &info, func(raw json.RawMessage) error {
				var item map[string]json.RawMessage
				if err := json.Unmarshal(raw, &item); err != nil {
					return err
				}
				if _, _, err := indexKeys(spec.kind, item[field]); err != nil {
					return err
				}
				processed++
				return nil
			})
			if err != nil {
				return err
			}
			total = *info.Total
			return nil
		})
		if err != nil || processed != total {
			t.Fatalf("official %s feed incomplete: %d/%d %v", spec.kind, processed, total, err)
		}
		t.Logf("Verified and parsed %d official %s records", processed, spec.kind)
	}
}

func TestOfficialCataloguePersistence(t *testing.T) {
	if os.Getenv("VULMAN_NVD_PERSIST") != "1" {
		t.Skip("set VULMAN_NVD_PERSIST=1 for the full dictionary persistence check")
	}
	root, err := os.OpenRoot(os.Getenv("VULMAN_NVD_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	s := testStore(t)
	u := NewUpdater(s)
	ctx := context.Background()
	nvdMeta, err := root.ReadFile("vulman-nvd-2003.meta")
	if err != nil {
		t.Fatal(err)
	}
	cpeMeta, err := root.ReadFile("vulman-cpe.meta")
	if err != nil {
		t.Fatal(err)
	}
	nvd, err := parseMeta(nvdMeta, Feed{Kind: "nvd", ID: "modified"})
	if err != nil {
		t.Fatal(err)
	}
	cpe, err := parseMeta(cpeMeta, Feed{Kind: "cpe", ID: "dictionary"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.begin(ctx, true, []Feed{nvd, cpe}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	for i, spec := range []struct {
		feed Feed
		file string
	}{{nvd, "vulman-nvd-2003.json.gz"}, {cpe, "vulman-cpe.zip"}} {
		source, err := root.Open(spec.file)
		if err != nil {
			t.Fatal(err)
		}
		dest, err := s.root.OpenFile(downloadFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			_ = source.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(dest, source)
		if err := errors.Join(copyErr, source.Close(), dest.Close()); err != nil {
			t.Fatal(err)
		}
		if err := u.verify(ctx, spec.feed); err != nil {
			t.Fatal(err)
		}
		if err := u.importFeed(ctx, spec.feed); err != nil {
			t.Fatal(err)
		}
		if err := s.finishFeed(ctx, spec.feed, true); err != nil {
			t.Fatal(err)
		}
		t.Logf("Persisted official feed %d after %s", i+1, time.Since(started).Round(time.Millisecond))
	}
	if err := s.publish(ctx); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Stats()
	if err != nil || stats.Records != 1555 || stats.CPEs != 1879483 {
		t.Fatalf("incorrect persisted official counts: %+v %v", stats, err)
	}
	queryStart := time.Now()
	result, err := s.Query(ctx, "HP UX", "")
	if err != nil || len(result.Records) == 0 {
		t.Fatalf("persisted query failed: %+v %v", result, err)
	}
	t.Logf("Official catalogue persisted in %s, size %.1f MiB, indexed query %s (%d results)", time.Since(started).Round(time.Millisecond), float64(stats.Bytes)/(1<<20), time.Since(queryStart), len(result.Records))
}
