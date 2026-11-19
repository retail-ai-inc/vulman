package cvedb

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testZIP(t testing.TB, count int, nested bool) []byte {
	t.Helper()
	var out bytes.Buffer
	z := zip.NewWriter(&out)
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("CVE-2026-%04d", i+1)
		w, err := z.Create("cves/2026/0xxx/" + id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintf(w, `{"cveMetadata":{"cveId":%q,"state":"PUBLISHED","dateUpdated":"2026-01-01T00:00:00Z"},"containers":{"cna":{"title":"Example"}}}`, id); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if !nested {
		return out.Bytes()
	}
	inner := bytes.Clone(out.Bytes())
	out.Reset()
	z = zip.NewWriter(&out)
	w, err := z.Create("all_CVEs.zip")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(inner); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func testArchive(data []byte, base bool, at time.Time) Archive {
	hash := sha256.Sum256(data)
	name := "2026-01-01_delta_CVEs_at_0100Z.zip"
	if base {
		name = "2026-01-01_all_CVEs_at_midnight.zip.zip"
	}
	return Archive{Name: name, URL: "https://github.com/CVEProject/cvelistV5/releases/download/test/" + name, Digest: "sha256:" + hex.EncodeToString(hash[:]), Size: int64(len(data)), Base: base, At: at}
}

func TestVerifiedImportResumesSavedCursorAndSupportsNestedZIP(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprint(nested), func(t *testing.T) {
			s := testCatalogue(t)
			data := testZIP(t, 600, nested)
			a := testArchive(data, true, time.Now().UTC())
			if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := s.begin(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			var records []Record
			for i := 0; i < 256; i++ {
				records = append(records, testRecord(fmt.Sprintf("CVE-2026-%04d", i+1)))
			}
			if err := s.commitBatch(context.Background(), records, 256); err != nil {
				t.Fatal(err)
			}
			u := NewUpdater(s)
			u.HTTP.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
				return nil, errors.New("resume redownloaded a verified archive")
			})
			if err := u.importArchive(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			stats, err := s.Stats()
			if err != nil || stats.Records != 600 || !stats.Initialized || stats.Resumable {
				t.Fatalf("incorrect resumed import: %+v %v", stats, err)
			}
			if _, err := s.root.Stat(downloadFile); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("download was retained after successful import: %v", err)
			}
			// Replaying a complete delta overwrites IDs and preserves the count.
			a.Base = false
			a.At = a.At.Add(time.Hour)
			if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := u.importArchive(context.Background(), a); err != nil {
				t.Fatal(err)
			}
			stats, err = s.Stats()
			if err != nil || stats.Records != 600 {
				t.Fatalf("delta duplicated records: %+v %v", stats, err)
			}
		})
	}
}

func TestFailedDownloadKeepsActiveCatalogueAndCheckpoint(t *testing.T) {
	s := testCatalogue(t)
	r := testRecord("CVE-2026-9999")
	if err := s.Put(r); err != nil {
		t.Fatal(err)
	}
	data := testZIP(t, 2, false)
	a := testArchive(data, true, time.Now().UTC())
	u := NewUpdater(s)
	u.HTTP.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("corrupt"))}, nil
	})
	if err := u.importArchive(context.Background(), a); err == nil {
		t.Fatal("corrupt download accepted")
	}
	stats, err := s.Stats()
	if err != nil || stats.Initialized || !stats.SourceAt.IsZero() || !stats.Resumable {
		t.Fatalf("failed download advanced freshness: %+v %v", stats, err)
	}
	if _, ok, err := s.Lookup(r.ID); err != nil || !ok {
		t.Fatalf("existing record lost: %v", err)
	}
}

func releaseFor(t *testing.T, at time.Time) release {
	t.Helper()
	r := release{Tag: at.Format("cve_2006-01-02_1504Z")}
	for _, base := range []bool{false, true} {
		a := testArchive([]byte("archive"), base, at)
		r.Assets = append(r.Assets, struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Size   int64  `json:"size"`
			Digest string `json:"digest"`
		}{a.Name, a.URL, a.Size, a.Digest})
	}
	return r
}

func TestReleasePlanChecksEveryHourAndRecoversMissingHistory(t *testing.T) {
	s := testCatalogue(t)
	u := NewUpdater(s)
	start := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	latest := releaseFor(t, start.Add(2*time.Hour))
	history := []release{latest, releaseFor(t, start.Add(time.Hour)), releaseFor(t, start), releaseFor(t, start.Add(-time.Hour))}
	u.HTTP.Transport = transportFunc(func(*http.Request) (*http.Response, error) {
		data, err := json.Marshal(history)
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(data))}, err
	})
	archives, err := u.plan(context.Background(), latest, start.Add(-2*time.Hour))
	if err != nil || len(archives) != 4 || archives[0].Base {
		t.Fatalf("cross-day incremental plan: %+v %v", archives, err)
	}
	archives, err = u.plan(context.Background(), latest, time.Time{})
	if err != nil || len(archives) != 3 || !archives[0].Base || !archives[0].At.Equal(start) {
		t.Fatalf("initial baseline plan: %+v %v", archives, err)
	}
	history = history[:3]
	archives, err = u.plan(context.Background(), latest, start.Add(-3*time.Hour))
	if err != nil || !archives[0].Base {
		t.Fatalf("gap did not select a fresh baseline: %+v %v", archives, err)
	}
	history = []release{latest}
	if _, err := u.plan(context.Background(), latest, start); err == nil {
		t.Fatal("incomplete same-day history was treated as complete")
	}
}

func TestUpdaterStopCancelsHTTPAndRejectsOverlappingRuns(t *testing.T) {
	s := testCatalogue(t)
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
		t.Fatal("overlapping CVE updates accepted")
	}
	u.Stop()
	u.wg.Wait()
	stats, err := u.Stats()
	if err != nil || stats.Running || stats.Phase != "interrupted" || stats.Error != "" {
		t.Fatalf("cancelled update: %+v %v", stats, err)
	}
}

func TestOfficialDeltaFixture(t *testing.T) {
	// Optional verification against an independently downloaded official asset.
	// The default suite stays fully local and uses deterministic ZIP fixtures.
	fixture := os.Getenv("VULMAN_CVE_FIXTURE")
	if fixture == "" {
		t.Skip("set VULMAN_CVE_FIXTURE to verify an official delta archive")
	}
	root, err := os.OpenRoot(filepath.Dir(fixture))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := root.ReadFile(filepath.Base(fixture))
	if err != nil {
		t.Fatal(err)
	}
	s := testCatalogue(t)
	if err := s.root.WriteFile(downloadFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(s)
	if err := u.importArchive(context.Background(), testArchive(data, true, time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	stats, err := s.Stats()
	if err != nil || stats.Records == 0 {
		t.Fatalf("official delta import failed: %+v %v", stats, err)
	}
	t.Logf("Imported %d official CVE records", stats.Records)
}

func BenchmarkCatalogueLookup(b *testing.B) {
	key := make([]byte, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		b.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}
	s, err := Open(b.TempDir(), aead)
	if err != nil {
		b.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			b.Error(err)
		}
	}()
	ctx := context.Background()
	if err := s.begin(ctx, Archive{Name: "benchmark", Base: true, At: time.Now()}); err != nil {
		b.Fatal(err)
	}
	for offset := 0; offset < 100000; offset += batchSize {
		var batch []Record
		for i := offset; i < offset+batchSize && i < 100000; i++ {
			batch = append(batch, testRecord(fmt.Sprintf("CVE-2026-%06d", i)))
		}
		if err := s.commitBatch(ctx, batch, offset+len(batch)); err != nil {
			b.Fatal(err)
		}
	}
	if err := s.finish(ctx); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, found, err := s.Lookup("CVE-2026-050000"); err != nil || !found {
			b.Fatalf("lookup: %v", err)
		}
	}
}
