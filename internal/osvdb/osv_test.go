package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net/http"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type fixtureObject struct {
	data       []byte
	generation string
	crc        string
}

type fixture struct {
	mu      sync.Mutex
	objects map[string]fixtureObject
	calls   []string
}

func crc(data []byte) string {
	var sum [4]byte
	binary.BigEndian.PutUint32(sum[:], crc32.Checksum(data, crc32.MakeTable(crc32.Castagnoli)))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func (f *fixture) put(name string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[name] = fixtureObject{data: bytes.Clone(data), generation: strconv.Itoa(len(f.calls) + len(f.objects) + 1), crc: crc(data)}
}

func (f *fixture) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	name := strings.TrimPrefix(r.URL.Path, "/osv-vulnerabilities/")
	f.calls = append(f.calls, r.Method+" "+name)
	object, found := f.objects[name]
	status := http.StatusOK
	if !found || r.URL.Query().Get("generation") != "" && r.URL.Query().Get("generation") != object.generation {
		status = http.StatusNotFound
	}

	header := make(http.Header)
	header.Set("X-Goog-Generation", object.generation)
	header.Set("X-Goog-Hash", "crc32c="+object.crc)
	header.Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
	body := object.data
	if r.Method == http.MethodHead {
		body = nil
	}

	return &http.Response{StatusCode: status, Header: header, ContentLength: int64(len(object.data)), Body: io.NopCloser(bytes.NewReader(body))}, nil
}

func testRecord(t *testing.T, id, ecosystem, name string, at time.Time) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(map[string]any{"id": id, "modified": at, "summary": "Test vulnerability", "aliases": []string{"CVE-2026-1234"}, "database_specific": map[string]string{"severity": "HIGH"}, "affected": []any{map[string]any{"package": map[string]string{"ecosystem": ecosystem, "name": name}, "ranges": []any{map[string]any{"type": "SEMVER", "events": []any{map[string]string{"introduced": "0"}, map[string]string{"fixed": "2.0.0"}}}}}}})
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func testZIP(t *testing.T, rows []json.RawMessage) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	for index, raw := range rows {
		w, err := writer.Create(fmt.Sprintf("records/%06d.json", index))
		if err != nil {
			t.Fatal(err)
		}

		if _, err := w.Write(raw); err != nil {
			t.Fatal(err)
		}
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return out.Bytes()
}

func testUpdater(t *testing.T) (*Store, *Updater, *fixture, cipher.AEAD) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(t.TempDir(), aead)
	if err != nil {
		t.Fatal(err)
	}

	u := NewUpdater(s)
	f := &fixture{objects: map[string]fixtureObject{}}
	u.HTTP.Transport = f
	t.Cleanup(func() {
		if err := u.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, u, f, aead
}

func seed(t *testing.T, u *Updater, f *fixture, ecosystem string, rows []json.RawMessage) {
	t.Helper()
	f.put(ecosystem+"/all.zip", testZIP(t, rows))
	// Old modification dates need no follow-up requests during baseline catch-up.
	var lines strings.Builder
	for _, raw := range rows {
		var record Record
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}

		if _, err := fmt.Fprintf(&lines, "%s,%s\n", record.Modified.Format(time.RFC3339Nano), record.ID); err != nil {
			t.Fatal(err)
		}
		f.put(ecosystem+"/"+record.ID+".json", raw)
	}

	f.put(ecosystem+"/modified_id.csv", []byte(lines.String()))
	if err := u.sync(context.Background(), []string{ecosystem}, false); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicBaselineResumeEncryptedPayloadAndCursorLookup(t *testing.T) {
	s, u, f, aead := testUpdater(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	seed(t, u, f, "Go", []json.RawMessage{testRecord(t, "GO-old", "Go", "demo", old)})
	rows := make([]json.RawMessage, 600)
	for index := range rows {
		rows[index] = testRecord(t, fmt.Sprintf("GO-%04d", index), "Go", "demo", old)
	}

	f.put("Go/all.zip", testZIP(t, rows))
	object, err := u.head(ctx, "Go/all.zip", maxArchiveSize)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.update(func(_ *bolt.Tx, m *metadata) error {
		m.Plan, m.Next = []string{"Go"}, 0
		m.Job = &job{Ecosystem: "Go", Full: true, Target: other(m.Ecosystems["Go"].Active), StartedAt: time.Now().UTC(), Object: object, Total: 600}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.putRows(ctx, rows[:256], 256, ""); err != nil {
		t.Fatal(err)
	}

	result, err := s.Query(ctx, "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 1 || result.Records[0].ID != "GO-old" {
		t.Fatal("unpublished baseline became visible")
	}

	if err := s.finish(ctx, false); err == nil {
		t.Fatal("incomplete baseline was published")
	}

	dir := s.root.Name()
	if err := u.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(dir, aead)
	if err != nil {
		t.Fatal(err)
	}
	// Keep the registered cleanup on the new handle after simulating restart.
	u.store = reopened
	u.closed = false
	if reopened.snapshot().Job.Offset != 256 {
		t.Fatal("committed checkpoint was lost")
	}

	if err := u.download(ctx, object, archiveFile); err != nil {
		t.Fatal(err)
	}

	if err := u.importZIP(ctx); err != nil {
		t.Fatal(err)
	}

	if err := reopened.finish(ctx, true); err != nil {
		t.Fatal(err)
	}

	result, err = reopened.Query(ctx, "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 600 || result.Uncertain {
		t.Fatalf("resumed cursor lookup: %d %v", len(result.Records), err)
	}

	raw, err := reopened.root.ReadFile(Filename)
	if err != nil || bytes.Contains(raw, []byte("Test vulnerability")) {
		t.Fatal("OSV payload was not encrypted")
	}
}

func TestIncrementalFailureRetryWithdrawalAndWeeklyReconciliation(t *testing.T) {
	s, u, f, _ := testUpdater(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	seed(t, u, f, "Go", []json.RawMessage{testRecord(t, "GO-one", "Go", "demo", old), testRecord(t, "GO-two", "Go", "demo", old)})
	before := s.snapshot().Ecosystems["Go"].CheckedAt
	at := time.Now().UTC()
	updated := testRecord(t, "GO-one", "Go", "renamed", at)
	f.put("Go/modified_id.csv", []byte(at.Format(time.RFC3339Nano)+",GO-one\n"))
	f.mu.Lock()
	delete(f.objects, "Go/GO-one.json")
	f.mu.Unlock()
	if err := u.sync(ctx, []string{"Go"}, false); err == nil {
		t.Fatal("missing delta record was treated as deleted or successful")
	}

	if !s.snapshot().Ecosystems["Go"].CheckedAt.Equal(before) || s.snapshot().Job.Offset != 0 {
		t.Fatal("failed delta advanced its successful timestamp or checkpoint")
	}

	f.put("Go/GO-one.json", updated)
	if err := u.sync(ctx, []string{"Go"}, false); err != nil {
		t.Fatal(err)
	}

	result, err := s.Query(ctx, "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 1 || result.Records[0].ID != "GO-two" {
		t.Fatal("old package index survived replacement")
	}

	var withdrawn map[string]any
	if err := json.Unmarshal(updated, &withdrawn); err != nil {
		t.Fatal(err)
	}
	withdrawn["withdrawn"], withdrawn["modified"] = at.Add(time.Second), at.Add(time.Second)
	raw, err := json.Marshal(withdrawn)
	if err != nil {
		t.Fatal(err)
	}
	f.put("Go/GO-one.json", raw)
	f.put("Go/modified_id.csv", []byte(at.Add(time.Second).Format(time.RFC3339Nano)+",GO-one\n"))
	if err := u.sync(ctx, []string{"Go"}, false); err != nil {
		t.Fatal(err)
	}
	result, err = s.Query(ctx, "Go", "renamed", "1.0.0")
	if err != nil || len(result.Records) != 0 {
		t.Fatal("withdrawn advisory still matched")
	}

	f.put("Go/all.zip", testZIP(t, []json.RawMessage{testRecord(t, "GO-new", "Go", "fresh", old)}))
	f.put("Go/modified_id.csv", []byte(old.Format(time.RFC3339Nano)+",GO-new\n"))
	if err := s.update(func(_ *bolt.Tx, m *metadata) error {
		state := m.Ecosystems["Go"]
		state.BaselineAt = old
		m.Ecosystems["Go"] = state
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := u.sync(ctx, []string{"Go"}, false); err != nil {
		t.Fatal(err)
	}
	result, err = s.Query(ctx, "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 0 {
		t.Fatal("weekly reconciliation retained a deleted advisory")
	}
}

func TestRollbackIncludesIndexesCountsAndPendingCheckpoint(t *testing.T) {
	s, u, f, _ := testUpdater(t)
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	seed(t, u, f, "Go", []json.RawMessage{testRecord(t, "GO-one", "Go", "demo", old)})
	if err := s.update(func(_ *bolt.Tx, m *metadata) error {
		m.Job = &job{Ecosystem: "Go", Target: m.Ecosystems["Go"].Active}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.putRows(context.Background(), []json.RawMessage{testRecord(t, "GO-new", "Go", "new", old), json.RawMessage(`{"id":"bad"}`)}, 2, ""); err == nil {
		t.Fatal("bad batch accepted")
	}
	result, err := s.Query(context.Background(), "Go", "new", "1.0.0")
	if err != nil || len(result.Records) != 0 || s.snapshot().Job.Offset != 0 {
		t.Fatal("rollback left indexes or advanced checkpoint")
	}
}

func TestMatchingNormalizationBoundariesAndUnsupportedVersions(t *testing.T) {
	for _, tc := range []struct {
		version        string
		events         []Event
		matched, known bool
	}{
		{"1.0.0", []Event{{Introduced: "0"}, {Fixed: "1.0.0"}}, false, true},
		{"1.0.0", []Event{{Introduced: "0"}, {LastAffected: "1.0.0"}}, true, true},
		{"1.0.0-rc.1", []Event{{Introduced: "0"}, {Fixed: "1.0.0"}}, true, true},
		{"2.0.0", []Event{{Introduced: "0"}, {Fixed: "1.0.0"}, {Introduced: "2.0.0"}, {Limit: "3.0.0"}}, true, true},
		{"vendor-release", []Event{{Introduced: "0"}}, false, false},
		{"1.0.0", []Event{{Fixed: "2.0.0"}}, false, false},
	} {
		matched, known := matchSemver(tc.version, tc.events)
		if matched != tc.matched || known != tc.known {
			t.Fatalf("range result for %s: %v %v", tc.version, matched, known)
		}
	}

	if PackageName("PyPI", "Some_Package.Name") != "some-package-name" {
		t.Fatal("PyPI normalization")
	}
	for _, invalid := range []string{"../Go", "Go/../../", "", "https://host", "Go?key=x"} {
		if _, err := Ecosystem(invalid); err == nil {
			t.Fatalf("accepted ecosystem %q", invalid)
		}
	}
	if names, err := NormalizeEcosystems([]string{"Debian:12", "Go", "Go"}); err != nil || !slices.Equal(names, []string{"Debian", "Go"}) {
		t.Fatal("ecosystem selection normalization")
	}
	r := Record{Affected: []Affected{{Versions: []string{"vendor-release"}}}}
	r.Affected[0].Package.Name, r.Affected[0].Package.Ecosystem = "demo", "PyPI"
	if yes, unknown := Match(r, "PyPI", "demo", "vendor-release"); !yes || unknown {
		t.Fatal("explicit version should match")
	}
	r.Affected[0].Ranges = append(r.Affected[0].Ranges, struct {
		Type   string  `json:"type"`
		Events []Event `json:"events"`
	}{Type: "ECOSYSTEM"})
	if yes, unknown := Match(r, "PyPI", "demo", "other"); yes || !unknown {
		t.Fatal("unsupported range reported safe")
	}
}

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestStopCancelsDownloadAndRejectsOverlappingUpdates(t *testing.T) {
	_, u, _, _ := testUpdater(t)
	started := make(chan struct{})
	u.HTTP.Transport = transportFunc(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	if err := u.Start(context.Background(), []string{"Go"}); err != nil {
		t.Fatal(err)
	}
	<-started
	stats, err := u.Stats()
	if err != nil || !stats.Running || len(stats.Ecosystems) == 0 || !stats.Ecosystems[0].Running {
		t.Fatal("initial update is invisible to queued assessments")
	}
	if err := u.Start(context.Background(), []string{"Go"}); err == nil {
		t.Fatal("overlapping update accepted")
	}
	u.Stop()
	u.wg.Wait()
	stats, err = u.Stats()
	if err != nil || stats.Running || stats.Phase != "interrupted" {
		t.Fatalf("stop failed: %+v %v", stats, err)
	}
}

func TestOfficialGoArchive(t *testing.T) {
	path := os.Getenv("VULMAN_OSV_FIXTURE")
	if path == "" {
		t.Skip("set VULMAN_OSV_FIXTURE for the official Go archive validation")
	}
	s, u, _, _ := testUpdater(t)
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	data, err := root.ReadFile("osv-go.zip")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ensure("Go"); err != nil {
		t.Fatal(err)
	}
	if err := s.update(func(_ *bolt.Tx, m *metadata) error {
		m.Plan = []string{"Go"}
		m.Job = &job{Ecosystem: "Go", Target: "b", Full: true, StartedAt: time.Now(), Object: blob{Size: int64(len(data)), Updated: time.Now()}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.root.WriteFile(archiveFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := u.importZIP(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	stats, err := u.Stats()
	if err != nil || stats.Records < 1000 {
		t.Fatalf("official archive incomplete: %+v %v", stats, err)
	}
	t.Logf("Imported %d official Go advisories into %.1f MiB", stats.Records, float64(stats.Bytes)/(1<<20))
}

func TestLiveOfficialGoSync(t *testing.T) {
	if os.Getenv("VULMAN_OSV_LIVE") != "1" {
		t.Skip("set VULMAN_OSV_LIVE=1 for a live OSV baseline and incremental catch-up")
	}

	_, u, _, _ := testUpdater(t)
	u.HTTP.Transport = nil
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := u.sync(ctx, []string{"Go"}, false); err != nil {
		t.Fatal(err)
	}

	stats, err := u.Stats()
	if err != nil || stats.Records < 1000 || stats.Resumable {
		t.Fatalf("live snapshot or catch-up incomplete: %+v %v", stats, err)
	}

	t.Logf("Verified and synced %d official Go advisories with incremental catch-up", stats.Records)
}

func TestChecksumFailureKeepsPublishedCatalogue(t *testing.T) {
	s, u, f, _ := testUpdater(t)
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	seed(t, u, f, "Go", []json.RawMessage{testRecord(t, "GO-old", "Go", "demo", old)})
	before := s.snapshot().Ecosystems["Go"].CheckedAt
	f.put("Go/all.zip", testZIP(t, []json.RawMessage{testRecord(t, "GO-new", "Go", "other", old)}))
	f.mu.Lock()
	object := f.objects["Go/all.zip"]
	object.crc = "AAAAAA=="
	f.objects["Go/all.zip"] = object
	f.mu.Unlock()
	if err := u.sync(context.Background(), []string{"Go"}, true); err == nil {
		t.Fatal("corrupted download was accepted")
	}

	result, err := s.Query(context.Background(), "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 1 || result.Records[0].ID != "GO-old" || !s.snapshot().Ecosystems["Go"].CheckedAt.Equal(before) {
		t.Fatal("failed checksum changed the published catalogue or freshness")
	}
}

func TestUncleanOSVProcessPreservesCommittedRecordsAndCheckpoint(t *testing.T) {
	if os.Getenv("VULMAN_OSV_CRASH_CHILD") == "1" {
		key, err := hex.DecodeString(os.Getenv("VULMAN_OSV_CRASH_KEY"))
		if err != nil {
			t.Fatal(err)
		}

		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatal(err)
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}

		s, err := Open(os.Getenv("VULMAN_OSV_CRASH_DIR"), aead)
		if err != nil {
			t.Fatal(err)
		}

		if err := s.ensure("Go"); err != nil {
			t.Fatal(err)
		}

		if err := s.update(func(_ *bolt.Tx, m *metadata) error {
			m.Plan = []string{"Go"}
			m.Job = &job{Ecosystem: "Go", Target: "b", Full: true, Total: 2, StartedAt: time.Now(), Object: blob{Updated: time.Now()}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}

		if err := s.putRows(context.Background(), []json.RawMessage{testRecord(t, "GO-first", "Go", "demo", time.Now().UTC())}, 1, ""); err != nil {
			t.Fatal(err)
		}

		if err := s.db.Update(func(tx *bolt.Tx) error {
			if err := tx.Bucket([]byte("meta")).Put([]byte("uncommitted"), []byte("must disappear")); err != nil {
				return err
			}
			os.Exit(23)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		t.Fatal("child did not exit inside its uncommitted transaction")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(executable, "-test.run=^TestUncleanOSVProcessPreservesCommittedRecordsAndCheckpoint$") // #nosec G204 -- reexecutes this test binary with a fixed test selector.
	cmd.Env = append(os.Environ(), "VULMAN_OSV_CRASH_CHILD=1", "VULMAN_OSV_CRASH_KEY="+hex.EncodeToString(key), "VULMAN_OSV_CRASH_DIR="+dir)
	if output, err := cmd.CombinedOutput(); err == nil || cmd.ProcessState.ExitCode() != 23 {
		t.Fatalf("crash fixture failed: %s %v", output, err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, aead)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()

	if s.snapshot().Job.Offset != 1 {
		t.Fatal("committed checkpoint was lost")
	}

	if err := s.db.View(func(tx *bolt.Tx) error {
		if tx.Bucket([]byte("meta")).Get([]byte("uncommitted")) != nil {
			return fmt.Errorf("uncommitted transaction survived")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := s.putRows(context.Background(), []json.RawMessage{testRecord(t, "GO-second", "Go", "demo", time.Now().UTC())}, 2, ""); err != nil {
		t.Fatal(err)
	}

	if err := s.finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}

	result, err := s.Query(context.Background(), "Go", "demo", "1.0.0")
	if err != nil || len(result.Records) != 2 {
		t.Fatal("crash recovery did not preserve complete records and indexes")
	}
}
