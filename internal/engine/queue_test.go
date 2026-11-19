package engine

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
	"vulman/internal/testutil"
	"vulman/internal/workflow"
)

const queueCPE = "cpe:2.3:a:golang:go:1.26.0:*:*:*:*:*:*:*"

type queueDownload struct {
	started chan struct{}
	release func()
	fail    atomic.Bool
}

func queueZIP(t *testing.T, name, data string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zip.NewWriter(&out)
	file, err := writer.Create(name)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := io.WriteString(file, data); err != nil {
		t.Fatal(err)
	}

	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	return out.Bytes()
}

func queueFeed(t *testing.T, data string, dictionary bool) ([]byte, string) {
	t.Helper()
	var out bytes.Buffer
	if dictionary {
		out.Write(queueZIP(t, "dictionary.json", data))
	} else {
		writer := gzip.NewWriter(&out)
		if _, err := io.WriteString(writer, data); err != nil {
			t.Fatal(err)
		}

		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
	}

	hash := sha256.Sum256([]byte(data))
	meta := fmt.Sprintf("lastModifiedDate:%s\nsize:%d\ngzSize:%d\nzipSize:%d\nsha256:%x\n", time.Now().UTC().Format(time.RFC3339Nano), len(data), out.Len(), out.Len(), hash)
	return out.Bytes(), meta
}

func blockQueueDownload(t *testing.T, client *http.Client, respond func(*http.Request) *http.Response) *queueDownload {
	t.Helper()
	release := make(chan struct{})
	download := &queueDownload{started: make(chan struct{}), release: sync.OnceFunc(func() { close(release) })}
	started := sync.OnceFunc(func() { close(download.started) })
	t.Cleanup(download.release)
	client.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		started()
		select {
		case <-release:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}

		if download.fail.Load() {
			response := controlResponse("denied")
			response.StatusCode = http.StatusForbidden
			return response, nil
		}

		return respond(r), nil
	})

	return download
}

func queueNVDDownload(t *testing.T, e *Engine) *queueDownload {
	t.Helper()
	data := `{"totalResults":1,"resultsPerPage":1,"vulnerabilities":[{"cve":{"id":"CVE-2026-0001","descriptions":[{"lang":"en","value":"Go advisory"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},"configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"` + queueCPE + `"}]}]}]}}]}`
	nvd, meta := queueFeed(t, data, false)
	cpe, cpeMeta := queueFeed(t, `{"totalResults":1,"resultsPerPage":1,"products":[{"cpe":{"cpeNameId":"test-cpe-id","cpeName":"`+queueCPE+`"}}]}`, true)

	return blockQueueDownload(t, e.NVD.HTTP, func(r *http.Request) *http.Response {
		dictionary := strings.Contains(r.URL.Path, "/cpe/")
		body := nvd
		if dictionary {
			body = cpe
		}

		if strings.HasSuffix(r.URL.Path, ".meta") {
			body = []byte(meta)
			if dictionary {
				body = []byte(cpeMeta)
			}
		}

		return controlResponse(string(body))
	})
}

func queueCVEDownload(t *testing.T, e *Engine) *queueDownload {
	t.Helper()
	data := queueZIP(t, "cves/2026/0xxx/CVE-2026-0001.json", `{"cveMetadata":{"cveId":"CVE-2026-0001","state":"PUBLISHED"},"containers":{"cna":{"title":"Go advisory enriched"}}}`)
	hash := sha256.Sum256(data)
	name := "test_all_CVEs_at_midnight.zip"
	release, err := json.Marshal(map[string]any{
		"tag_name": time.Now().UTC().Truncate(24 * time.Hour).Format("cve_2006-01-02_1504Z"),
		"assets":   []map[string]any{{"name": name, "browser_download_url": "https://github.com/CVEProject/cvelistV5/releases/download/test/" + name, "size": len(data), "digest": fmt.Sprintf("sha256:%x", hash)}},
	})
	if err != nil {
		t.Fatal(err)
	}

	return blockQueueDownload(t, e.CVE.HTTP, func(r *http.Request) *http.Response {
		if r.URL.Host == "github.com" {
			return controlResponse(string(data))
		}

		if strings.HasSuffix(r.URL.Path, "/latest") {
			return controlResponse(string(release))
		}

		return controlResponse("[" + string(release) + "]")
	})
}

func queuedEngine(t *testing.T, cve bool) (*store.Store, *Engine, *atomic.Int32) {
	t.Helper()
	s, e := controlEngine(t)
	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"nvd": true, "cve": cve}
		st.Settings.CVEUpdateSchedule = "off"
		st.Settings.NVDUpdateSchedule = "off"
		st.Projects[0].Assets[0].Name = "Go"
		st.Projects[0].Assets[0].CPE = queueCPE
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	var apiCalls atomic.Int32
	e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
		apiCalls.Add(1)
		return controlResponse(`{"totalResults":0,"vulnerabilities":[]}`), nil
	})
	t.Cleanup(func() {
		if t.Failed() {
			st, err := s.Read()
			t.Logf("queue state at failure: %+v, read error: %v", st.Projects, err)
		}
	})

	return s, e, &apiCalls
}

func waitQueueCondition(t *testing.T, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}

		time.Sleep(5 * time.Millisecond)
	}

	t.Fatal("queue condition was not reached")
}

func TestQueuedSyncWaitsForBothUpdatesAndStartsOnceWithOriginalScope(t *testing.T) {
	s, e, calls := queuedEngine(t, true)
	nvd, cve := queueNVDDownload(t, e), queueCVEDownload(t, e)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	if err := e.UpdateCVEDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	signalControl(t, cve.started)
	if err := e.StartFiltered("p", "manual", "a", "auto", "CRITICAL"); err != nil {
		t.Fatal(err)
	}

	p := waitControlStatus(t, s, "queued")
	id := p.Runs[0].ID
	if len(p.Runs[0].DatabaseWaits) != 2 || !p.Syncing || calls.Load() != 0 {
		t.Fatalf("assessment did not wait for both databases: %+v", p.Runs[0])
	}

	e.mu.Lock()
	paused := workflow.Paused(e.active["p"].control.Context())
	e.mu.Unlock()
	if !paused || e.Start("p", "manual") == nil || e.Control("p", id, "pause") == nil {
		t.Fatal("queued sync consumed its timeout or accepted overlapping work")
	}

	nvd.release()
	waitQueueCondition(t, func() bool {
		stats, err := e.NVD.Stats()
		return err == nil && !stats.Running && stats.Phase == "complete"
	})
	time.Sleep(600 * time.Millisecond)
	p = waitControlStatus(t, s, "queued")
	if calls.Load() != 0 || p.Runs[0].Steps[0].Status != "pending" {
		t.Fatal("assessment started before CVE finished")
	}

	cve.release()
	p = awaitRun(t, s)
	run := p.Runs[0]
	starts := 0
	for _, entry := range run.Logs {
		if entry.Event == "run_started" {
			starts++
		}
	}

	if run.ID != id || run.Status != "complete" || run.AssetID != "a" || run.Mode != "auto" || run.Severity != "CRITICAL" || run.Count != 1 || starts != 1 || run.PausedSeconds <= 0 || calls.Load() != 0 {
		t.Fatalf("queued scope or automatic start was incorrect: %+v, API calls %d", run, calls.Load())
	}

	if e.Control("p", id, "cancel-queued") == nil {
		t.Fatal("stale queue controls were accepted after start")
	}
}

func TestCancellingQueuedSyncKeepsDownloadAndPriorFindings(t *testing.T) {
	s, e, calls := queuedEngine(t, false)
	nvd := queueNVDDownload(t, e)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}

	p := waitControlStatus(t, s, "queued")
	if err := e.Control("p", p.Runs[0].ID, "cancel-queued"); err != nil {
		t.Fatal(err)
	}

	finished := awaitRun(t, s)
	stats, err := e.NVD.Stats()
	if err != nil || !stats.Running || finished.Runs[0].Status != "stopped" || !reflect.DeepEqual(p.Findings, finished.Findings) || !p.LastSync.Equal(finished.LastSync) || calls.Load() != 0 {
		t.Fatal("cancelling queued sync stopped its download or changed findings")
	}
}

func TestFailedDatabaseUpdateWaitsForRetryThenStartsQueuedSync(t *testing.T) {
	s, e, calls := queuedEngine(t, false)
	nvd := queueNVDDownload(t, e)
	nvd.fail.Store(true)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}

	id := waitControlStatus(t, s, "queued").Runs[0].ID
	nvd.release()
	p := waitControlStatus(t, s, "waiting_databases")
	if !strings.Contains(p.Runs[0].DatabaseWaits[0].Detail, "403") || calls.Load() != 0 || !p.Syncing {
		t.Fatal("failure reason was hidden or assessment fell back to APIs")
	}

	nvd.fail.Store(false)
	if err := e.Control("p", id, "retry-databases"); err != nil {
		t.Fatal(err)
	}

	p = awaitRun(t, s)
	if p.Runs[0].ID != id || p.Runs[0].Status != "complete" || calls.Load() != 0 {
		t.Fatalf("retry did not release the same queued sync: %+v", p.Runs[0])
	}
}

func TestStoppedUpdateCanUseAvailableDataWithoutAPIsOrStoppingOtherDownloads(t *testing.T) {
	s, e, calls := queuedEngine(t, true)
	nvd, cve := queueNVDDownload(t, e), queueCVEDownload(t, e)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	if err := e.UpdateCVEDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	signalControl(t, cve.started)
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}

	before := waitControlStatus(t, s, "queued")
	e.NVD.Stop()
	p := waitControlStatus(t, s, "waiting_databases")
	if p.Runs[0].DatabaseWaits[0].Status != "interrupted" {
		t.Fatal("stopped database was not identified")
	}

	if err := e.Control("p", p.Runs[0].ID, "use-available"); err != nil {
		t.Fatal(err)
	}

	p = awaitRun(t, s)
	stats, err := e.CVE.Stats()
	if err != nil || !stats.Running || p.Runs[0].Mode != "local" || len(p.Runs[0].Warnings) == 0 || !reflect.DeepEqual(before.Findings, p.Findings) || calls.Load() != 0 {
		t.Fatal("available-data option accessed APIs, stopped CVE, or hid incomplete results")
	}
}

func TestUnrelatedDatabaseUpdatesDoNotDelayAssessmentsOrStandaloneScans(t *testing.T) {
	s, e, _ := queuedEngine(t, false)
	nvd := queueNVDDownload(t, e)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	st, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}

	for _, mode := range []string{"auto", codeScanMode} {
		settings := st.Settings
		if mode == "auto" {
			settings.NVDURL = "https://example.test/nvd"
		}

		waits, err := e.databaseDependencies(st.Projects[0], settings, mode)
		if err != nil || len(waits) != 0 {
			t.Fatalf("unrelated updater blocked mode %s: %+v %v", mode, waits, err)
		}
	}

	if err := s.Update(func(st *model.State) error {
		st.Settings.Sources = map[string]bool{"osv": true, "nvd": false, "cve": false}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
		return controlResponse(`{"vulns":[]}`), nil
	})
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}

	if run := awaitRun(t, s).Runs[0]; len(run.DatabaseWaits) != 0 || run.Status != "complete" {
		t.Fatal("disabled NVD source still delayed an OSV-only assessment")
	}
}

func TestClosingQueuedSyncLeavesInterruptedHistoryAndNoAutomaticReplay(t *testing.T) {
	s, e, calls := queuedEngine(t, false)
	nvd := queueNVDDownload(t, e)
	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}

	p := waitControlStatus(t, s, "queued")
	e.Close()
	finished := awaitRun(t, s)
	if finished.Runs[0].Status != "interrupted" || !reflect.DeepEqual(p.Findings, finished.Findings) || calls.Load() != 0 {
		t.Fatal("shutdown executed queued work or changed findings")
	}

	reopened, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	st, err := s.Read()
	if err != nil || st.Projects[0].Syncing || len(st.Projects[0].Runs) != 1 {
		t.Fatal("restart replayed a queued assessment")
	}
}

func TestStaleQueueControlsCannotAlterAnAssessmentAfterAutomaticStart(t *testing.T) {
	s, e, _ := queuedEngine(t, false)
	nvd := queueNVDDownload(t, e)
	started, cancelled := make(chan struct{}), make(chan struct{})
	e.Sources.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
		return nil, r.Context().Err()
	})

	if err := e.UpdateNVDDatabase(); err != nil {
		t.Fatal(err)
	}

	signalControl(t, nvd.started)
	if err := e.StartFiltered("p", "manual", "a", "refresh", "HIGH"); err != nil {
		t.Fatal(err)
	}

	id := waitControlStatus(t, s, "queued").Runs[0].ID
	nvd.release()
	signalControl(t, started)
	p := waitControlStatus(t, s, "running")
	if p.Runs[0].Mode != "refresh" || p.Runs[0].Severity != "HIGH" {
		t.Fatal("queue did not retain the requested sync mode and severity")
	}

	for _, action := range []string{"cancel-queued", "use-available", "retry-databases"} {
		if err := e.Control("p", id, action); err != ErrRunNotActive {
			t.Fatalf("stale %s action was accepted: %v", action, err)
		}
	}

	select {
	case <-cancelled:
		t.Fatal("stale queue controls cancelled an active API request")
	default:
	}

	if err := e.Control("p", id, "stop"); err != nil {
		t.Fatal(err)
	}

	signalControl(t, cancelled)
	awaitRun(t, s)
}

func TestRestartRecoversUnfinishedQueuedRequestsAsInterrupted(t *testing.T) {
	for _, status := range []string{"queued", "waiting_databases"} {
		t.Run(status, func(t *testing.T) {
			s := testStore(t)
			if err := s.Update(func(st *model.State) error {
				st.Settings.CVEUpdateSchedule = "off"
				st.Settings.NVDUpdateSchedule = "off"
				st.Projects = []model.Project{{ID: "p", Syncing: true, Runs: []model.Run{{ID: "queued-run", Status: status, PausedAt: time.Now(), StartedAt: time.Now(), Steps: []model.SyncStep{{ID: "save", Kind: "save", Status: "pending"}}}}}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			e, err := New(s)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(e.Close)
			st, err := s.Read()
			if err != nil {
				t.Fatal(err)
			}

			p := st.Projects[0]
			run := p.Runs[0]
			if p.Syncing || run.Status != "interrupted" || run.Logs[len(run.Logs)-1].Event != "queue_interrupted" || run.Steps[0].Status != "skipped" {
				t.Fatal("unfinished queued request was replayed or left locked after restart")
			}
		})
	}
}

func TestOSVQueueWaitsOnlyForTheSelectedComponentEcosystem(t *testing.T) {
	s, e := controlEngine(t)
	if err := s.Update(func(st *model.State) error {
		st.Settings.OSVEcosystems = []string{"Go", "PyPI"}
		st.Settings.OSVUpdateSchedule = "off"
		st.Projects[0].Assets = []model.Asset{{ID: "go", Name: "demo", Version: "1.0.0", Ecosystem: "Go"}, {ID: "python", Name: "demo", Version: "1.0.0", Ecosystem: "PyPI"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-10 * 24 * time.Hour).Format(time.RFC3339Nano)
	raw := func(eco string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"id":"TEST-%s","modified":%q,"summary":"Issue","affected":[{"package":{"name":"demo","ecosystem":%q},"versions":["1.0.0"]}]}`, eco, old, eco))
	}
	goData := testutil.NewOSVTransport(t, "Go", []json.RawMessage{raw("Go")})
	goStarted, pythonStarted, releaseGo := make(chan struct{}), make(chan struct{}), make(chan struct{})
	goSignal, pythonSignal := sync.OnceFunc(func() { close(goStarted) }), sync.OnceFunc(func() { close(pythonStarted) })
	unblock := sync.OnceFunc(func() { close(releaseGo) })
	defer unblock()
	e.OSV.HTTP.Transport = controlTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.Path, "/PyPI/") {
			pythonSignal()
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		goSignal()
		select {
		case <-releaseGo:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
		return goData.RoundTrip(r)
	})
	if err := e.UpdateOSVDatabase(); err != nil {
		t.Fatal(err)
	}
	signalControl(t, goStarted)
	if err := e.StartAsset("p", "manual", "go"); err != nil {
		t.Fatal(err)
	}
	p := waitControlStatus(t, s, "queued")
	if len(p.Runs[0].DatabaseWaits) != 1 || p.Runs[0].DatabaseWaits[0].Source != "osv:Go" {
		t.Fatal("selected component waited for unrelated ecosystem")
	}
	unblock()
	signalControl(t, pythonStarted)
	p = awaitRun(t, s)
	stats, err := e.OSV.Stats()
	if err != nil || !stats.Running || p.Runs[0].Status != "complete" || p.Runs[0].Count != 1 {
		t.Fatalf("Go queue did not release while PyPI still updated: %+v %+v %v", p.Runs[0], stats, err)
	}
}
