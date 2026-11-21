package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"vulman/internal/apperror"
)

func TestAssessmentPersistsStructuredWarningsAndFailureLogs(t *testing.T) {
	s, e := controlEngine(t)
	e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
		response := controlResponse(`{}`)
		response.StatusCode = http.StatusForbidden
		return response, nil
	})
	if err := e.Start("p", "manual"); err != nil {
		t.Fatal(err)
	}
	project := awaitRun(t, s)
	run := project.Runs[0]
	if len(run.WarningMessages) != len(run.Warnings) || len(run.WarningMessages) == 0 || run.WarningMessages[0].Code != "source_component" {
		t.Fatalf("missing structured warnings: %+v", run)
	}
	found := false
	for _, entry := range run.Logs {
		if entry.Event == "failed" && entry.Message != nil && entry.Message.Code == "upstream_http" {
			found = entry.Message.Params["arg0"] == "403"
		}
	}
	if !found {
		t.Fatal("saved failure log lost its error code or HTTP status")
	}
	data, err := json.Marshal(run)
	if err != nil || !strings.Contains(string(data), `"warning_messages"`) || !strings.Contains(string(data), `"code":"upstream_http"`) {
		t.Fatal("structured history did not survive serialization", err)
	}
}

func TestAllDatabaseUpdatersExposeStructuredFailureStatus(t *testing.T) {
	_, e := controlEngine(t)
	transport := controlTransport(func(*http.Request) (*http.Response, error) {
		response := controlResponse(`{}`)
		response.StatusCode = http.StatusForbidden
		return response, nil
	})
	e.CVE.HTTP.Transport, e.NVD.HTTP.Transport, e.OSV.HTTP.Transport = transport, transport, transport
	for _, tc := range []struct {
		name   string
		start  func() error
		status func() (bool, *apperror.Message, error)
	}{
		{"cve", func() error { return e.CVE.Start(context.Background()) }, func() (bool, *apperror.Message, error) {
			s, err := e.CVE.Stats()
			return s.Running, s.ErrorMessage, err
		}},
		{"nvd", func() error { return e.NVD.Start(context.Background()) }, func() (bool, *apperror.Message, error) {
			s, err := e.NVD.Stats()
			return s.Running, s.ErrorMessage, err
		}},
		{"osv", func() error { return e.OSV.Start(context.Background(), []string{"Go"}) }, func() (bool, *apperror.Message, error) {
			s, err := e.OSV.Stats()
			return s.Running, s.ErrorMessage, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				running, message, err := tc.status()
				if err != nil {
					t.Fatal(err)
				}
				if !running {
					if message == nil || message.Code == "unexpected" {
						t.Fatalf("database failure lost its public code: %+v", message)
					}
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
			t.Fatal("database update did not finish")
		})
	}
}
