package apperror

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPublicErrorsPreserveCodesParametersAndGoCauses(t *testing.T) {
	sentinel := New("project_not_found", "project not found")
	err := Newf("context", "%s: %w", "demo", fmt.Errorf("internal context: %w", sentinel))
	if !errors.Is(err, sentinel) {
		t.Fatal("wrapping lost the sentinel")
	}
	var structured *Error
	if !errors.As(err, &structured) {
		t.Fatal("wrapping lost the error type")
	}

	message := Public(err)
	if message.Code != "context" || message.Params["arg0"] != "demo" || len(message.Causes) != 1 || message.Causes[0].Code != "project_not_found" {
		t.Fatalf("unexpected public message: %+v", message)
	}
	if message.English() != "demo: project not found" {
		t.Fatal(message.English())
	}

	joined := Public(errors.Join(err, context.DeadlineExceeded))
	if joined.Code != "multiple" || len(joined.Causes) != 2 || joined.Causes[1].Code != "timeout" {
		t.Fatalf("joined causes were lost: %+v", joined)
	}
}

func TestUntrustedDiagnosticsNeverCrossThePublicBoundary(t *testing.T) {
	private := errors.New("https://user:private-value@example.test/?token=private-value: scanner output private-value")
	err := Expose(Newf("scan_cleanup", "Could not remove temporary scan files: %w", private))
	data, encodeErr := json.Marshal(Public(err))
	if encodeErr != nil {
		t.Fatal(encodeErr)
	}
	if strings.Contains(string(data), "private-value") || strings.Contains(err.Error(), "private-value") {
		t.Fatal("a private diagnostic leaked to the public message")
	}
	if !errors.Is(err, private) {
		t.Fatal("the original cause is no longer available inside Go")
	}
	if Public(private).Code != "unexpected" {
		t.Fatal("unknown external errors must use the generic translated fallback")
	}
}

func TestCommonExternalFailuresHaveActionableCodes(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{context.Canceled, "cancelled"},
		{context.DeadlineExceeded, "timeout"},
		{&os.PathError{Op: "open", Path: "private", Err: os.ErrPermission}, "permission_denied"},
		{os.ErrNotExist, "file_missing"},
		{&exec.Error{Name: "private", Err: exec.ErrNotFound}, "tool_missing"},
		{exec.ErrDot, "tool_relative_path"},
		{&net.DNSError{Err: "private", Name: "private"}, "network"},
	} {
		if got := Public(tc.err); got.Code != tc.code || strings.Contains(got.English(), "private") {
			t.Errorf("unexpected public failure for %T: %+v", tc.err, got)
		}
	}
}
