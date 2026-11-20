package scanner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"vulman/internal/apperror"
	"vulman/internal/model"
)

func TestScannerWarningsCarryCodesAndKeepTheCLICompatible(t *testing.T) {
	project := model.Project{ScanCode: true}
	settings := model.Defaults().Settings
	_, problems := ScanDetailed(context.Background(), project, settings, "", func(ScanEvent) {})
	if len(problems) != 1 || apperror.Public(problems[0]).Code != "scan_no_tools" {
		t.Fatalf("missing scanner configuration code: %+v", problems)
	}
	_, warnings := Scan(context.Background(), project, settings, "", func(ScanEvent) {})
	if len(warnings) != 1 || warnings[0] != "Code scanning enabled on project, but no scanner is enabled in settings." {
		t.Fatalf("unexpected CLI warning: %v", warnings)
	}

	result := checkFailure(CheckResult{}, errors.New("private command output"))
	if result.Message == nil || result.Message.Code != "unexpected" || strings.Contains(result.Detail, "private") {
		t.Fatal("scanner availability check exposed external command diagnostics")
	}
}
