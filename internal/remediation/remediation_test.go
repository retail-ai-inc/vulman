package remediation

import (
	"context"
	"strings"
	"testing"
	"vulman/internal/model"
)

func TestPublicGuidanceDoesNotInventFixedVersions(t *testing.T) {
	f := model.Finding{ID: "CVE-2024-0001", Component: "demo", Version: "1.0"}
	a := Public(f, "en")
	if !strings.Contains(a.Text, "does not specify a fixed version") {
		t.Fatal("missing uncertainty")
	}
	s := model.Defaults().Settings
	s.OpenAIModel = "configured-model"
	a = Generate(context.Background(), f, s, "openai")
	if a.Provider != "public" || a.Warning == "" {
		t.Fatal("missing credential fallback")
	}
	if !strings.Contains(Public(f, "ja").Text, "修正バージョン") {
		t.Fatal("Japanese guidance missing")
	}
}
