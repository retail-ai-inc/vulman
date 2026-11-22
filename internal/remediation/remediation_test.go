package remediation

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
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

type adviceTransport func(*http.Request) (*http.Response, error)

func (f adviceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestMissingProviderConfigurationKeepsPublicGuidanceWithoutHTTP(t *testing.T) {
	transport := http.DefaultTransport
	requests := 0
	http.DefaultTransport = adviceTransport(func(*http.Request) (*http.Response, error) {
		requests++
		return nil, errors.New("unexpected AI request")
	})
	t.Cleanup(func() {
		http.DefaultTransport = transport
		if requests != 0 {
			t.Errorf("made %d HTTP requests without provider configuration", requests)
		}
	})

	finding := model.Finding{ID: "CVE-2024-0001", Component: "demo", Version: "1.0", References: []string{"https://example.com/advisory"}}
	for _, provider := range []string{"openai", "claude"} {
		for _, tc := range []struct {
			name, key, model, code, section string
		}{
			{name: "no key", model: "configured-model", code: "advice_missing_api_key", section: "API credentials"},
			{name: "blank key", key: " \t\n", model: "configured-model", code: "advice_missing_api_key", section: "API credentials"},
			{name: "no model", key: rand.Text(), code: "advice_missing_model", section: "Fix suggestions"},
			{name: "blank model", key: rand.Text(), model: " \t\n", code: "advice_missing_model", section: "Fix suggestions"},
			{name: "neither configured", code: "advice_missing_api_key", section: "API credentials"},
		} {
			t.Run(provider+"/"+tc.name, func(t *testing.T) {
				settings := model.Defaults().Settings
				settings.Tokens = map[string]string{provider: tc.key}
				settings.OpenAIModel, settings.ClaudeModel = tc.model, tc.model

				advice := Generate(context.Background(), finding, settings, provider)
				if advice.Provider != "public" || advice.Text != Public(finding, settings.Language).Text || len(advice.References) != 1 {
					t.Fatal("missing provider configuration must preserve public advisory guidance")
				}
				if advice.WarningMessage == nil || advice.WarningMessage.Code != tc.code {
					t.Fatalf("expected %s, got %+v", tc.code, advice.WarningMessage)
				}

				brand := "OpenAI"
				if provider == "claude" {
					brand = "Claude"
				}
				if advice.WarningMessage.Params["arg0"] != brand || !strings.Contains(advice.Warning, brand) || !strings.Contains(advice.Warning, tc.section) {
					t.Fatalf("warning does not identify the provider and configuration section: %+v", advice.WarningMessage)
				}
			})
		}
	}

	advice := Generate(context.Background(), finding, model.Defaults().Settings, "public")
	if advice.WarningMessage != nil || advice.Warning != "" {
		t.Fatal("public guidance must not require an API key or model")
	}
}
