package main

import (
	"testing"
	"testing/fstest"

	"vulman/internal/model"
)

func TestLocalizationsLoadAdditionalLanguageFiles(t *testing.T) {
	files := fstest.MapFS{
		"locales/en.json":    {Data: []byte(`{"name":"English","messages":{"overview":"Overview"}}`)},
		"locales/pt-BR.json": {Data: []byte(`{"name":"Português","messages":{"overview":"Visão geral"}}`)},
	}
	localizations, err := readLocalizations(files)
	if err != nil {
		t.Fatal(err)
	}
	if got := localizations["pt-BR"]; got.Name != "Português" || got.Messages["overview"] != "Visão geral" {
		t.Fatalf("unexpected additional localization: %+v", got)
	}

	delete(files, "locales/en.json")
	if _, err := readLocalizations(files); err == nil {
		t.Fatal("loaded localizations without the English fallback")
	}
}

func TestSaveSettingsAcceptsBundledLanguages(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	localizations, err := desktop.Localizations()
	if err != nil {
		t.Fatal(err)
	}
	settings := model.Defaults().Settings
	for code := range localizations {
		settings.Language = code
		if err := desktop.SaveSettings(SettingsInput{Settings: settings}); err != nil {
			t.Fatalf("could not save bundled language %s: %v", code, err)
		}
		got, err := desktop.State()
		if err != nil || got.Settings.Language != code {
			t.Fatalf("language %s was not saved: %v", code, err)
		}
	}
	settings.Language = "not-bundled"
	if err := desktop.SaveSettings(SettingsInput{Settings: settings}); err == nil {
		t.Fatal("accepted an unbundled language")
	}
}
