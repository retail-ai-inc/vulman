package main

import (
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"

	"vulman/internal/apperror"
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

func TestErrorCodesHaveSeparateEnglishAndJapaneseMessages(t *testing.T) {
	locales, err := bundledLocalizations()
	if err != nil {
		t.Fatal(err)
	}
	placeholders := regexp.MustCompile(`\{[a-zA-Z0-9_]+\}`)
	for key, english := range locales["en"].Messages {
		if !strings.HasPrefix(key, "error_") {
			continue
		}
		japanese := locales["ja"].Messages[key]
		if japanese == "" {
			t.Errorf("missing Japanese error message: %s", key)
		}
		first, second := placeholders.FindAllString(english, -1), placeholders.FindAllString(japanese, -1)
		slices.Sort(first)
		slices.Sort(second)
		if !reflect.DeepEqual(first, second) {
			t.Errorf("different error parameters for %s: %v, %v", key, first, second)
		}
	}

	// Catch newly introduced codes whose translations were forgotten.
	for _, root := range []string{".", "../../internal"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (selector.Sel.Name != "New" && selector.Sel.Name != "Newf") {
					return true
				}
				name, ok := selector.X.(*ast.Ident)
				literal, literalOK := call.Args[0].(*ast.BasicLit)
				if !ok || name.Name != "apperror" || !literalOK {
					return true
				}
				code, err := strconv.Unquote(literal.Value)
				if err != nil || locales["en"].Messages["error_"+code] == "" || locales["ja"].Messages["error_"+code] == "" {
					t.Errorf("missing error translation for %s in %s", literal.Value, path)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestDesktopErrorsExposeCodesAndProtectUnknownCauses(t *testing.T) {
	desktop := &Desktop{store: newTestStore(t)}
	_, err := desktop.CreateProject(ProjectInput{})
	var message apperror.Message
	if err == nil {
		t.Fatal("invalid project accepted")
	}
	if err := json.Unmarshal(marshalDesktopError(err), &message); err != nil {
		t.Fatal(err)
	}
	if message.Code != "project_name_invalid" {
		t.Fatalf("validation lost its structured error: %+v", message)
	}

	private := errors.New("private diagnostic must not reach the WebView")
	desktop.openBrowser = func(string) error { return private }
	err = desktop.OpenExternal("https://github.com/retail-ai-inc/vulman")
	if err == nil || !errors.Is(err, private) || strings.Contains(err.Error(), "private diagnostic") || strings.Contains(string(marshalDesktopError(err)), "private diagnostic") {
		t.Fatal("the desktop boundary exposed the diagnostic or lost the Go cause")
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
