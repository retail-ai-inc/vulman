package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"
)

//go:embed locales/*.json
var localeFiles embed.FS

type Localization struct {
	Name     string            `json:"name"`
	Locale   string            `json:"locale,omitempty"`
	Messages map[string]string `json:"messages"`
}

var bundledLocalizations = sync.OnceValues(func() (map[string]Localization, error) {
	return readLocalizations(localeFiles)
})

func readLocalizations(files fs.FS) (map[string]Localization, error) {
	paths, err := fs.Glob(files, "locales/*.json")
	if err != nil {
		return nil, err
	}

	localizations := make(map[string]Localization, len(paths))

	for _, filename := range paths {
		data, err := fs.ReadFile(files, filename)
		if err != nil {
			return nil, err
		}

		var locale Localization
		if err := json.Unmarshal(data, &locale); err != nil {
			return nil, fmt.Errorf("invalid localization %s: %w", filename, err)
		}

		code := strings.TrimSuffix(path.Base(filename), ".json")
		if code == "" || strings.TrimSpace(locale.Name) == "" || len(locale.Messages) == 0 {
			return nil, fmt.Errorf("localization %s requires a language code, name, and messages", filename)
		}

		localizations[code] = locale
	}

	if _, ok := localizations["en"]; !ok {
		return nil, errors.New("the English localization is required")
	}

	return localizations, nil
}

// Localizations loads the bundled desktop language catalogs.
func (d *Desktop) Localizations() (map[string]Localization, error) {
	return bundledLocalizations()
}
