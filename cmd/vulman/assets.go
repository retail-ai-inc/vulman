//go:build !server

package main

import (
	"embed"
	"io/fs"
	"net/http"

	"github.com/wailsapp/wails/v3/pkg/application"
)

//go:embed ui
var assets embed.FS

func assetHandler() (http.Handler, error) {
	ui, err := fs.Sub(assets, "ui")
	if err != nil {
		return nil, err
	}
	handler := application.BundledAssetFileServer(ui)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		handler.ServeHTTP(w, r)
	}), nil
}
