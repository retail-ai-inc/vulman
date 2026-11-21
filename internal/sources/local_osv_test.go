package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"vulman/internal/model"
	"vulman/internal/osvdb"
	"vulman/internal/store"
	"vulman/internal/testutil"
)

func TestLocalOSVMatchingAndExplicitFallbackModes(t *testing.T) {
	for _, unsupported := range []bool{false, true} {
		t.Run(fmt.Sprint(unsupported), func(t *testing.T) {
			s, err := store.Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := s.Close(); err != nil {
					t.Error(err)
				}
			})
			db, err := s.OpenOSVDatabase()
			if err != nil {
				t.Fatal(err)
			}
			u := osvdb.NewUpdater(db)
			t.Cleanup(func() {
				if err := u.Close(); err != nil {
					t.Error(err)
				}
			})
			rangeType := "SEMVER"
			if unsupported {
				rangeType = "ECOSYSTEM"
			}
			raw := json.RawMessage(fmt.Sprintf(`{"id":"GO-test","modified":%q,"aliases":["CVE-2026-1234"],"summary":"OSV advisory","database_specific":{"severity":"HIGH"},"affected":[{"package":{"name":"demo","ecosystem":"Go"},"ranges":[{"type":%q,"events":[{"introduced":"0"},{"fixed":"2.0.0"}]}]}]}`, time.Now().UTC().Add(-10*24*time.Hour).Format(time.RFC3339Nano), rangeType))
			u.HTTP.Transport = testutil.NewOSVTransport(t, "Go", []json.RawMessage{raw})
			if err := u.Start(context.Background(), []string{"Go"}); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(3 * time.Second)
			for {
				stats, err := u.Stats()
				if err != nil {
					t.Fatal(err)
				}
				if !stats.Running {
					if stats.Phase != "complete" {
						t.Fatalf("initial import: %+v", stats)
					}
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("import did not finish")
				}
				time.Sleep(5 * time.Millisecond)
			}

			client := New(s)
			client.LocalOSV = db
			var calls atomic.Int32
			client.HTTP.Transport = localOSVTransport(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"vulns":[` + string(raw) + `]}`))}, nil
			})
			settings := model.Defaults().Settings
			asset := model.Asset{ID: "component", Name: "demo", Version: "1.0.0", Ecosystem: "Go"}
			items, err := client.OSV(WithMode(context.Background(), "local"), asset, settings)
			if calls.Load() != 0 || len(items) != 1 || items[0].ID != "CVE-2026-1234" || items[0].AssetID != "component" {
				t.Fatalf("local lookup: %+v %v", items, err)
			}
			if unsupported {
				if err == nil || items[0].Match != "review" {
					t.Fatal("unsupported version was treated as verified")
				}
				items, err = client.OSV(context.Background(), asset, settings)
				if err != nil || len(items) != 1 || calls.Load() != 1 {
					t.Fatal("unsupported version did not use API validation")
				}
			} else {
				if err != nil || items[0].Match != "package" {
					t.Fatal("local version match failed")
				}
				asset.Version = "3.0.0"
				items, err = client.OSV(context.Background(), asset, settings)
				if err != nil || len(items) != 0 || calls.Load() != 0 {
					t.Fatal("fixed version matched or triggered an API request")
				}
				asset.Version = "1.0.0"
				if _, err := client.OSV(WithMode(context.Background(), "refresh"), asset, settings); err != nil || calls.Load() != 1 {
					t.Fatal("force refresh did not use API")
				}
				settings.OSVURL = "https://custom.example.test/query"
				if _, err := client.OSV(context.Background(), asset, settings); err != nil || calls.Load() != 2 {
					t.Fatal("custom endpoint incorrectly used local catalogue")
				}
			}
		})
	}
}

type localOSVTransport func(*http.Request) (*http.Response, error)

func (f localOSVTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
