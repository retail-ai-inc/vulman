package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"vulman/internal/model"
)

// Benchmarks use disposable workspaces and synthetic findings. Encryption,
// transaction durability, and cache limits use the normal production settings.
func BenchmarkWorkspace(b *testing.B) {
	for _, count := range []int{1000, 10000, 50000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			s, err := Open(b.TempDir())
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := s.Close(); err != nil {
					b.Error(err)
				}
			})

			state := model.Defaults()
			project := model.Project{ID: "synthetic", Name: "Synthetic benchmark project", Runs: []model.Run{{ID: "benchmark", Status: "running"}}}
			project.Findings = make([]model.Finding, count)
			for i := range project.Findings {
				project.Findings[i] = model.Finding{
					ID: fmt.Sprintf("CVE-2026-%06d", i), AssetID: "demo", Component: "Example component", Version: "1.0",
					Title: "Example dependency vulnerability with affected version constraints", Severity: "HIGH", Score: 7.5,
					Description: strings.Repeat("Synthetic advisory description with affected version details. ", 4),
					Sources:     []string{"NVD", "CVE"}, References: []string{"https://example.com/advisory"}, Match: "review",
				}
			}
			state.Projects = []model.Project{project}
			if err := s.Update(func(next *model.State) error { *next = state; return nil }); err != nil {
				b.Fatal(err)
			}

			plain, err := json.Marshal(state)
			if err != nil {
				b.Fatal(err)
			}
			_, version, err := s.ReadSnapshot("")
			if err != nil {
				b.Fatal(err)
			}

			b.Run("UnchangedSnapshot", func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					if snapshot, _, err := s.ReadSnapshot(version); err != nil || snapshot != nil {
						b.Fatalf("unchanged snapshot returned data or failed: %v", err)
					}
				}
			})
			b.Run("ChangedSnapshot", func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(plain)))
				for b.Loop() {
					if _, _, err := s.ReadSnapshot(""); err != nil {
						b.Fatal(err)
					}
				}
			})
			initial, err := s.ReadChanges("")
			if err != nil {
				b.Fatal(err)
			}
			if err := s.UpdateRun("synthetic", "benchmark", func(_ *RunProject, run *model.Run) error { run.Count++; return nil }); err != nil {
				b.Fatal(err)
			}
			b.Run("IncrementalSnapshot", func(b *testing.B) {
				b.ReportAllocs()
				var response ChangeSet
				for b.Loop() {
					response, err = s.ReadChanges(initial.Version)
					if err != nil || response.Full != nil || response.Delta == nil {
						b.Fatalf("incremental snapshot failed: %v", err)
					}
				}
				data, err := json.Marshal(response.Delta)
				if err != nil {
					b.Fatal(err)
				}
				b.ReportMetric(float64(len(data)), "delta-bytes/op")
			})
			b.Run("ProgressUpdate", func(b *testing.B) {
				b.ReportAllocs()
				before := s.db.Stats()
				for b.Loop() {
					if err := s.UpdateRun("synthetic", "benchmark", func(_ *RunProject, run *model.Run) error {
						run.Count++
						return nil
					}); err != nil {
						b.Fatal(err)
					}
				}
				after := s.db.Stats()
				b.ReportMetric(float64(after.TxStats.GetPageAlloc()-before.TxStats.GetPageAlloc())/float64(b.N), "db-page-bytes/op")
			})
			b.Run("FullStateUpdate", func(b *testing.B) {
				b.ReportAllocs()
				before := s.db.Stats()
				for b.Loop() {
					if err := s.Update(func(next *model.State) error {
						next.Projects[0].Runs[0].Count++
						return nil
					}); err != nil {
						b.Fatal(err)
					}
				}
				after := s.db.Stats()
				b.ReportMetric(float64(after.TxStats.GetPageAlloc()-before.TxStats.GetPageAlloc())/float64(b.N), "db-page-bytes/op")
			})
		})
	}
}
