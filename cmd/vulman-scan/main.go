package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"vulman/internal/apperror"
	"vulman/internal/model"
	"vulman/internal/scanner"
	"vulman/internal/sources"
)

type toolResult struct {
	Name     string `json:"name"`
	Path     string `json:"path,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Status   string `json:"status"`
	Findings *int   `json:"findings,omitempty"`
	Error    string `json:"error,omitempty"`
}

type scanReport struct {
	Status   string          `json:"status"`
	Scanners []toolResult    `json:"scanners"`
	Findings []model.Finding `json:"findings"`
	Warnings []string        `json:"warnings"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	logger := log.New(stderr, "vulman-scan: ", 0)
	flags := flag.NewFlagSet("vulman-scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dir := flags.String("dir", "", "local repository folder (defaults to the current folder)")
	repo := flags.String("repo", "", "HTTPS GitHub repository URL")
	list := flags.String("scanners", "", "comma-separated tools: "+strings.Join(scanner.Names(), ",")+" (required)")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 || (*dir != "" && *repo != "") {
		logger.Print("use either --dir or --repo, and pass no positional arguments")
		return 2
	}
	enabled, err := selectedTools(*list)
	if err != nil {
		logger.Print(err)
		return 2
	}
	project := model.Project{Repository: *repo}
	if *repo != "" {
		err = model.ValidateRepositoryURL(*repo)
	} else {
		project.LocalPath, err = filepath.Abs(*dir)
	}
	if err != nil {
		logger.Print(err)
		return 2
	}

	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	settings := model.EffectiveSettings(model.Settings{Scanners: enabled})
	report := scan(ctx, project, settings)
	if err := json.NewEncoder(stdout).Encode(report); err != nil {
		logger.Print(err)
		return 2
	}
	if report.Status != "complete" {
		return 2
	}
	if len(report.Findings) > 0 {
		return 1
	}
	return 0
}

func selectedTools(list string) (map[string]bool, error) {
	if strings.TrimSpace(list) == "" {
		return nil, errors.New("select at least one tool with --scanners")
	}
	enabled := map[string]bool{}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if !scanner.Supported(name) {
			return nil, fmt.Errorf("unknown scanner %q", name)
		}
		enabled[name] = true
	}
	return enabled, nil
}

func scan(ctx context.Context, project model.Project, settings model.Settings) scanReport {
	report := scanReport{Status: "complete", Warnings: []string{}}
	positions := map[string]int{}
	project.ScannerProfiles = map[string]model.ScannerProfile{}
	for _, target := range scanner.TargetKeys(project) {
		project.ScannerProfiles[target] = model.ScannerProfile{Mode: "custom", Tools: scanner.EnabledTools(settings.Scanners)}
	}
	completed := 0
	findings, warnings := scanner.Scan(ctx, project, settings, "", func(event scanner.ScanEvent) {
		for _, job := range event.Plan {
			if !settings.Scanners[job.Tool] {
				continue
			}
			key := job.Tool + ":" + job.Path
			positions[key] = len(report.Scanners)
			report.Scanners = append(report.Scanners, toolResult{Name: job.Tool, Path: job.Path, Status: job.Status, Reason: job.Reason})
		}
		if !settings.Scanners[event.Tool] {
			return
		}
		key := event.Tool + ":" + event.Path
		position, found := positions[key]
		if !found {
			positions[key] = len(report.Scanners)
			position = len(report.Scanners)
			report.Scanners = append(report.Scanners, toolResult{Name: event.Tool, Path: event.Path, Status: "planned"})
		}
		result := &report.Scanners[position]
		if event.Job != nil {
			result.Status, result.Reason = event.Job.Status, event.Job.Reason
		}
		switch event.Phase {
		case "scanner_completed":
			completed++
			result.Status, result.Findings = "complete", &event.Found
		case "scanner_failed":
			result.Status, result.Error = "failed", apperror.Public(event.Err).English()
		case "scanner_interrupted":
			result.Status, result.Error = "interrupted", apperror.Public(event.Err).English()
		case "scanner_missing_token", "scanner_blocked":
			result.Error = apperror.Public(event.Err).English()
		}
	})
	// The CLI accepts one target, so its component IDs remain stable.
	for i := range findings {
		findings[i].AssetID = scanner.FindingAssetID("", findings[i].ScanPath, findings[i].Component)
	}
	report.Findings = sources.Merge(findings)
	report.Warnings = append(report.Warnings, warnings...)
	if ctx.Err() != nil {
		report.Status = "interrupted"
	} else if len(warnings) > 0 || completed == 0 {
		report.Status = "failed"
		if completed > 0 {
			report.Status = "partial"
		}
	}
	return report
}
