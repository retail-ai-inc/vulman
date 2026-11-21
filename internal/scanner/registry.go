package scanner

import (
	"context"
	"os/exec"
	"slices"

	"vulman/internal/model"
)

// Definition is the shared catalogue used by matching, profiles, availability
// checks, and the desktop. Commands and parsers remain application-owned code.
type Definition struct {
	ID        string     `json:"id"`
	Label     string     `json:"label"`
	Scope     string     `json:"scope"`
	Detect    []string   `json:"detect,omitempty"`
	Inputs    [][]string `json:"inputs,omitempty"`
	Token     string     `json:"token,omitempty"`
	DocsURL   string     `json:"docs_url"`
	build     func(context.Context, string, *scanScratch) (*exec.Cmd, string, error)
	probe     func(context.Context) (*exec.Cmd, error)
	parse     func([]byte) ([]model.Finding, error)
	exitCodes []int
}

var registry = []Definition{
	{ID: "govulncheck", exitCodes: []int{0, 1, 3}, Label: "govulncheck", Scope: "manifest", Detect: []string{"go.mod"}, Inputs: [][]string{{"go.mod"}}, DocsURL: "https://go.dev/doc/security/vuln/",
		build: simpleCommand(func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "govulncheck", "-json", "./..."), nil
		}),
		probe: func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "govulncheck", "-help"), nil
		}, parse: parseGoVulncheck},
	{ID: "npm", exitCodes: []int{0, 1}, Label: "npm audit", Scope: "manifest", Detect: []string{"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"}, Inputs: [][]string{{"package.json"}, {"package-lock.json", "npm-shrinkwrap.json"}}, DocsURL: "https://docs.npmjs.com/cli/commands/npm-audit/",
		build: simpleCommand(func(ctx context.Context) (*exec.Cmd, error) {
			return newNPMCommand(ctx, "audit", "--json", "--ignore-scripts")
		}),
		probe: func(ctx context.Context) (*exec.Cmd, error) { return newNPMCommand(ctx, "--version") }, parse: parseNPM},
	{ID: "composer", exitCodes: []int{0, 1}, Label: "composer audit", Scope: "manifest", Detect: []string{"composer.json", "composer.lock"}, Inputs: [][]string{{"composer.json"}, {"composer.lock"}}, DocsURL: "https://getcomposer.org/doc/03-cli.md#audit",
		build: simpleCommand(func(ctx context.Context) (*exec.Cmd, error) {
			return newComposerCommand(ctx, "--no-plugins", "--no-scripts", "--no-interaction", "audit", "--locked", "--format=json")
		}),
		probe: func(ctx context.Context) (*exec.Cmd, error) {
			return newComposerCommand(ctx, "--no-plugins", "--no-scripts", "--no-interaction", "--version")
		}, parse: parseComposer},
	{ID: "pip-audit", exitCodes: []int{0, 1}, Label: "pip-audit", Scope: "manifest", Detect: []string{"requirements.txt", "pyproject.toml", "pylock.toml", "pylock.*.toml"}, Inputs: [][]string{{"requirements.txt", "pylock.toml", "pylock.*.toml"}}, DocsURL: "https://github.com/pypa/pip-audit",
		build: newPipAuditCommand, probe: func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "pip-audit", "--version"), nil
		}, parse: parsePipAudit},
	{ID: "trivy", exitCodes: []int{0}, Label: "Trivy", Scope: "repository", DocsURL: "https://trivy.dev/",
		build: simpleCommand(func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "trivy", "fs", "--format", "json", "--scanners", "vuln", "--quiet", "."), nil
		}),
		probe: func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "trivy", "--version"), nil
		}, parse: parseTrivy},
	{ID: "snyk", exitCodes: []int{0, 1}, Label: "Snyk", Scope: "repository", Token: "snyk", DocsURL: "https://docs.snyk.io/developer-tools/snyk-cli",
		build: simpleCommand(func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "snyk", "test", "--all-projects", "--fail-fast", "--json"), nil
		}),
		probe: func(ctx context.Context) (*exec.Cmd, error) {
			return exec.CommandContext(ctx, "snyk", "--version"), nil
		}, parse: parseSnyk},
}

func simpleCommand(build func(context.Context) (*exec.Cmd, error)) func(context.Context, string, *scanScratch) (*exec.Cmd, string, error) {
	return func(ctx context.Context, dir string, _ *scanScratch) (*exec.Cmd, string, error) {
		cmd, err := build(ctx)
		return cmd, dir, err
	}
}

func Definitions() []Definition {
	definitions := slices.Clone(registry)
	for i := range definitions {
		definitions[i].Detect = slices.Clone(definitions[i].Detect)
		definitions[i].Inputs = slices.Clone(definitions[i].Inputs)
		for j := range definitions[i].Inputs {
			definitions[i].Inputs[j] = slices.Clone(definitions[i].Inputs[j])
		}
	}
	return definitions
}

func Names() []string {
	names := make([]string, 0, len(registry))
	for _, definition := range registry {
		names = append(names, definition.ID)
	}
	return names
}

func definition(id string) (Definition, bool) {
	for _, definition := range registry {
		if definition.ID == id {
			return definition, true
		}
	}
	return Definition{}, false
}
