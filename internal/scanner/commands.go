package scanner

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"slices"
	"strings"

	"vulman/internal/apperror"
	"vulman/internal/model"
)

var scannerNames = Names()

func Supported(name string) bool {
	_, ok := definition(name)
	return ok
}

func newScannerCommand(ctx context.Context, name string) (*exec.Cmd, error) {
	item, ok := definition(name)
	if !ok || name == "pip-audit" {
		return nil, apperror.Newf("scanner_unsupported", "unsupported scanner %q", name)
	}
	cmd, _, err := item.build(ctx, "", nil)
	return cmd, err
}

const githubAuthHeaderEnv = "VULMAN_GITHUB_AUTH_HEADER"

func newCloneCommand(ctx context.Context, repository, destination, token string) (*exec.Cmd, error) {
	cloneURL, err := model.GitHubCloneURL(repository)
	if err != nil {
		return nil, err
	}
	args := []string{"-c", "core.hooksPath=" + os.DevNull}
	if token != "" {
		args = append(args, "--config-env=http.https://github.com/.extraHeader="+githubAuthHeaderEnv,
			"-c", "http.https://github.com/.followRedirects=false", "-c", "http.https://github.com/.sslVerify=true")
	}
	args = append(args, "clone", "--depth", "1", "--no-recurse-submodules", "--", cloneURL, destination)
	// #nosec G204 -- Fixed Git options precede the validated GitHub URL and app-generated destination after --.
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = slices.DeleteFunc(scannerEnvironment(), func(entry string) bool {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		switch key {
		case "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_TEMPLATE_DIR", "GIT_CURL_VERBOSE", "GIT_SSL_NO_VERIFY":
			return true
		}
		return strings.HasPrefix(key, "GIT_TRACE") || strings.HasPrefix(key, "GIT_CONFIG")
	})
	if token != "" {
		// Scope the token to this Git process tree.
		header := base64.StdEncoding.EncodeToString([]byte("x-access-token:" + token))
		cmd.Env = append(cmd.Env, githubAuthHeaderEnv+"=Authorization: Basic "+header)
	}
	return cmd, nil
}
