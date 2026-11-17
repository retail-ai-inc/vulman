package model

import (
	"slices"
	"testing"
)

func TestValidateInventory(t *testing.T) {
	base := func() Project {
		return Project{Name: "App", Schedule: "daily", Assets: []Asset{{Kind: "library", Name: "log4j", Version: "2.14.1", CPE: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"}}}
	}
	p := base()
	if err := ValidateProject(&p); err != nil {
		t.Fatal(err)
	}
	if p.Assets[0].ID == "" {
		t.Fatal("asset ID missing")
	}
	for name, mutate := range map[string]func(*Project){"missing version": func(p *Project) { p.Assets[0].Version = "" }, "wrong CPE version": func(p *Project) { p.Assets[0].Version = "2.17.1" }, "repository injection": func(p *Project) { p.Repository = "--upload-pack=bad" }, "SSH repository": func(p *Project) { p.Repository = "ssh://git@example.com/project" }, "schedule": func(p *Project) { p.Schedule = "every second" }} {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(&p)
			if ValidateProject(&p) == nil {
				t.Fatal("invalid project accepted")
			}
		})
	}
}

func TestEnvironmentOverridesStoredToken(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "environment")
	s := Defaults().Settings
	s.Tokens["openai"] = "stored"
	effective := EffectiveSettings(s)
	if effective.Tokens["openai"] != "environment" || s.Tokens["openai"] != "stored" {
		t.Fatal("environment resolution mutated persisted settings")
	}
}

func TestProjectRepositoryURLs(t *testing.T) {
	first := "https://github.com/owner/first.git"
	second := "https://github.com/owner/second.git"
	p := Project{Name: "Demo", Schedule: "off", Repository: first, ScanCode: true}
	if !slices.Equal(p.Repositories(), []string{first}) {
		t.Fatal("legacy repository URL was lost")
	}
	p.RepositoryURLs = []string{first, "", " " + second + " ", first}
	if err := ValidateProject(&p); err != nil {
		t.Fatal(err)
	}
	if p.Repository != first || !slices.Equal(p.Repositories(), []string{first, second}) {
		t.Fatalf("unexpected stored repositories: %+v", p.Repositories())
	}
	p.RepositoryURLs = []string{first, "https://gitlab.com/owner/repo"}
	if ValidateProject(&p) == nil {
		t.Fatal("non-GitHub URL was accepted in the repository list")
	}
	p.RepositoryURLs, p.ScanCode = []string{}, false
	if err := ValidateProject(&p); err != nil || p.Repository != "" || len(p.Repositories()) != 0 {
		t.Fatalf("explicit removal did not clear the legacy URL: %v", err)
	}
}

func TestGitHubCloneURL(t *testing.T) {
	for _, tc := range []struct{ input, expected string }{
		{"https://github.com/my-org/my.repo", "https://github.com/my-org/my.repo"},
		{"https://GITHUB.COM:443/my-org/my_repo.git/?tab=readme#overview", "https://github.com/my-org/my_repo.git"},
		{"https://github.com.example.test/owner/repo", ""},
		{"https://github.com@other.example/owner/repo", ""},
		{"https://user@github.com/owner/repo", ""},
		{"https://github.com:8443/owner/repo", ""},
		{"http://github.com/owner/repo", ""},
		{"https://github.com/owner", ""},
		{"https://github.com/owner/repo/tree/main", ""},
		{"https://github.com/owner/..", ""},
		{"https://github.com/owner/repo%2Ftree%2Fmain", ""},
	} {
		got, err := GitHubCloneURL(tc.input)
		if got != tc.expected || (err != nil) != (tc.expected == "") {
			t.Errorf("GitHubCloneURL(%q) = %q, %v, want %q", tc.input, got, err, tc.expected)
		}
	}
}
