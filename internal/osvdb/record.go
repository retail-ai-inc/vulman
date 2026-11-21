// Package osvdb maintains ecosystem-scoped encrypted OSV catalogues.
package osvdb

import (
	"regexp"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"vulman/internal/apperror"
)

const Filename = "vulman-osv.db"
const DefaultEndpoint = "https://api.osv.dev/v1/query"

var ecosystemName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+\-]{0,79}$`)
var recordID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:\-]{0,199}$`)
var pythonSeparator = regexp.MustCompile(`[-_.]+`)

// Options are bundled so opening Configuration never starts a network request.
var Ecosystems = []string{"AlmaLinux", "Alpaquita", "Alpine", "Android", "Azure Linux", "BellSoft Hardened Containers", "Bitnami", "CRAN", "Chainguard", "CleanStart", "Debian", "Docker Hardened Images", "Echo", "GHC", "GIT", "GSD", "GitHub Actions", "Go", "Hackage", "Hex", "Julia", "Linux", "Mageia", "Maven", "MinimOS", "NuGet", "OSS-Fuzz", "Packagist", "Pub", "PyPI", "Red Hat", "Red Hat Lightwell", "Rocky Linux", "Root", "RubyGems", "SUSE", "SwiftURL", "TuxCare", "UVI", "Ubuntu", "VSCode", "Wolfi", "crates.io", "npm", "opam", "openEuler", "openSUSE"}

type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

type Affected struct {
	Package  struct{ Name, Ecosystem string } `json:"package"`
	Versions []string                         `json:"versions"`
	Ranges   []struct {
		Type   string  `json:"type"`
		Events []Event `json:"events"`
	} `json:"ranges"`
	EcosystemSpecific struct {
		Severity string `json:"severity"`
	} `json:"ecosystem_specific"`
}

type Record struct {
	SchemaVersion string     `json:"schema_version"`
	ID            string     `json:"id"`
	Modified      time.Time  `json:"modified"`
	Withdrawn     string     `json:"withdrawn"`
	Summary       string     `json:"summary"`
	Details       string     `json:"details"`
	Aliases       []string   `json:"aliases"`
	Affected      []Affected `json:"affected"`
	References    []struct {
		URL string `json:"url"`
	} `json:"references"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func supportedSchema(value string) bool {
	return value == "" || semver.IsValid("v"+value) && semver.Major("v"+value) == "v1"
}

func Ecosystem(value string) (string, error) {
	base, suffix, variant := strings.Cut(strings.TrimSpace(value), ":")
	if !ecosystemName.MatchString(base) || strings.Contains(base, "..") || variant && (!ecosystemName.MatchString(suffix) || strings.Contains(suffix, "..")) {
		return "", apperror.New("invalid_osv_ecosystem", "invalid OSV ecosystem")
	}

	return base, nil
}

func PackageName(ecosystem, name string) string {
	switch ecosystem {
	case "PyPI":
		return pythonSeparator.ReplaceAllString(strings.ToLower(name), "-")
	case "NuGet", "Packagist":
		return strings.ToLower(name)
	}

	return name
}

// Match returns uncertainty when the local catalogue cannot prove applicability.
// Explicit affected versions and ranges are a union under the OSV schema.
func Match(record Record, ecosystem, name, version string) (bool, bool) {
	if record.Withdrawn != "" {
		return false, false
	}

	uncertain := false
	for _, affected := range record.Affected {
		if affected.Package.Ecosystem != ecosystem || PackageName(ecosystem, affected.Package.Name) != PackageName(ecosystem, name) {
			continue
		}

		for _, candidate := range affected.Versions {
			if candidate == version {
				return true, false
			}
		}

		for _, r := range affected.Ranges {
			if r.Type != "SEMVER" {
				uncertain = true
				continue
			}

			matched, known := matchSemver(version, r.Events)
			if matched && known {
				return true, false
			}

			uncertain = uncertain || !known
		}

		if len(affected.Ranges) == 0 && len(affected.Versions) == 0 {
			uncertain = true
		}
	}

	return false, uncertain
}

func matchSemver(version string, events []Event) (bool, bool) {
	v := "v" + strings.TrimPrefix(version, "v")
	if !semver.IsValid(v) || len(events) == 0 {
		return false, false
	}

	inside, matched, open := false, false, false
	previous := ""
	for _, event := range events {
		values := []string{event.Introduced, event.Fixed, event.LastAffected, event.Limit}
		count, bound := 0, ""
		for _, value := range values {
			if value != "" {
				count++
				bound = value
			}
		}

		if count != 1 {
			return false, false
		}

		if event.Introduced == "0" {
			if open || previous != "" {
				return false, false
			}

			inside, open = true, true
			continue
		}

		if event.Limit == "*" {
			if !open {
				return false, false
			}

			continue
		}

		boundary := "v" + bound
		if !semver.IsValid(boundary) || previous != "" && semver.Compare(boundary, previous) < 0 {
			return false, false
		}

		previous = boundary
		if event.Introduced != "" {
			if open {
				return false, false
			}

			inside = semver.Compare(v, boundary) >= 0
			open = true
		} else {
			if !open {
				return false, false
			}

			cmp := semver.Compare(v, boundary)
			matched = matched || inside && (cmp < 0 || cmp == 0 && event.LastAffected != "")
			inside, open = false, false
		}
	}

	return matched || inside, true
}
