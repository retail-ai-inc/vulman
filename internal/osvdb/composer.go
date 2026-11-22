package osvdb

import (
	"cmp"
	"regexp"
	"strings"
)

// Composer tags allow four numeric components and named stability suffixes.
// Branch aliases and date-based tags stay uncertain rather than being guessed.
var composerTag = regexp.MustCompile(`(?i)^v?(\d{1,5})(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?(?:[._-]?(stable|alpha|a|beta|b|rc|patch|pl|p)([.-]?\d+(?:[.-]\d+)*)?)?([.-]?dev)?(?:\+[0-9a-z.-]+)?$`)

type composerVersion struct {
	parts [4]string
	stage int
	build []string
	dev   bool
}

func parseComposerVersion(value string) (composerVersion, bool) {
	var version composerVersion
	if len(value) > 200 {
		return version, false
	}
	parts := composerTag.FindStringSubmatch(value)
	if parts == nil {
		return version, false
	}
	copy(version.parts[:], parts[1:5])
	version.stage = 4
	if strings.EqualFold(parts[5], "stable") {
		return version, true
	}
	switch strings.ToLower(parts[5]) {
	case "alpha", "a":
		version.stage = 1
	case "beta", "b":
		version.stage = 2
	case "rc":
		version.stage = 3
	case "patch", "pl", "p":
		version.stage = 5
	}
	version.build = strings.FieldsFunc(parts[6], func(r rune) bool { return r == '.' || r == '-' })
	if parts[7] != "" {
		if parts[5] == "" {
			version.stage = 0
		} else {
			version.dev = true
		}
	}
	return version, true
}

func compareComposer(a, b string) (int, bool) {
	left, ok := parseComposerVersion(a)
	if !ok {
		return 0, false
	}
	right, ok := parseComposerVersion(b)
	if !ok {
		return 0, false
	}
	compareNumber := func(a, b string) int {
		a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
		if result := cmp.Compare(len(a), len(b)); result != 0 {
			return result
		}
		return strings.Compare(a, b)
	}
	for i := range left.parts {
		if result := compareNumber(left.parts[i], right.parts[i]); result != 0 {
			return result, true
		}
	}
	if result := cmp.Compare(left.stage, right.stage); result != 0 {
		return result, true
	}
	for i := 0; i < max(len(left.build), len(right.build)); i++ {
		var a, b string
		if i < len(left.build) {
			a = left.build[i]
		}
		if i < len(right.build) {
			b = right.build[i]
		}
		if result := compareNumber(a, b); result != 0 {
			return result, true
		}
	}
	if left.dev != right.dev {
		if left.dev {
			return -1, true
		}
		return 1, true
	}
	return 0, true
}

func matchComposer(version string, events []Event) (bool, bool) {
	if _, ok := parseComposerVersion(version); !ok {
		return false, false
	}
	return matchVersionRange(version, events, compareComposer)
}
