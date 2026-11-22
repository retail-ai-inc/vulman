package osvdb

import (
	"encoding/json"
	"testing"
)

func TestComposerVersionOrderAndUnknownBranches(t *testing.T) {
	for _, pair := range [][2]string{
		{"v1.2", "1.2.0.0"}, {"1.2.3+build.5", "1.2.3"}, {"1.2.3a1", "1.2.3-alpha.1"}, {"1.2.3-PL2", "1.2.3-patch2"}, {"1.2.3-stable", "1.2.3"},
	} {
		if result, known := compareComposer(pair[0], pair[1]); !known || result != 0 {
			t.Errorf("equal Composer tags differ: %v: %d, %v", pair, result, known)
		}
	}
	versions := []string{"1.2.3-dev", "1.2.3-alpha1-dev", "1.2.3-alpha1", "1.2.3-alpha2", "1.2.3-beta1", "1.2.3-RC1", "1.2.3", "1.2.3-p1", "1.2.3.1", "1.2.10", "2.0"}
	for i := 1; i < len(versions); i++ {
		if result, known := compareComposer(versions[i-1], versions[i]); !known || result >= 0 {
			t.Errorf("wrong Composer tag order: %s, %s", versions[i-1], versions[i])
		}
	}
	for _, value := range []string{"dev-main", "1.2.x-dev", "^1.2", "1.2 || 2.0", "1.0.0 as 2.0.0", "invalid", ""} {
		if _, known := compareComposer(value, "1.2.0"); known {
			t.Errorf("unsupported Composer version was guessed: %q", value)
		}
	}
}

func TestPackagistEcosystemRangesAndBoundaries(t *testing.T) {
	var record Record
	if err := json.Unmarshal([]byte(`{"id":"GHSA-test","affected":[{"package":{"ecosystem":"Packagist","name":"vendor/package"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.2.3"},{"introduced":"2.0.0"},{"last_affected":"2.0.1"}]}]}]}`), &record); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		matched bool
		unknown bool
	}{
		{"v1.2.2", true, false}, {"1.2.3-RC1", true, false}, {"1.2.3", false, false},
		{"1.2.3.1", false, false}, {"2.0", true, false}, {"2.0.1", true, false}, {"2.0.2", false, false},
		{"dev-main", false, true}, {"2.0.x-dev", false, true},
	} {
		matched, unknown := Match(record, "Packagist", "Vendor/Package", tc.version)
		if matched != tc.matched || unknown != tc.unknown {
			t.Errorf("%s: match=%v uncertain=%v", tc.version, matched, unknown)
		}
	}
	record.Affected[0].Versions = []string{"dev-main"}
	if matched, unknown := Match(record, "Packagist", "vendor/package", "dev-main"); !matched || unknown {
		t.Fatal("explicit branch version was not matched")
	}
	record.Affected[0].Ranges[0].Events = []Event{{Introduced: "2.0.0"}, {Fixed: "1.0.0"}}
	if _, unknown := Match(record, "Packagist", "vendor/package", "1.5.0"); !unknown {
		t.Fatal("malformed Composer range was treated as definitive")
	}
}
