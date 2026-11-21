package nvddb

import "testing"

func TestCPEMatchingRangesEscapesAndUncertainVersions(t *testing.T) {
	target, err := parseCPE(testCPE)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		criteria Criteria
		want     certainty
	}{
		{"exact", Criteria{Name: testCPE}, yes},
		{"inclusive", Criteria{Name: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", StartIncluding: "1.26.0", EndIncluding: "1.26.1"}, yes},
		{"exclusive", Criteria{Name: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", EndExcluding: "1.26.0"}, no},
		{"unrelated", Criteria{Name: "cpe:2.3:a:other:go:*:*:*:*:*:*:*:*"}, no},
		{"prerelease", Criteria{Name: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", EndExcluding: "1.27rc1"}, unknown},
		{"out-of-range-despite-prerelease", Criteria{Name: "cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", StartIncluding: "1.0rc1", EndExcluding: "1.20.0"}, no},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := criteriaMatch(tc.criteria, target); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
	if fieldMatch(`foo\:bar`, `foo\:bar`) != yes || fieldMatch("foo*", "foobar") != yes || fieldMatch("windows", "*") != unknown {
		t.Fatal("CPE escapes or logical values were matched incorrectly")
	}
	r := Record{Configurations: []Node{{Operator: "AND", Nodes: []Node{{Matches: []Criteria{{Vulnerable: true, Name: testCPE}}}}}}}
	if matchRecord(r, target) != unknown {
		t.Fatal("conditional applicability was treated as confirmed")
	}
	r.Configurations[0].Operator = "OR"
	if matchRecord(r, target) != yes {
		t.Fatal("simple applicability did not match")
	}
	r.Configurations[0].Negate = true
	if matchRecord(r, target) != unknown {
		t.Fatal("negated applicability was treated as confirmed")
	}
}
