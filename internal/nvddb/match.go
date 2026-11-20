package nvddb

import (
	"regexp"
	"strings"

	"vulman/internal/apperror"
)

type certainty uint8

const (
	no certainty = iota
	yes
	unknown
)

func parseCPE(name string) ([]string, error) {
	var parts []string
	var part strings.Builder
	escaped := false
	for _, r := range name {
		if r == ':' && !escaped {
			parts = append(parts, part.String())
			part.Reset()
			continue
		}
		part.WriteRune(r)
		if escaped {
			escaped = false
		} else {
			escaped = r == '\\'
		}
	}
	parts = append(parts, part.String())
	if escaped || len(parts) != 13 || parts[0] != "cpe" || parts[1] != "2.3" {
		return nil, apperror.New("invalid_cpe_2_3_name", "invalid CPE 2.3 name")
	}
	for _, field := range parts[2:] {
		if field == "" {
			return nil, apperror.New("empty_cpe_field", "empty CPE field")
		}
	}
	return parts[2:], nil
}

func productKey(parts []string) string {
	for _, field := range parts[:3] {
		if strings.ContainsAny(field, "*?\\") {
			return "product:*"
		}
	}
	return "product:" + strings.ToLower(strings.Join(parts[:3], "\x00"))
}

func fieldMatch(pattern, value string) certainty {
	if pattern == "*" {
		return yes
	}
	if value == "*" {
		return unknown
	}
	if !strings.ContainsAny(pattern, "*?\\") && !strings.ContainsAny(value, "*?\\") {
		if strings.EqualFold(pattern, value) {
			return yes
		}
		return no
	}
	if pattern == "-" || value == "-" {
		if pattern == value {
			return yes
		}
		return no
	}
	var expr strings.Builder
	expr.WriteString("(?i)^")
	escaped := false
	for _, r := range pattern {
		if escaped {
			expr.WriteString(regexp.QuoteMeta(string(r)))
			escaped = false
			continue
		}
		switch r {
		case '\\':
			escaped = true
		case '*':
			expr.WriteString(".*")
		case '?':
			expr.WriteByte('.')
		default:
			expr.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	expr.WriteByte('$')
	if escaped {
		return unknown
	}
	var literal strings.Builder
	escaped = false
	for _, r := range value {
		if !escaped && r == '\\' {
			escaped = true
			continue
		}
		if !escaped && (r == '*' || r == '?') {
			return unknown
		}
		literal.WriteRune(r)
		escaped = false
	}
	matched, err := regexp.MatchString(expr.String(), literal.String())
	if err != nil {
		return unknown
	}
	if matched {
		return yes
	}
	return no
}

// Only numeric dotted versions have an ecosystem-independent ordering here.
// Other version schemes remain uncertain and can use the NVD API fallback.
func compareVersion(a, b string) (int, bool) {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	x, y := strings.Split(a, "."), strings.Split(b, ".")
	for _, version := range [][]string{x, y} {
		for _, part := range version {
			if part == "" {
				return 0, false
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					return 0, false
				}
			}
		}
	}
	for i := 0; i < max(len(x), len(y)); i++ {
		left, right := "", ""
		if i < len(x) {
			left = strings.TrimLeft(x[i], "0")
		}
		if i < len(y) {
			right = strings.TrimLeft(y[i], "0")
		}
		if len(left) < len(right) {
			return -1, true
		}
		if len(left) > len(right) {
			return 1, true
		}
		if cmp := strings.Compare(left, right); cmp != 0 {
			return cmp, true
		}
	}
	return 0, true
}

func criteriaMatch(m Criteria, target []string) certainty {
	parts, err := parseCPE(m.Name)
	if err != nil {
		return unknown
	}
	result := yes
	for i := range parts {
		match := fieldMatch(parts[i], target[i])
		if match == no {
			return no
		}
		if match == unknown {
			result = unknown
		}
	}
	for _, bound := range []struct {
		value            string
		lower, inclusive bool
	}{
		{m.StartIncluding, true, true}, {m.StartExcluding, true, false}, {m.EndIncluding, false, true}, {m.EndExcluding, false, false},
	} {
		if bound.value == "" {
			continue
		}
		cmp, ok := compareVersion(target[3], bound.value)
		if !ok {
			result = unknown
			continue
		}
		if bound.lower && (cmp < 0 || cmp == 0 && !bound.inclusive) || !bound.lower && (cmp > 0 || cmp == 0 && !bound.inclusive) {
			return no
		}
	}
	return result
}

func matchRecord(r Record, target []string) certainty {
	result := no
	var visit func([]Node, bool)
	visit = func(nodes []Node, conditional bool) {
		for _, n := range nodes {
			// An AND/negated configuration can depend on deployment information
			// absent from this component. Keep it eligible for remote validation.
			uncertain := conditional || n.Negate || strings.EqualFold(n.Operator, "AND")
			for _, m := range n.Matches {
				if !m.Vulnerable {
					continue
				}
				match := criteriaMatch(m, target)
				if match == yes && !uncertain {
					result = yes
				}
				if match != no && result != yes {
					result = unknown
				}
			}
			visit(n.Nodes, uncertain)
			visit(n.Children, uncertain)
		}
	}
	visit(r.Configurations, false)
	return result
}
