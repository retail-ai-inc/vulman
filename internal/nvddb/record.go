// Package nvddb stores NVD advisories and the CPE dictionary in an encrypted,
// indexed catalogue independent of project inventory and assessment history.
package nvddb

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"unicode"
)

const Filename = "vulman-nvd.db"
const DefaultEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

var cveID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

type Text struct{ Lang, Value string }
type Reference struct {
	URL string `json:"url"`
}
type Metric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}
type Criteria struct {
	Vulnerable     bool   `json:"vulnerable"`
	Name           string `json:"criteria"`
	ID             string `json:"matchCriteriaId"`
	StartIncluding string `json:"versionStartIncluding,omitempty"`
	StartExcluding string `json:"versionStartExcluding,omitempty"`
	EndIncluding   string `json:"versionEndIncluding,omitempty"`
	EndExcluding   string `json:"versionEndExcluding,omitempty"`
}
type Node struct {
	Operator string     `json:"operator,omitempty"`
	Negate   bool       `json:"negate,omitempty"`
	Matches  []Criteria `json:"cpeMatch,omitempty"`
	Nodes    []Node     `json:"nodes,omitempty"`
	Children []Node     `json:"children,omitempty"`
}
type Record struct {
	ID             string              `json:"id"`
	VulnStatus     string              `json:"vulnStatus"`
	Published      string              `json:"published,omitempty"`
	LastModified   string              `json:"lastModified,omitempty"`
	Descriptions   []Text              `json:"descriptions"`
	References     []Reference         `json:"references"`
	Metrics        map[string][]Metric `json:"metrics"`
	Configurations []Node              `json:"configurations,omitempty"`
}
type CPE struct {
	ID           string                         `json:"cpeNameId"`
	Name         string                         `json:"cpeName"`
	Deprecated   bool                           `json:"deprecated"`
	Titles       []struct{ Lang, Title string } `json:"titles"`
	LastModified string                         `json:"lastModified"`
	DeprecatedBy []struct {
		Name string `json:"cpeName"`
	} `json:"deprecatedBy,omitempty"`
}

func words(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsNumber(r) })
}

func description(r Record) string {
	var text strings.Builder
	for _, d := range r.Descriptions {
		text.WriteString(d.Value)
		text.WriteByte('\n')
	}
	return text.String()
}

// indexKeys is also used when replacing a record, so obsolete postings and the
// new record always change in the same transaction.
func indexKeys(kind string, raw json.RawMessage) (string, []string, error) {
	keys := map[string]bool{}
	var id, text string
	if kind == "nvd" {
		var r Record
		if err := json.Unmarshal(raw, &r); err != nil {
			return "", nil, err
		}
		if !cveID.MatchString(r.ID) {
			return "", nil, errors.New("invalid NVD CVE identity")
		}
		id = r.ID
		if !strings.EqualFold(r.VulnStatus, "Rejected") {
			text = description(r)
			var visit func([]Node) error
			visit = func(nodes []Node) error {
				for _, n := range nodes {
					for _, m := range n.Matches {
						if !m.Vulnerable {
							continue
						}
						parts, err := parseCPE(m.Name)
						if err != nil {
							return err
						}
						keys[productKey(parts)] = true
					}
					if err := visit(n.Nodes); err != nil {
						return err
					}
					if err := visit(n.Children); err != nil {
						return err
					}
				}
				return nil
			}
			if err := visit(r.Configurations); err != nil {
				return "", nil, err
			}
		}
	} else if kind == "cpe" {
		var c CPE
		if err := json.Unmarshal(raw, &c); err != nil {
			return "", nil, err
		}
		_, err := parseCPE(c.Name)
		if err != nil || c.ID == "" || len(c.ID) > 100 || strings.ContainsRune(c.ID, 0) {
			return "", nil, errors.New("invalid CPE dictionary record")
		}
		id = c.ID
		keys["name:"+strings.ToLower(c.Name)] = true
	} else {
		return "", nil, errors.New("invalid NVD dataset")
	}
	for _, word := range words(text) {
		if len(word) <= 256 {
			keys["word:"+word] = true
		}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	return id, result, nil
}
