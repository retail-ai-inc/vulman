// Package cvedb maintains the shared, encrypted CVE catalogue independently of
// project state. Records are addressed by CVE ID rather than decoded as a list.
package cvedb

import (
	"encoding/json"
	"regexp"
	"time"

	"vulman/internal/apperror"
)

const Filename = "vulman-cve.db"

var validID = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

type Record struct {
	ID         string    `json:"id"`
	State      string    `json:"state"`
	Title      string    `json:"title,omitempty"`
	References []string  `json:"references,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
	CheckedAt  time.Time `json:"checked_at"`
}

// Parse retains the fields used for enrichment, including rejection state.
func Parse(data []byte) (Record, error) {
	type container struct {
		Title      string
		References []struct{ URL string }
	}
	var raw struct {
		Metadata struct {
			ID      string `json:"cveId"`
			State   string
			Updated string `json:"dateUpdated"`
		} `json:"cveMetadata"`
		Containers struct {
			CNA container
			ADP []container
		}
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return Record{}, err
	}
	if !validID.MatchString(raw.Metadata.ID) || (raw.Metadata.State != "PUBLISHED" && raw.Metadata.State != "REJECTED") {
		return Record{}, apperror.New("invalid_cve_record_identity_or_state", "invalid CVE record identity or state")
	}
	var updated time.Time
	if raw.Metadata.Updated != "" {
		var err error
		updated, err = time.Parse(time.RFC3339Nano, raw.Metadata.Updated)
		if err != nil {
			// Some original records omit the UTC suffix.
			updated, err = time.Parse("2006-01-02T15:04:05.999999999", raw.Metadata.Updated)
		}
		if err != nil {
			return Record{}, apperror.New("invalid_cve_modification_date", "invalid CVE modification date")
		}
	}
	r := Record{ID: raw.Metadata.ID, State: raw.Metadata.State, UpdatedAt: updated, Title: raw.Containers.CNA.Title}
	seen := make(map[string]bool)
	for _, c := range append([]container{raw.Containers.CNA}, raw.Containers.ADP...) {
		for _, ref := range c.References {
			if ref.URL != "" && !seen[ref.URL] {
				seen[ref.URL] = true
				r.References = append(r.References, ref.URL)
			}
		}
	}
	return r, nil
}

func newer(a, b Record) bool {
	// Release/observation order remains authoritative when upstream corrects a
	// modification date backwards or omits the optional dateUpdated field.
	if !a.CheckedAt.Equal(b.CheckedAt) {
		return a.CheckedAt.After(b.CheckedAt)
	}
	return a.UpdatedAt.After(b.UpdatedAt)
}
