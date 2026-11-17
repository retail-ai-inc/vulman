package sources

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"vulman/internal/model"
	"vulman/internal/store"
)

type Client struct {
	HTTP        *http.Client
	mu          sync.Mutex
	nextNVD     time.Time
	Cache       *store.Store
	flightsMu   sync.Mutex
	flights     map[string]*flight
	gatesMu     sync.Mutex
	gates       map[string]*providerGate
	retryBase   time.Duration
	gapOverride map[string]time.Duration
}

func New(caches ...*store.Store) *Client {
	c := &Client{HTTP: &http.Client{Timeout: 45 * time.Second}, flights: map[string]*flight{}, gates: map[string]*providerGate{}, retryBase: time.Second}
	if len(caches) > 0 {
		c.Cache = caches[0]
	}
	return c
}

func notify(reports []func(model.SyncProgress), p model.SyncProgress) {
	for _, report := range reports {
		if report != nil {
			report(p)
		}
	}
}

func (c *Client) pace(ctx context.Context, key string, reports ...func(model.SyncProgress)) error {
	c.mu.Lock()
	delay := time.Until(c.nextNVD)
	if delay < 0 {
		delay = 0
	}
	gap := 6100 * time.Millisecond
	if key != "" {
		gap = 650 * time.Millisecond
	}
	c.nextNVD = time.Now().Add(delay + gap)
	c.mu.Unlock()
	if delay == 0 {
		return nil
	}
	notify(reports, model.SyncProgress{Phase: "waiting", WaitSeconds: int((delay + time.Second - 1) / time.Second)})
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type nvdMetric struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}
type nvdRecord struct {
	ID           string                         `json:"id"`
	VulnStatus   string                         `json:"vulnStatus"`
	Descriptions []struct{ Lang, Value string } `json:"descriptions"`
	References   []struct {
		URL string `json:"url"`
	} `json:"references"`
	Metrics map[string][]nvdMetric `json:"metrics"`
}

func (c *Client) fetchNVD(ctx context.Context, a model.Asset, s model.Settings, reports ...func(model.SyncProgress)) ([]model.Finding, error) {
	out := []model.Finding{}
	start := 0
	for page := 0; page < 50; page++ {
		notify(reports, model.SyncProgress{Phase: "request"})
		u, err := url.Parse(s.NVDURL)
		if err != nil {
			return out, err
		}
		q := u.Query()
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", fmt.Sprint(start))
		q.Set("noRejected", "")
		match := "review"
		if a.CPE != "" {
			q.Set("cpeName", a.CPE)
			q.Set("isVulnerable", "")
			match = "cpe"
		} else {
			q.Set("keywordSearch", a.Name)
			q.Set("keywordExactMatch", "")
		}
		u.RawQuery = q.Encode()
		var data struct {
			TotalResults    *int `json:"totalResults"`
			Vulnerabilities []struct {
				CVE nvdRecord `json:"cve"`
			} `json:"vulnerabilities"`
		}
		headers := map[string]string{}
		if s.Tokens["nvd"] != "" {
			headers["apiKey"] = s.Tokens["nvd"]
		}
		if err = c.request(ctx, "GET", u.String(), nil, headers, &data); err != nil {
			return out, err
		}
		if data.TotalResults == nil || *data.TotalResults < 0 {
			return out, fmt.Errorf("NVD returned an invalid result envelope")
		}
		for _, item := range data.Vulnerabilities {
			v := item.CVE
			if v.ID == "" {
				return out, fmt.Errorf("NVD returned an advisory without an identifier")
			}
			if strings.EqualFold(v.VulnStatus, "Rejected") {
				continue
			}
			f := model.Finding{ID: v.ID, AssetID: a.ID, Component: a.Name, Version: a.Version, Severity: "UNKNOWN", Sources: []string{"NVD"}, Match: match, References: []string{}, FixedVersions: []string{}}
			for _, d := range v.Descriptions {
				if d.Lang == "en" {
					f.Description = d.Value
					break
				}
			}
			f.Title = f.Description
			if len(f.Title) > 180 {
				f.Title = truncate(f.Title, 180) + "…"
			}
			for _, k := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
				if ms := v.Metrics[k]; len(ms) > 0 {
					f.Score = ms[0].CVSSData.BaseScore
					f.Severity = model.Severity(f.Score)
					break
				}
			}
			for _, r := range v.References {
				f.References = Unique(f.References, r.URL)
			}
			out = append(out, f)
		}
		start += len(data.Vulnerabilities)
		notify(reports, model.SyncProgress{Phase: "page", Processed: start, Total: *data.TotalResults, Found: len(out)})
		if start >= *data.TotalResults {
			return out, nil
		}
		if len(data.Vulnerabilities) == 0 {
			return out, fmt.Errorf("NVD pagination stopped before all results were returned")
		}
	}
	return out, fmt.Errorf("NVD result limit reached; narrow the query using an exact CPE")
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

type cveContainer struct {
	Title        string                         `json:"title"`
	Descriptions []struct{ Lang, Value string } `json:"descriptions"`
	References   []struct{ URL string }         `json:"references"`
	Solutions    []struct{ Lang, Value string } `json:"solutions"`
}

// CVE enriches identifiers discovered through NVD/OSV with the CNA record.
// It deliberately preserves match confidence: an advisory is not proof of exposure.
func (c *Client) fetchCVE(ctx context.Context, id string, s model.Settings) (string, []string, error) {
	var data struct {
		CVEMetadata struct{ State string } `json:"cveMetadata"`
		Containers  struct {
			CNA cveContainer   `json:"cna"`
			ADP []cveContainer `json:"adp"`
		} `json:"containers"`
	}
	if !strings.HasPrefix(id, "CVE-") {
		return "", nil, nil
	}
	if err := c.request(ctx, "GET", strings.TrimRight(s.CVEURL, "/")+"/"+url.PathEscape(id), nil, nil, &data); err != nil {
		return "", nil, err
	}
	if data.CVEMetadata.State == "REJECTED" {
		return "", nil, ErrRejected
	}
	if data.CVEMetadata.State != "PUBLISHED" {
		return "", nil, fmt.Errorf("CVE returned an invalid record")
	}
	refs := []string{}
	for _, container := range append([]cveContainer{data.Containers.CNA}, data.Containers.ADP...) {
		for _, r := range container.References {
			refs = Unique(refs, r.URL)
		}
	}
	return data.Containers.CNA.Title, refs, nil
}

type osvRecord struct {
	ID, Summary, Details string
	Withdrawn            string   `json:"withdrawn"`
	Aliases              []string `json:"aliases"`
	DatabaseSpecific     struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct{ URL string } `json:"references"`
	Affected   []struct {
		Package           struct{ Name, Ecosystem string } `json:"package"`
		EcosystemSpecific struct {
			Severity string `json:"severity"`
		} `json:"ecosystem_specific"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

func (c *Client) fetchOSV(ctx context.Context, a model.Asset, s model.Settings, reports ...func(model.SyncProgress)) ([]model.Finding, error) {
	out := []model.Finding{}
	if a.Ecosystem == "" {
		return out, fmt.Errorf("OSV skipped: ecosystem is required")
	}
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 100; page++ {
		notify(reports, model.SyncProgress{Phase: "request"})
		var data struct {
			Vulns []osvRecord `json:"vulns"`
			Next  string      `json:"next_page_token"`
			Error any         `json:"error"`
		}
		payload := map[string]any{"package": map[string]string{"name": a.Name, "ecosystem": a.Ecosystem}, "version": a.Version, "page_token": token}
		if err := c.request(ctx, "POST", s.OSVURL, payload, nil, &data); err != nil {
			return out, err
		}
		if data.Error != nil {
			return out, fmt.Errorf("OSV returned an error response")
		}
		for _, v := range data.Vulns {
			if v.ID == "" {
				return out, fmt.Errorf("OSV returned an advisory without an identifier")
			}
			if v.Withdrawn != "" {
				continue
			}
			sev := strings.ToUpper(v.DatabaseSpecific.Severity)
			f := model.Finding{ID: v.ID, AssetID: a.ID, Component: a.Name, Version: a.Version, Title: v.Summary, Description: v.Details, Severity: sev, Sources: []string{"OSV"}, Match: "package", Aliases: v.Aliases, References: []string{}, FixedVersions: []string{}}
			if f.Title == "" {
				f.Title = truncate(v.Details, 180)
			}
			for _, alias := range v.Aliases {
				if strings.HasPrefix(alias, "CVE-") {
					f.ID = alias
					break
				}
			}
			for _, r := range v.References {
				f.References = Unique(f.References, r.URL)
			}
			for _, a2 := range v.Affected {
				if a2.Package.Name != a.Name || a2.Package.Ecosystem != a.Ecosystem {
					continue
				}
				if f.Severity == "" {
					f.Severity = strings.ToUpper(a2.EcosystemSpecific.Severity)
				}
				for _, r := range a2.Ranges {
					if r.Type == "GIT" {
						continue
					}
					for _, e := range r.Events {
						if e.Fixed != "" {
							f.FixedVersions = Unique(f.FixedVersions, e.Fixed)
						}
					}
				}
			}
			if f.Severity == "MODERATE" {
				f.Severity = "MEDIUM"
			}
			if model.Rank(f.Severity) == 1 {
				f.Severity = "UNKNOWN"
			}
			out = append(out, f)
		}
		notify(reports, model.SyncProgress{Phase: "page", Processed: len(out), Found: len(out)})
		if data.Next == "" {
			return out, nil
		}
		if seen[data.Next] {
			return out, fmt.Errorf("OSV repeated a pagination token")
		}
		seen[data.Next] = true
		token = data.Next
	}
	return out, fmt.Errorf("OSV pagination limit reached")
}

func Unique(values []string, more ...string) []string {
	for _, v := range more {
		if v == "" {
			continue
		}
		found := false
		for _, old := range values {
			if old == v {
				found = true
				break
			}
		}
		if !found {
			values = append(values, v)
		}
	}
	return values
}

func Merge(all []model.Finding) []model.Finding {
	out := []model.Finding{}
	index := map[string]int{}
	for _, f := range all {
		key := f.AssetID + "/" + f.ID
		if i, ok := index[key]; ok {
			old := &out[i]
			old.Sources = Unique(old.Sources, f.Sources...)
			old.References = Unique(old.References, f.References...)
			old.FixedVersions = Unique(old.FixedVersions, f.FixedVersions...)
			old.Aliases = Unique(old.Aliases, f.Aliases...)
			if model.Rank(f.Severity) > model.Rank(old.Severity) {
				old.Severity = f.Severity
			}
			if f.Score > old.Score {
				old.Score = f.Score
			}
			if old.Match == "review" && f.Match != "review" {
				old.Match = f.Match
			}
			if old.Title == "" {
				old.Title = f.Title
			}
		} else {
			index[key] = len(out)
			out = append(out, f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if model.Rank(out[i].Severity) != model.Rank(out[j].Severity) {
			return model.Rank(out[i].Severity) > model.Rank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
