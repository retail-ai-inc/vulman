package engine

import (
	"net/http"
	"reflect"
	"testing"

	"vulman/internal/model"
)

func TestStartupRecognizesPreviousVersionFindingsWithoutDiscardingHistory(t *testing.T) {
	s := testStore(t)
	findings := []model.Finding{
		{ID: "CVE-old", AssetID: "changed", Component: "demo", Version: "1", Severity: "CRITICAL"},
		{ID: "CVE-current", AssetID: "unchanged", Component: "other", Version: "2", Severity: "HIGH"},
		{ID: "CVE-scanner", AssetID: "unchanged", Component: "dependency", Version: "1", Match: "scanner"},
	}
	runs := []model.Run{{ID: "previous", Status: "complete", Count: len(findings)}}
	if err := s.Update(func(st *model.State) error {
		st.Projects = []model.Project{{
			ID: "p", Revision: 2, AssessedRevision: 1,
			Assets: []model.Asset{
				{ID: "changed", Name: "demo", Version: "2"},
				{ID: "unchanged", Name: "other", Version: "2"},
			},
			Findings: findings, Runs: runs,
		}}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	e, err := New(s)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(e.Close)
	st, err := s.Read()
	if err != nil {
		t.Fatal(err)
	}

	project := st.Projects[0]
	if !project.Assets[0].NeedsAssessment || project.Assets[1].NeedsAssessment {
		t.Fatalf("incorrect component freshness after startup: %+v", project.Assets)
	}

	if !reflect.DeepEqual(project.Findings, findings) || !reflect.DeepEqual(project.Runs, runs) {
		t.Fatal("startup changed previous findings or workflow history")
	}
}

func TestComponentAssessmentStatusClearsOnlyForSuccessfulCompleteSeverityScope(t *testing.T) {
	for _, tc := range []struct {
		name, assetID, severity     string
		fail                        bool
		firstPending, secondPending bool
	}{
		{name: "component", assetID: "a", secondPending: true},
		{name: "full project"},
		{name: "severity filtered", assetID: "a", severity: "CRITICAL", firstPending: true, secondPending: true},
		{name: "failed", assetID: "a", fail: true, firstPending: true, secondPending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, e := controlEngine(t)
			if err := s.Update(func(st *model.State) error {
				p := &st.Projects[0]
				p.Assets[0].NeedsAssessment = true
				p.Assets = append(p.Assets, model.Asset{ID: "b", Name: "other", Version: "1", Ecosystem: "npm", NeedsAssessment: true})
				return nil
			}); err != nil {
				t.Fatal(err)
			}

			e.Sources.HTTP.Transport = controlTransport(func(*http.Request) (*http.Response, error) {
				response := controlResponse(`{"vulns":[]}`)
				if tc.fail {
					response.StatusCode = http.StatusForbidden
				}

				return response, nil
			})
			if err := e.StartFiltered("p", "manual", tc.assetID, "auto", tc.severity); err != nil {
				t.Fatal(err)
			}

			project := awaitRun(t, s)
			if project.Assets[0].NeedsAssessment != tc.firstPending || project.Assets[1].NeedsAssessment != tc.secondPending {
				t.Fatalf("incorrect reassessment status after %s: %+v", tc.name, project.Assets)
			}
		})
	}
}
