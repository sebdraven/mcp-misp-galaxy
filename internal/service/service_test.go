package service

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sebdraven/mcp-misp-galaxy/internal/galaxy"
)

func TestParseNormalisationAcceptsKnownModes(t *testing.T) {
	cases := map[string]galaxy.Normalisation{
		"":           galaxy.Standard, // omitted by the caller
		"standard":   galaxy.Standard,
		"Standard":   galaxy.Standard,
		"  standard": galaxy.Standard,
		"aggressive": galaxy.Aggressive,
		"AGGRESSIVE": galaxy.Aggressive,
	}
	for in, want := range cases {
		got, err := parseNormalisation(in)
		if err != nil {
			t.Errorf("parseNormalisation(%q) returned %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("parseNormalisation(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseNormalisationRejectsUnknownMode(t *testing.T) {
	// The failure this guards against is silent: defaulting a misspelt mode to
	// standard returns a plausible answer under the wrong folding, and the
	// caller reads it as "aggressive found nothing extra".
	for _, in := range []string{"agressive", "loose", "true", "1"} {
		if _, err := parseNormalisation(in); !errors.Is(err, ErrUnknownNormalisation) {
			t.Errorf("parseNormalisation(%q) error = %v, want ErrUnknownNormalisation", in, err)
		}
	}
}

func writeFixture(t *testing.T, path string, body map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshalling fixture: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
}

// selectorService serves threat-actor (named-threat / actor) and firearms,
// whose definition declares no category, both holding an entry named Fancy.
func selectorService(t *testing.T, scope []string) *Service {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	galaxies := filepath.Join(root, "galaxies")
	for _, d := range []string{clusters, galaxies} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for gt, id := range map[string]string{"threat-actor": "ta-1", "firearms": "fa-1"} {
		writeFixture(t, filepath.Join(clusters, gt+".json"), map[string]any{
			"type": gt, "name": gt, "uuid": gt + "-uuid",
			"values": []map[string]any{{"value": "Fancy", "uuid": id}},
		})
	}
	writeFixture(t, filepath.Join(galaxies, "threat-actor.json"), map[string]any{
		"type": "threat-actor", "name": "Threat Actor", "uuid": "ta-def",
		"category": "named-threat", "sub_category": "actor",
	})
	writeFixture(t, filepath.Join(galaxies, "firearms.json"), map[string]any{
		"type": "firearms", "name": "Firearms", "uuid": "fa-def",
	})

	g, err := galaxy.Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	h := &galaxy.Holder{}
	h.Set(g)
	return &Service{holder: h, scope: normaliseScope(scope)}
}

func TestResolveExpandsScopeSelectors(t *testing.T) {
	svc := selectorService(t, []string{"sub_category:actor"})
	res, err := svc.Resolve("Fancy", nil, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Count != 1 || res.Candidates[0].UUID != "ta-1" {
		t.Fatalf("expected only the threat-actor entry, got %+v", res.Candidates)
	}
	if want := []string{"threat-actor"}; !reflect.DeepEqual(res.Scope, want) {
		t.Errorf("scope = %q, want the expanded %q", res.Scope, want)
	}
}

func TestResolveSelectorUnionWithNames(t *testing.T) {
	svc := selectorService(t, nil)
	res, err := svc.Resolve("Fancy", []string{"category:named-threat", "firearms"}, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Count != 2 {
		t.Fatalf("expected both entries, got %+v", res.Candidates)
	}
}

func TestResolveUnresolvedSelectorSearchesNothing(t *testing.T) {
	svc := selectorService(t, nil)
	res, err := svc.Resolve("Fancy", []string{"category:victim"}, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Count != 0 {
		t.Errorf("a selector matching nothing must not widen to the corpus, got %+v", res.Candidates)
	}
	if want := []string{"category:victim"}; !reflect.DeepEqual(res.Scope, want) {
		t.Errorf("scope = %q, want %q", res.Scope, want)
	}
	if len(res.OutOfScope) != 2 {
		t.Errorf("out_of_scope = %+v, want both galaxies", res.OutOfScope)
	}
}

func TestResolvedScopeReportsUnresolved(t *testing.T) {
	svc := selectorService(t, []string{"category:victim", "sub_category:actor", "nope"})
	got, unresolved, err := svc.ResolvedScope()
	if err != nil {
		t.Fatalf("ResolvedScope: %v", err)
	}
	if want := []string{"category:victim", "nope"}; !reflect.DeepEqual(unresolved, want) {
		t.Errorf("unresolved = %q, want %q", unresolved, want)
	}
	if want := []string{"category:victim", "threat-actor", "nope"}; !reflect.DeepEqual(got, want) {
		t.Errorf("scope = %q, want %q", got, want)
	}
}

func TestResolveReportsUnresolvedSelectorInCall(t *testing.T) {
	svc := selectorService(t, nil)
	res, err := svc.Resolve("Fancy", []string{"category:named_threat"}, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"category:named_threat"}; !reflect.DeepEqual(res.UnresolvedScope, want) {
		t.Errorf("unresolved_scope = %q, want %q", res.UnresolvedScope, want)
	}
}

func TestResolveReportsUnknownGalaxyName(t *testing.T) {
	svc := selectorService(t, nil)
	res, err := svc.Resolve("Fancy", []string{"threat-actr", "threat-actor"}, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"threat-actr"}; !reflect.DeepEqual(res.UnresolvedScope, want) {
		t.Errorf("unresolved_scope = %q, want %q", res.UnresolvedScope, want)
	}
	if res.Count != 1 {
		t.Errorf("the resolved part of the scope must still be searched, got %+v", res.Candidates)
	}
}

func TestResolveReportsUnresolvedDefaultScope(t *testing.T) {
	svc := selectorService(t, []string{"category:named_threat", "firearms"})
	res, err := svc.Resolve("Fancy", nil, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if want := []string{"category:named_threat"}; !reflect.DeepEqual(res.UnresolvedScope, want) {
		t.Errorf("unresolved_scope = %q, want %q", res.UnresolvedScope, want)
	}
}

func TestFuzzyNoteLeadsWithUnresolvedScope(t *testing.T) {
	svc := selectorService(t, nil)
	res, err := svc.Fuzzy("Fancy", []string{"sub_category:actr"}, nil, 0)
	if err != nil {
		t.Fatalf("Fuzzy: %v", err)
	}
	if want := []string{"sub_category:actr"}; !reflect.DeepEqual(res.UnresolvedScope, want) {
		t.Errorf("unresolved_scope = %q, want %q", res.UnresolvedScope, want)
	}
	if !strings.HasPrefix(res.Note, unresolvedScopeNote) {
		t.Errorf("note should open on the unresolved scope, got %q", res.Note)
	}
	if !strings.Contains(res.Note, "see out_of_scope") {
		t.Errorf("the out-of-scope note must still follow, got %q", res.Note)
	}
}

func TestNeighboursAndCompareReportUnresolvedScope(t *testing.T) {
	svc := selectorService(t, nil)
	nb, err := svc.Neighbours("ta-1", galaxy.NeighbourOpts{Galaxies: []string{"category:named_threat"}})
	if err != nil {
		t.Fatalf("Neighbours: %v", err)
	}
	if want := []string{"category:named_threat"}; !reflect.DeepEqual(nb.UnresolvedScope, want) {
		t.Errorf("neighbours unresolved_scope = %q, want %q", nb.UnresolvedScope, want)
	}
	cmp, err := svc.Compare("ta-1", "fa-1", galaxy.CompareOpts{Galaxies: []string{"nope"}})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if want := []string{"nope"}; !reflect.DeepEqual(cmp.UnresolvedScope, want) {
		t.Errorf("compare unresolved_scope = %q, want %q", cmp.UnresolvedScope, want)
	}
}

func TestUnresolvedScopeAbsentWhenEverythingResolves(t *testing.T) {
	svc := selectorService(t, []string{"sub_category:actor", "firearms"})
	res, err := svc.Resolve("Fancy", nil, 0, false, "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	fz, err := svc.Fuzzy("Fancy", nil, nil, 0)
	if err != nil {
		t.Fatalf("Fuzzy: %v", err)
	}
	nb, err := svc.Neighbours("ta-1", galaxy.NeighbourOpts{Galaxies: []string{"category:named-threat"}})
	if err != nil {
		t.Fatalf("Neighbours: %v", err)
	}
	cmp, err := svc.Compare("ta-1", "fa-1", galaxy.CompareOpts{})
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	for name, v := range map[string]any{"resolve": res, "fuzzy": fz, "neighbours": nb, "compare": cmp} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshalling %s: %v", name, err)
		}
		if strings.Contains(string(raw), "unresolved_scope") {
			t.Errorf("%s: unresolved_scope should be omitted, got %s", name, raw)
		}
	}
	if strings.HasPrefix(fz.Note, unresolvedScopeNote) {
		t.Errorf("fuzzy note should not mention an unresolved scope, got %q", fz.Note)
	}
}
