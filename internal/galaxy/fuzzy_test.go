package galaxy

import (
	"os"
	"path/filepath"
	"testing"
)

// fuzzyGraph carries the pairs that matter: a genuine typo, a numbered family
// whose members must stay apart, and two actors attributed to different
// countries.
func fuzzyGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{"value": "Kimsuky", "uuid": "a-kimsuky", "meta": map[string]any{"country": "KP"}},
		{"value": "APT28", "uuid": "a-apt28", "meta": map[string]any{"country": "RU"}},
		{"value": "APT29", "uuid": "a-apt29", "meta": map[string]any{"country": "RU"}},
		{"value": "Callisto", "uuid": "a-callisto", "meta": map[string]any{"country": "RU"}},
		// The misspelling the naming literature documents, and a country its own
		// catalogue disagrees on — one letter apart, two different entities.
		{"value": "Calisto", "uuid": "a-calisto", "meta": map[string]any{"country": "CN"}},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestFuzzyFindsTypos(t *testing.T) {
	// The case the feature exists for: a misspelling that exact matching and
	// prefix matching both miss.
	g := fuzzyGraph(t)
	got := g.FuzzyResolve("Kimsuki", FuzzyOpts{})
	if len(got) == 0 {
		t.Fatal("expected the misspelling to reach Kimsuky")
	}
	if got[0].UUID != "a-kimsuky" {
		t.Errorf("expected Kimsuky first, got %+v", got)
	}
	if got[0].Signals.JaroWinkler < 0.9 {
		t.Errorf("a single-character typo should score high on Jaro-Winkler, got %v",
			got[0].Signals.JaroWinkler)
	}
}

func TestFuzzyKeepsNumberedFamiliesApart(t *testing.T) {
	// The failure this design guards against. Every string metric rates
	// APT28 against APT29 above 0.9 — they differ by one character — so
	// without a signal that reads the digits, the tool would confidently
	// propose two different Russian actors as the same entity.
	g := fuzzyGraph(t)
	got := g.FuzzyResolve("APT28", FuzzyOpts{})

	for _, m := range got {
		if m.UUID != "a-apt29" {
			continue
		}
		if m.Signals.DigitMatch != 0 {
			t.Errorf("differing digits must score 0, got %v", m.Signals.DigitMatch)
		}
		t.Errorf("APT29 should fall below the default threshold, scored %v", m.Similarity)
	}
}

func TestFuzzyDigitSignalIsDecisive(t *testing.T) {
	// Verifies the mechanism rather than only its effect: on the string
	// signals alone the pair is close, and it is the digit signal that pulls
	// the composite under the floor.
	sig := scoreName("apt28", "apt29")
	if sig.JaroWinkler < 0.9 {
		t.Fatalf("fixture assumption broken: apt28/apt29 should look alike to Jaro-Winkler, got %v",
			sig.JaroWinkler)
	}
	if sig.DigitMatch != 0 {
		t.Errorf("digit signal = %v, want 0 for differing numbers", sig.DigitMatch)
	}
	if sig.composite() >= FuzzyThreshold {
		t.Errorf("composite = %v, should fall below the %v threshold",
			sig.composite(), FuzzyThreshold)
	}

	// And the same names with the same number stay together.
	same := scoreName("apt28", "apt 28")
	if same.DigitMatch != 1 {
		t.Errorf("identical digits should score 1, got %v", same.DigitMatch)
	}
}

func TestFuzzyHardConflictBlocksDespiteScore(t *testing.T) {
	// The guard the entity-resolution literature insists on: a documented
	// disagreement on a discriminating attribute is never overridden by a
	// similarity score. Callisto and Calisto are one letter apart, and their
	// catalogues place them in different countries.
	g := fuzzyGraph(t)
	got := g.FuzzyResolve("Callisto", FuzzyOpts{})

	var found bool
	for _, m := range got {
		if m.UUID != "a-calisto" {
			continue
		}
		found = true
		if !m.Blocked {
			t.Error("a country conflict must block the match whatever it scored")
		}
		if m.BlockedReason == "" {
			t.Error("a blocked match must say why")
		}
	}
	if !found {
		t.Fatalf("the conflicting entry should still be returned, flagged; got %+v", got)
	}
	// Blocked entries sort last, so a caller reading top-down is not misled.
	if len(got) > 1 && got[0].Blocked {
		t.Error("a blocked match should not lead the results")
	}
}

func TestAbbreviationNeedsARealAbbreviation(t *testing.T) {
	// The documented bug worth not repeating: a scorer that accepted any
	// shared first letter rated "Michael Cruz" against "Mario Chavez" at 0.92
	// and produced 79 false positives.
	if got := abbreviationConfidence("michaelcruz", "mariochavez"); got != 0 {
		t.Errorf("shared first letters are not an abbreviation, got %v", got)
	}
	// A genuine one still matches: a single-letter token standing for a word.
	if got := abbreviationConfidence("e petrov", "elena petrov"); got != 1 {
		t.Errorf("a real abbreviation should score 1, got %v", got)
	}
}

func TestFuzzyExcludesExactMatches(t *testing.T) {
	// Exact matching is Resolve's job; returning the same entry here would
	// present a certainty as an approximation.
	g := fuzzyGraph(t)
	for _, m := range g.FuzzyResolve("Kimsuky", FuzzyOpts{}) {
		if m.UUID == "a-kimsuky" {
			t.Error("an exact match should not appear among fuzzy results")
		}
	}
}

func TestFuzzyEmptyQuery(t *testing.T) {
	g := fuzzyGraph(t)
	if got := g.FuzzyResolve("   ", FuzzyOpts{}); got != nil {
		t.Errorf("an empty query should match nothing, got %+v", got)
	}
}

func TestFuzzyRespectsScope(t *testing.T) {
	g := fuzzyGraph(t)
	if got := g.FuzzyResolve("Kimsuki", FuzzyOpts{Galaxies: []string{"malpedia"}}); len(got) != 0 {
		t.Errorf("a scope excluding the galaxy should find nothing, got %+v", got)
	}
}
