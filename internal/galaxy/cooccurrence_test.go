package galaxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// nestedGraph reproduces what the literature actually measures: two techniques
// used by many of the same actors, and a third used by a different crowd.
//
// Ten actors use both "link" techniques; the same ten plus two others use the
// unrelated one. So the nested pair scores 1.0 and the other pairings 10/12.
func nestedGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	var actors []map[string]any
	for i := 0; i < 12; i++ {
		rel := []map[string]any{{"dest-uuid": "t-other", "type": "uses"}}
		if i < 10 {
			rel = append(rel,
				map[string]any{"dest-uuid": "t-link", "type": "uses"},
				map[string]any{"dest-uuid": "t-spear", "type": "uses"},
			)
		}
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Actor %02d", i), "uuid": fmt.Sprintf("a-%02d", i),
			"related": rel,
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Malicious Link", "uuid": "t-link"},
		{"value": "Spearphishing Link", "uuid": "t-spear"},
		{"value": "Something Unrelated", "uuid": "t-other"},
		// Linked to no actor at all, so it sits below any floor and is never
		// compared — which is what the exclusion tests check.
		{"value": "Barely Seen", "uuid": "t-rare"},
	})
	writeCluster(t, clusters, "mitre-malware", []map[string]any{
		{"value": "Family", "uuid": "m-1", "related": []map[string]any{
			{"dest-uuid": "t-link", "type": "uses"},
			{"dest-uuid": "t-spear", "type": "uses"},
			{"dest-uuid": "t-other", "type": "uses"},
			{"dest-uuid": "t-rare", "type": "uses"},
		}},
	})

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestCoOccurrenceAcrossAGalaxy(t *testing.T) {
	// Searching a whole galaxy is what the literature does, and the only way
	// to surface pairs that are shared across the corpus rather than sitting
	// next to any one entry.
	g := nestedGraph(t)

	link, _ := g.Node("t-link")
	other, _ := g.Node("t-other")
	if link.GroupCount != 10 || other.GroupCount != 12 {
		t.Fatalf("fixture broken: link=%d other=%d, want 10 and 12",
			link.GroupCount, other.GroupCount)
	}

	pairs := g.CoOccurrence(CoOccurrenceOpts{
		Galaxy: "mitre-attack-pattern", MinRate: CoOccurrenceThreshold, Limit: 10,
	})
	if len(pairs) == 0 {
		t.Fatal("expected the nested pair to surface")
	}
	top := pairs[0]
	if top.Rate != 1.0 || top.Shared != 10 {
		t.Errorf("top pair should be the fully-overlapping one, got rate %v shared %d",
			top.Rate, top.Shared)
	}
	// And it should be the two link techniques, not either of them with the
	// unrelated one.
	if !(top.AUUID == "t-link" && top.BUUID == "t-spear") &&
		!(top.AUUID == "t-spear" && top.BUUID == "t-link") {
		t.Errorf("expected the two nested techniques, got %s and %s", top.AUUID, top.BUUID)
	}
}

func TestCoOccurrenceExcludesThinlyDocumentedEntries(t *testing.T) {
	// The failure this guards against made the tool useless on real data:
	// entries with one actor each score 1.0 against anything sharing that
	// actor, so an implant documented for a single group turned every pair of
	// its techniques into apparent redundancy.
	//
	// The floor applies to each entry's own actor set, not to the overlap: two
	// well-documented entries may still share only a handful of actors.
	g := nestedGraph(t)

	rare, _ := g.Node("t-rare")
	if rare.GroupCount != 0 {
		t.Fatalf("fixture broken: t-rare has %d actors, want 0", rare.GroupCount)
	}
	pairs := g.CoOccurrence(CoOccurrenceOpts{
		Galaxy: "mitre-attack-pattern", MinRate: 0, Limit: 50,
	})
	if len(pairs) == 0 {
		t.Fatal("expected the well-documented techniques to still be compared")
	}
	for _, p := range pairs {
		if p.AUUID == "t-rare" || p.BUUID == "t-rare" {
			t.Errorf("an entry with no actor must not be compared: %+v", p)
		}
		if p.AGroup < MinCoOccurrenceActors || p.BGroup < MinCoOccurrenceActors {
			t.Errorf("an entry below the actor floor slipped through: %+v", p)
		}
	}
}

func TestCoOccurrenceMinActorsIsAdjustable(t *testing.T) {
	// Lowering the floor should let thinner entries back in — the caller may
	// want to see them, as long as the default protects them from doing it by
	// accident.
	//
	// t-thin shares its single actor with the others, so it can actually form
	// pairs once the floor drops; an entry that shared nobody would be filtered
	// out by the overlap check instead and prove nothing about the floor.
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	var actors []map[string]any
	for i := 0; i < 8; i++ {
		rel := []map[string]any{
			{"dest-uuid": "t-wide-a", "type": "uses"},
			{"dest-uuid": "t-wide-b", "type": "uses"},
		}
		if i == 0 {
			rel = append(rel, map[string]any{"dest-uuid": "t-thin", "type": "uses"})
		}
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Actor %d", i), "uuid": fmt.Sprintf("a-%d", i),
			"related": rel,
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Wide A", "uuid": "t-wide-a"},
		{"value": "Wide B", "uuid": "t-wide-b"},
		{"value": "Thin", "uuid": "t-thin"},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	thin, _ := g.Node("t-thin")
	if thin.GroupCount != 1 {
		t.Fatalf("fixture broken: t-thin has %d actors, want 1", thin.GroupCount)
	}

	strict := g.CoOccurrence(CoOccurrenceOpts{
		Galaxy: "mitre-attack-pattern", MinRate: 0, MinActors: 5, Limit: 50,
	})
	loose := g.CoOccurrence(CoOccurrenceOpts{
		Galaxy: "mitre-attack-pattern", MinRate: 0, MinActors: 1, Limit: 50,
	})
	if len(loose) <= len(strict) {
		t.Errorf("a lower floor should admit more pairs, got %d vs %d",
			len(loose), len(strict))
	}
	for _, p := range strict {
		if p.AUUID == "t-thin" || p.BUUID == "t-thin" {
			t.Errorf("the thin entry should be excluded at the default floor: %+v", p)
		}
	}
}

func TestCoOccurrenceDividesByLargerSet(t *testing.T) {
	// Dividing by the larger set is stricter than Jaccard: a smaller set nested
	// inside a bigger one must not score as though the two were equivalent.
	// 10 shared over the larger set of 12 is 0.833, not 10/12 of the union.
	g := nestedGraph(t)
	pairs := g.CoOccurrence(CoOccurrenceOpts{
		Galaxy: "mitre-attack-pattern", MinRate: 0, Limit: 50,
	})

	var found bool
	for _, p := range pairs {
		if p.AUUID == "t-other" || p.BUUID == "t-other" {
			found = true
			want := 10.0 / 12.0
			if p.Rate != want {
				t.Errorf("rate = %v, want %v (10 shared over the larger set of 12)", p.Rate, want)
			}
		}
	}
	if !found {
		t.Fatalf("expected a pair involving the wider technique, got %+v", pairs)
	}
}

func TestCoOccurrenceScopedToOneEntry(t *testing.T) {
	// The neighbourhood form still works, and answers a narrower question:
	// "in this profile, what am I counting twice?".
	//
	// Three pairs qualify here, not one: the unrelated technique still overlaps
	// the other two at 10/12, above the threshold. That is the measure working
	// as defined — a wide actor set overlaps almost anything — and the reason
	// the top pair, at a perfect 1.0, is the one worth reading.
	g := nestedGraph(t)
	pairs := g.CoOccurrence(CoOccurrenceOpts{
		UUID: "m-1", MinRate: CoOccurrenceThreshold, Limit: 10,
	})
	if len(pairs) != 3 {
		t.Fatalf("expected three qualifying pairs, got %+v", pairs)
	}
	top := pairs[0]
	if top.Rate != 1.0 {
		t.Errorf("the nested pair should rank first at 1.0, got %v", top.Rate)
	}
	if !(top.AUUID == "t-link" && top.BUUID == "t-spear") &&
		!(top.AUUID == "t-spear" && top.BUUID == "t-link") {
		t.Errorf("expected the two nested techniques on top, got %s and %s",
			top.AUUID, top.BUUID)
	}
	// The technique no actor is linked to is excluded whatever its overlap.
	for _, p := range pairs {
		if p.AUUID == "t-rare" || p.BUUID == "t-rare" {
			t.Errorf("the entry with no actor should not be compared: %+v", p)
		}
	}
}

func TestCoOccurrenceIgnoresActorsAsCandidates(t *testing.T) {
	// The measure is over behaviours co-observed across actors. An actor is
	// not a behaviour, and pairing two actors would answer a different
	// question entirely.
	g := nestedGraph(t)
	for _, p := range g.CoOccurrence(CoOccurrenceOpts{UUID: "a-00", MinRate: 0, Limit: 50}) {
		for _, uuid := range []string{p.AUUID, p.BUUID} {
			if n, ok := g.Node(uuid); ok && ActorGalaxies[n.Galaxy] {
				t.Errorf("an actor should never appear as a candidate: %s", uuid)
			}
		}
	}
}

func TestCoOccurrenceDeduplicatesTwoWayNeighbours(t *testing.T) {
	// A relation declared from both sides appears in Out and In alike, so the
	// same node reaches the candidate list twice and ends up paired with
	// itself — a pair no threshold filters out, since a set overlaps itself
	// completely.
	g := nestedGraph(t)
	for _, p := range g.CoOccurrence(CoOccurrenceOpts{UUID: "m-1", MinRate: 0, Limit: 50}) {
		if p.AUUID == p.BUUID {
			t.Errorf("an entry was paired with itself: %+v", p)
		}
	}
}

func TestCoOccurrenceSurvivesInvalidLimit(t *testing.T) {
	// The service validates, but the method is exported within the module: a
	// non-positive limit must not index into an empty slice.
	g := nestedGraph(t)
	for _, limit := range []int{0, -1} {
		if pairs := g.CoOccurrence(CoOccurrenceOpts{
			Galaxy: "mitre-attack-pattern", MinRate: 0, Limit: limit,
		}); pairs == nil {
			t.Errorf("limit %d returned nothing; expected the default to apply", limit)
		}
	}
}

func TestCoOccurrenceUnknownScope(t *testing.T) {
	g := nestedGraph(t)
	if pairs := g.CoOccurrence(CoOccurrenceOpts{UUID: "nope"}); pairs != nil {
		t.Errorf("expected nothing for an unknown uuid, got %+v", pairs)
	}
	if pairs := g.CoOccurrence(CoOccurrenceOpts{Galaxy: "no-such-galaxy"}); pairs != nil {
		t.Errorf("expected nothing for an unknown galaxy, got %+v", pairs)
	}
}
