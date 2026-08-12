package galaxy

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// profileGraph builds a malware linked to an actor, an exclusive technique, a
// widely shared one, and one nobody is linked to — the four cases a profile
// has to tell apart.
func profileGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Twelve actors so the galaxy has enough attributed entries for a real
	// generic threshold; eleven of them use t-shared and nothing else.
	var actors []map[string]any
	actors = append(actors, map[string]any{
		"value": "The Actor", "uuid": "a-main",
		"related": []map[string]any{
			{"dest-uuid": "m-1", "type": "uses"},
			{"dest-uuid": "t-only", "type": "uses"},
			{"dest-uuid": "t-shared", "type": "uses"},
		},
	})
	for i := 0; i < 11; i++ {
		actors = append(actors, map[string]any{
			"value": fmt.Sprintf("Actor %02d", i),
			"uuid":  fmt.Sprintf("a-%02d", i),
			"related": []map[string]any{
				{"dest-uuid": "t-shared", "type": "uses"},
			},
		})
	}
	writeCluster(t, clusters, "threat-actor", actors)

	writeCluster(t, clusters, "mitre-malware", []map[string]any{
		{"value": "Family", "uuid": "m-1", "related": []map[string]any{
			{"dest-uuid": "t-only", "type": "uses"},
			{"dest-uuid": "t-shared", "type": "uses"},
			{"dest-uuid": "t-orphan", "type": "uses"},
		}},
	})
	writeCluster(t, clusters, "mitre-attack-pattern", []map[string]any{
		{"value": "Only This One", "uuid": "t-only"},
		{"value": "Everyone Does This", "uuid": "t-shared"},
		{"value": "Nobody Recorded", "uuid": "t-orphan"},
	})

	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestProfileCountsSpecificGenericAndUnattributed(t *testing.T) {
	g := profileGraph(t)
	p, ok := g.Profile("m-1", 1, 100)
	if !ok {
		t.Fatal("expected a profile for the malware")
	}

	// The fixture only tests anything if the three cases really differ.
	for uuid, want := range map[string]int{"t-only": 1, "t-shared": 12, "t-orphan": 0} {
		n, _ := g.Node(uuid)
		if n.GroupCount != want {
			t.Fatalf("fixture broken: %s has group_count %d, want %d", uuid, n.GroupCount, want)
		}
	}

	if p.Specific != 1 {
		t.Errorf("specific = %d, want 1 (the exclusive technique)", p.Specific)
	}
	if p.Generic != 1 {
		t.Errorf("generic = %d, want 1 (the widely shared technique)", p.Generic)
	}
	if p.Unattributed != 1 {
		t.Errorf("unattributed = %d, want 1 (the technique nobody is linked to)", p.Unattributed)
	}
}

func TestProfileDoesNotCountUnattributedAsSpecific(t *testing.T) {
	// The distinction the whole type exists for: one actor is evidence, no
	// actor is a gap. Collapsing them turns under-reporting into confidence.
	g := profileGraph(t)
	p, _ := g.Profile("m-1", 1, 100)
	if p.Specific == p.Total {
		t.Fatal("an entry with no actor must not be counted as specific")
	}
}

func TestProfileGroupsActorsFirst(t *testing.T) {
	// Walking out from a malware, who uses it is the answer; the technique
	// list is context. Size alone would bury the actor under the techniques.
	g := profileGraph(t)
	p, _ := g.Profile("m-1", 1, 100)
	if len(p.Groups) < 2 {
		t.Fatalf("expected several groups, got %+v", p.Groups)
	}
	if p.Groups[0].Galaxy != "threat-actor" {
		t.Errorf("actors should lead the profile, got %q with %d entries",
			p.Groups[0].Galaxy, p.Groups[0].Count)
	}
}

func TestProfileNotesAbsenceOfAnySpecificEntry(t *testing.T) {
	// Saying so is more useful than letting a caller read a long list as
	// discriminating — the literature's recurring finding is that most
	// profiles have nothing exclusive in them.
	g := profileGraph(t)
	p, _ := g.Profile("a-00", 1, 100) // an actor whose only technique is shared
	if p.Specific != 0 {
		t.Fatalf("fixture broken: expected no specific entry, got %d", p.Specific)
	}
	if p.Note == "" {
		t.Error("a profile with nothing exclusive should say so")
	}
}

func TestProfileUnknownUUID(t *testing.T) {
	g := profileGraph(t)
	if _, ok := g.Profile("nope", 1, 100); ok {
		t.Error("expected no profile for an unknown uuid")
	}
}
