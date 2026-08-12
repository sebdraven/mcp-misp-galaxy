package galaxy

import (
	"os"
	"path/filepath"
	"testing"
)

// refsGraph carries an entry with a mix of report links, a self-referential
// catalogue page, a duplicate, and an entry with nothing at all.
func refsGraph(t *testing.T) *Graph {
	t.Helper()
	root := t.TempDir()
	clusters := filepath.Join(root, "clusters")
	if err := os.MkdirAll(clusters, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeCluster(t, clusters, "threat-actor", []map[string]any{
		{
			"value": "Documented", "uuid": "a-doc",
			"meta": map[string]any{
				"refs": []string{
					"https://malpedia.caad.fkie.fraunhofer.de/details/win.foo",
					"https://securelist.com/report-one/",
					"https://www.securelist.com/report-two/",
					"https://unit42.paloaltonetworks.com/report/",
					"https://securelist.com/report-one/",
				},
			},
		},
		{"value": "Undocumented", "uuid": "a-none", "meta": map[string]any{}},
	})
	g, err := Load(root, "deadbeef")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return g
}

func TestReferencesDeduplicateAndParseDomains(t *testing.T) {
	g := refsGraph(t)
	n, _ := g.Node("a-doc")
	refs := n.References()

	if len(refs) != 4 {
		t.Fatalf("expected the duplicate URL to be dropped, got %d refs", len(refs))
	}
	// www. is stripped, so the same publisher under two spellings counts once.
	byDomain := map[string]int{}
	for _, r := range refs {
		byDomain[r.Domain]++
	}
	if byDomain["securelist.com"] != 2 {
		t.Errorf("www. should be stripped so both securelist URLs share a domain, got %+v", byDomain)
	}
}

func TestSelfReferentialRefsSortLast(t *testing.T) {
	// Every Malpedia entry links to its own catalogue page. Left unmarked, a
	// non-report would head thousands of lists.
	g := refsGraph(t)
	n, _ := g.Node("a-doc")
	refs := n.References()

	if refs[len(refs)-1].Domain != "malpedia.caad.fkie.fraunhofer.de" {
		t.Errorf("the catalogue page should sort last, got %+v", refs)
	}
	if !refs[len(refs)-1].SelfReferential {
		t.Error("the catalogue page should be flagged self-referential")
	}
	for _, r := range refs[:len(refs)-1] {
		if r.SelfReferential {
			t.Errorf("%s wrongly flagged self-referential", r.URL)
		}
	}
}

func TestPublisherCountExcludesCataloguePages(t *testing.T) {
	// The point of the count is "how many independent teams looked at this".
	// A catalogue page is not a team.
	g := refsGraph(t)
	n, _ := g.Node("a-doc")
	pubs := ByPublisher(n.References())

	for _, p := range pubs {
		if p.Domain == "malpedia.caad.fkie.fraunhofer.de" {
			t.Error("the catalogue page should not count as a publisher")
		}
	}
	if len(pubs) != 2 {
		t.Fatalf("expected two publishers, got %+v", pubs)
	}
	if pubs[0].Domain != "securelist.com" || pubs[0].Count != 2 {
		t.Errorf("the most prolific publisher should lead, got %+v", pubs)
	}
}

func TestReferencesOnEntryWithNone(t *testing.T) {
	g := refsGraph(t)
	n, _ := g.Node("a-none")
	if refs := n.References(); refs != nil {
		t.Errorf("expected no references, got %+v", refs)
	}
}
