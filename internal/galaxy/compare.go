package galaxy

import (
	"sort"
)

// SharedEntry is one entry both sides of a comparison are linked to.
type SharedEntry struct {
	UUID       string `json:"uuid"`
	Tag        string `json:"tag,omitempty"`
	Value      string `json:"value"`
	Galaxy     string `json:"galaxy"`
	GroupCount int    `json:"group_count" jsonschema:"actors linked to this entry; the higher it is, the less the sharing means"`
	Generic    bool   `json:"generic,omitempty"`
}

// Comparison is what two entries have in common and what sets them apart.
type Comparison struct {
	AUUID  string `json:"a_uuid"`
	AValue string `json:"a_value"`
	BUUID  string `json:"b_uuid"`
	BValue string `json:"b_value"`

	// Similarity is the Jaccard index over the two neighbourhoods, computed
	// after generic entries are removed.
	//
	// Removing them first is what makes the number mean anything. Everyone
	// spearphishes; leaving the behaviours that every actor shares in the
	// comparison makes every pair look alike, and unsupervised clustering on
	// the raw profiles collapses two thirds of ATT&CK's groups into a single
	// blob.
	Similarity float64 `json:"similarity"`

	Shared []SharedEntry `json:"shared"`
	AOnly  []SharedEntry `json:"a_only"`
	BOnly  []SharedEntry `json:"b_only"`

	SharedCount int `json:"shared_count"`
	AOnlyCount  int `json:"a_only_count"`
	BOnlyCount  int `json:"b_only_count"`

	// GenericExcluded counts what was dropped before comparing, so a caller
	// can tell a genuinely thin overlap from one that was mostly noise.
	GenericExcluded int `json:"generic_excluded"`

	// Truncated marks a comparison scored over a ranked slice of a
	// neighbourhood rather than the whole of it. On a high-degree entry the
	// similarity is then an estimate, and reading it as exact overstates what
	// was measured.
	Truncated bool `json:"truncated,omitempty"`

	Note string `json:"note,omitempty"`
}

// CompareOpts tunes a comparison.
type CompareOpts struct {
	Depth int

	// IncludeGeneric keeps the widely-shared entries in the comparison. Off by
	// default, and turning it on inflates similarity for every pair.
	IncludeGeneric bool

	// Galaxies restricts the comparison to certain kinds of neighbour —
	// comparing tooling alone, say, rather than tooling and techniques
	// together.
	Galaxies []string

	Limit int
}

// Compare reports what two entries share and what distinguishes them.
//
// The CTI literature is blunt about what this can support: only about a third
// of threat groups have any behaviour exclusive to them, and similarity
// between profiles is driven mostly by how much has been written about each.
// A high score here is a starting point for a question, not an answer to one.
func (g *Graph) Compare(aUUID, bUUID string, opt CompareOpts) (Comparison, bool) {
	a, okA := g.nodes[aUUID]
	b, okB := g.nodes[bUUID]
	if !okA || !okB {
		return Comparison{}, false
	}
	if opt.Depth <= 0 {
		opt.Depth = 1
	}
	if opt.Limit <= 0 {
		opt.Limit = 100
	}

	// The generic filter has to block traversal, not just hide results.
	// Neighbours walks through a node it declines to report, so at depth > 1
	// two entries could share everything reachable *via* the hub the filter was
	// meant to neutralise — reintroducing the "everything looks related" effect
	// by the back door. MaxGroupCount is what stops the walk at those nodes.
	walk := NeighbourOpts{Depth: opt.Depth, Limit: maxCompareNeighbours, Galaxies: opt.Galaxies}
	if !opt.IncludeGeneric {
		// One below the galaxy's own generic threshold, so exactly the entries
		// flagged generic are excluded rather than an arbitrary count.
		walk.MaxGroupCount = g.genericCutoffFor(opt.Galaxies)
	}
	aSet, aGeneric, aTrunc := g.comparableSet(aUUID, walk, opt.IncludeGeneric)
	bSet, bGeneric, bTrunc := g.comparableSet(bUUID, walk, opt.IncludeGeneric)

	cmp := Comparison{
		AUUID: a.UUID, AValue: a.Value,
		BUUID: b.UUID, BValue: b.Value,
		GenericExcluded: aGeneric + bGeneric,
		Truncated:       aTrunc || bTrunc,
	}

	for uuid, entry := range aSet {
		if _, both := bSet[uuid]; both {
			cmp.Shared = append(cmp.Shared, entry)
		} else {
			cmp.AOnly = append(cmp.AOnly, entry)
		}
	}
	for uuid, entry := range bSet {
		if _, both := aSet[uuid]; !both {
			cmp.BOnly = append(cmp.BOnly, entry)
		}
	}

	cmp.SharedCount = len(cmp.Shared)
	cmp.AOnlyCount = len(cmp.AOnly)
	cmp.BOnlyCount = len(cmp.BOnly)

	union := cmp.SharedCount + cmp.AOnlyCount + cmp.BOnlyCount
	if union > 0 {
		cmp.Similarity = float64(cmp.SharedCount) / float64(union)
	}

	sortShared(cmp.Shared)
	sortShared(cmp.AOnly)
	sortShared(cmp.BOnly)
	cmp.Shared = capShared(cmp.Shared, opt.Limit)
	cmp.AOnly = capShared(cmp.AOnly, opt.Limit)
	cmp.BOnly = capShared(cmp.BOnly, opt.Limit)

	switch {
	case union == 0:
		cmp.Note = "neither entry has any comparable neighbour in this corpus, so nothing can be said about how alike they are"
	case cmp.SharedCount == 0:
		cmp.Note = "nothing in common once generic entries are set aside"
	case allGeneric(cmp.Shared):
		// The trap the literature keeps pointing at: two groups look related
		// because both spearphish.
		cmp.Note = "everything shared here is used by many actors, so the overlap says little about these two in particular"
	}
	return cmp, true
}

// maxCompareNeighbours bounds each side of a comparison.
//
// Neighbours ranks before truncating, so a comparison that hits this cap is
// scored over the best-ranked slice rather than the whole neighbourhood — which
// is why Truncated is reported rather than left implicit.
const maxCompareNeighbours = 2000

// genericCutoffFor returns a MaxGroupCount that excludes exactly the entries
// their own galaxy calls generic.
//
// Thresholds are per-galaxy, so with several in scope the lowest is used: it is
// the only choice that never lets a generic entry through, and over-filtering a
// denser galaxy is the safer error here.
func (g *Graph) genericCutoffFor(galaxies []string) int {
	cutoff := 0
	consider := func(t int) {
		if t <= 1 {
			return
		}
		if cutoff == 0 || t-1 < cutoff {
			cutoff = t - 1
		}
	}
	if len(galaxies) > 0 {
		for _, name := range galaxies {
			if t, ok := g.GenericThreshold(name); ok {
				consider(t)
			}
		}
	} else {
		for _, t := range g.thresholds {
			consider(t)
		}
	}
	if cutoff == 0 {
		cutoff = GenericFallbackThreshold
	}
	return cutoff
}

// comparableSet collects an entry's neighbours as a set, dropping the ones too
// widely shared to distinguish anybody, and reporting how many were dropped
// and whether the walk was cut short.
func (g *Graph) comparableSet(uuid string, walk NeighbourOpts, includeGeneric bool) (map[string]SharedEntry, int, bool) {
	out := map[string]SharedEntry{}
	dropped := 0
	neighbours := g.Neighbours(uuid, walk)
	for _, n := range neighbours {
		if n.Dangling {
			continue
		}
		if n.Generic && !includeGeneric {
			dropped++
			continue
		}
		out[n.UUID] = SharedEntry{
			UUID: n.UUID, Tag: n.Tag, Value: n.Value, Galaxy: n.Galaxy,
			GroupCount: n.GroupCount, Generic: n.Generic,
		}
	}
	return out, dropped, len(neighbours) >= walk.Limit
}

func allGeneric(entries []SharedEntry) bool {
	if len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if !e.Generic {
			return false
		}
	}
	return true
}

// sortShared puts the most discriminating entries first: an entry linked to one
// actor says more about a pair than one linked to fifty.
func sortShared(entries []SharedEntry) {
	sort.Slice(entries, func(i, j int) bool {
		// Entries with no actor at all are a gap in the corpus, not a strong
		// signal, so they sink rather than lead.
		zi, zj := entries[i].GroupCount == 0, entries[j].GroupCount == 0
		if zi != zj {
			return zj
		}
		if entries[i].GroupCount != entries[j].GroupCount {
			return entries[i].GroupCount < entries[j].GroupCount
		}
		return entries[i].Value < entries[j].Value
	})
}

func capShared(entries []SharedEntry, limit int) []SharedEntry {
	if len(entries) > limit {
		return entries[:limit]
	}
	return entries
}
