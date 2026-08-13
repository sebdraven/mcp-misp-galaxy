package galaxy

import (
	"math"
	"sort"
	"strings"
)

// CoOccurrencePair is two entries used by nearly the same set of actors.
type CoOccurrencePair struct {
	AUUID  string `json:"a_uuid"`
	AValue string `json:"a_value"`
	AGroup int    `json:"a_group_count" jsonschema:"actors linked to A"`
	BUUID  string `json:"b_uuid"`
	BValue string `json:"b_value"`
	BGroup int    `json:"b_group_count" jsonschema:"actors linked to B"`

	// Rate is |actors(A) ∩ actors(B)| / max(|actors(A)|, |actors(B)|).
	//
	// Dividing by the larger set rather than the union is what the CTI
	// literature uses, and it is the stricter choice: a pair only scores high
	// when the smaller set is almost entirely contained in the larger AND the
	// two are of comparable size. Jaccard would flatter a rare entry that
	// happens to sit inside a common one.
	Rate float64 `json:"rate"`

	Shared int `json:"shared" jsonschema:"actors linked to both"`
	AOnly  int `json:"a_only" jsonschema:"actors linked to A but not B"`
	BOnly  int `json:"b_only" jsonschema:"actors linked to B but not A"`
}

// CoOccurrenceThreshold is where a pair stops being two observations and
// starts being one.
//
// 0.75 follows the literature, which finds five pairs above it in ATT&CK —
// spearphishing link with malicious link, spearphishing attachment with
// malicious file. Those are semantically nested rather than independent, and
// counting both as evidence is double counting.
const CoOccurrenceThreshold = 0.75

// MinCoOccurrenceActors is the smallest actor set the measure is applied to.
//
// Below it the rate is degenerate rather than merely noisy: two entries with a
// single actor each, and the same one, score a perfect 1.0 however unrelated
// they are. Most of this corpus is in that state — an implant documented for
// one group makes every pair of its techniques look redundant — so without a
// floor the tool reports spurious redundancy almost everywhere.
//
// The literature applies the measure to techniques used by dozens of groups,
// where a high rate genuinely means "these appear together for nearly everyone
// who uses either".
const MinCoOccurrenceActors = 5

// MaxCoOccurrenceCandidates caps how many entries are paired up.
//
// The comparison is quadratic in candidates, and both façades are reachable
// without authentication: a hub with a few thousand neighbours and a zero
// threshold would otherwise materialise millions of pairs before sorting.
const MaxCoOccurrenceCandidates = 500

// actorsOf returns the actors linked to a node, as a set.
func (g *Graph) actorsOf(n *Node) map[string]bool {
	out := map[string]bool{}
	for _, e := range undirectedEdges(n) {
		if e.To == n {
			continue
		}
		if ActorGalaxies[strings.ToLower(e.To.Galaxy)] {
			out[e.To.UUID] = true
		}
	}
	return out
}

// CoOccurrenceOpts tunes a co-occurrence search.
type CoOccurrenceOpts struct {
	// UUID scopes the search to one entry's neighbourhood. Empty searches a
	// whole galaxy instead — which is what the literature does, and the only
	// way to surface the pairs it reports, since those are shared across the
	// corpus rather than sitting next to any one entry.
	UUID string

	// Galaxy scopes a corpus-wide search. Required when UUID is empty.
	Galaxy string

	MinRate   float64
	MinActors int
	Limit     int
}

// CoOccurrence finds pairs of entries used by nearly the same set of actors.
//
// Pairs above the rate are not independent evidence. Two techniques used by
// the same actors tell you what one of them tells you; treating them as two
// findings inflates a profile without adding anything to it. The pairs the
// literature reports are semantically nested — a spearphishing link is a kind
// of malicious link — so what the measure really surfaces is redundancy
// already present in the taxonomy.
//
// Defaults and validation belong to the service layer; the values passed here
// are used as given, bar defensive guards against a crash.
func (g *Graph) CoOccurrence(opt CoOccurrenceOpts) []CoOccurrencePair {
	if opt.Limit <= 0 {
		opt.Limit = 20
	}
	if math.IsNaN(opt.MinRate) {
		opt.MinRate = CoOccurrenceThreshold
	}
	if opt.MinActors <= 0 {
		opt.MinActors = MinCoOccurrenceActors
	}

	candidates, actors := g.coOccurrenceCandidates(opt)

	var out []CoOccurrencePair
	for i := 0; i < len(candidates); i++ {
		for j := i + 1; j < len(candidates); j++ {
			a, b := candidates[i], candidates[j]
			sa, sb := actors[a], actors[b]

			shared := 0
			for uuid := range sa {
				if sb[uuid] {
					shared++
				}
			}
			if shared == 0 {
				continue
			}
			denom := len(sa)
			if len(sb) > denom {
				denom = len(sb)
			}
			rate := float64(shared) / float64(denom)
			if rate < opt.MinRate {
				continue
			}
			pair := CoOccurrencePair{
				AUUID: a.UUID, AValue: a.Value, AGroup: len(sa),
				BUUID: b.UUID, BValue: b.Value, BGroup: len(sb),
				Rate:   rate,
				Shared: shared,
				AOnly:  len(sa) - shared,
				BOnly:  len(sb) - shared,
			}
			// Keep only the best `limit` pairs seen so far. Collecting every
			// qualifying pair first would make peak memory quadratic in the
			// candidate set, which a zero threshold reaches easily.
			if len(out) < opt.Limit {
				out = append(out, pair)
				if len(out) == opt.Limit {
					sortPairs(out)
				}
				continue
			}
			if !betterPair(pair, out[len(out)-1]) {
				continue
			}
			out[len(out)-1] = pair
			sortPairs(out)
		}
	}

	sortPairs(out)
	return out
}

// coOccurrenceCandidates gathers the entries to compare, either from one
// entry's neighbourhood or from a whole galaxy.
func (g *Graph) coOccurrenceCandidates(opt CoOccurrenceOpts) ([]*Node, map[*Node]map[string]bool) {
	var pool []*Node
	if opt.UUID != "" {
		start, ok := g.nodes[opt.UUID]
		if !ok {
			return nil, nil
		}
		seen := map[*Node]bool{start: true}
		for _, e := range undirectedEdges(start) {
			// Deduplicated: a relation declared from both sides appears in Out
			// and In alike, and the same node would otherwise be paired with
			// itself.
			if seen[e.To] {
				continue
			}
			seen[e.To] = true
			pool = append(pool, e.To)
		}
	} else {
		pool = g.byGalaxy[strings.ToLower(opt.Galaxy)]
		if pool == nil {
			for gt, nodes := range g.byGalaxy {
				if strings.EqualFold(gt, opt.Galaxy) {
					pool = nodes
					break
				}
			}
		}
	}

	var candidates []*Node
	actors := map[*Node]map[string]bool{}
	for _, n := range pool {
		if n.Dangling {
			continue
		}
		if ActorGalaxies[strings.ToLower(n.Galaxy)] {
			continue // an actor is not a behaviour to be co-observed
		}
		set := g.actorsOf(n)
		// The floor is what keeps the measure meaningful: below it a shared
		// actor or two produces a perfect score between unrelated entries.
		if len(set) < opt.MinActors {
			continue
		}
		candidates = append(candidates, n)
		actors[n] = set
		if len(candidates) == MaxCoOccurrenceCandidates {
			break
		}
	}
	return candidates, actors
}

// betterPair reports whether a outranks b under the result ordering.
func betterPair(a, b CoOccurrencePair) bool {
	if a.Rate != b.Rate {
		return a.Rate > b.Rate
	}
	if a.Shared != b.Shared {
		return a.Shared > b.Shared
	}
	return a.AValue < b.AValue
}

func sortPairs(p []CoOccurrencePair) {
	sort.Slice(p, func(i, j int) bool { return betterPair(p[i], p[j]) })
}
