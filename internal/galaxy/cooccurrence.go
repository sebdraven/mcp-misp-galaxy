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

// MaxCoOccurrenceCandidates caps how many neighbours are paired up.
//
// The comparison is quadratic in candidates, and both façades are reachable
// without authentication: a hub with a few thousand neighbours and a zero
// threshold would otherwise materialise millions of pairs before sorting. The
// cap keeps the worst case bounded at roughly 125,000 comparisons.
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

// CoOccurrence finds, among the neighbours of an entry, the pairs used by
// almost the same set of actors.
//
// Scoped to one entry's neighbourhood rather than the whole corpus: comparing
// every pair of 55,000 nodes is quadratic, and the useful question is narrower
// anyway — "in this profile, what am I counting twice?".
//
// Pairs at or above minRate are not independent evidence. Two techniques used
// by the same actors tell you what one of them tells you; treating them as two
// findings inflates a profile without adding anything to it.
//
// minRate and limit are taken as given: validation and defaulting belong to
// the service layer, so both façades reject the same inputs the same way.
func (g *Graph) CoOccurrence(uuid string, minRate float64, limit int) []CoOccurrencePair {
	start, ok := g.nodes[uuid]
	if !ok {
		return nil
	}
	// Defensive: the service validates these, but the method is exported within
	// the module and a non-positive limit would index into an empty slice.
	if limit <= 0 {
		limit = 20
	}
	if math.IsNaN(minRate) {
		minRate = CoOccurrenceThreshold
	}

	// Only entries with actors can co-occur: the measure is defined over
	// actor sets, and an entry nobody is linked to has none.
	//
	// Deduplicated because a relation declared from both sides appears in Out
	// and In alike; without this the same node enters twice and gets paired
	// with itself.
	var candidates []*Node
	actors := map[*Node]map[string]bool{}
	for _, e := range undirectedEdges(start) {
		if e.To == start || e.To.Dangling {
			continue
		}
		if _, already := actors[e.To]; already {
			continue
		}
		if ActorGalaxies[strings.ToLower(e.To.Galaxy)] {
			continue // an actor is not a behaviour to be co-observed
		}
		set := g.actorsOf(e.To)
		if len(set) == 0 {
			continue
		}
		candidates = append(candidates, e.To)
		actors[e.To] = set
		if len(candidates) == MaxCoOccurrenceCandidates {
			// Deliberately silent truncation of the candidate set rather than an
			// error: the measure is a reading aid, and refusing to answer on the
			// busiest entries would remove it exactly where redundancy is worst.
			break
		}
	}

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
			if rate < minRate {
				continue
			}
			pair := CoOccurrencePair{
				AUUID: a.UUID, AValue: a.Value,
				BUUID: b.UUID, BValue: b.Value,
				Rate:   rate,
				Shared: shared,
				AOnly:  len(sa) - shared,
				BOnly:  len(sb) - shared,
			}
			// Keep only the best `limit` pairs seen so far. Collecting every
			// qualifying pair first would make peak memory quadratic in the
			// neighbourhood, which a zero threshold on a hub reaches easily.
			if len(out) < limit {
				out = append(out, pair)
				if len(out) == limit {
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
