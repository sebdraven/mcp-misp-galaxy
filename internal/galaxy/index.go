package galaxy

import (
	"sort"
	"strings"
	"unicode"
)

// Match reasons, ordered by how much they should be trusted.
const (
	MatchValue       = "value"   // exact match on the canonical name
	MatchSynonym     = "synonym" // exact match on a declared synonym
	MatchValuePrefix = "value_prefix"
	MatchSynonymPre  = "synonym_prefix"
	MatchSubstring   = "substring" // query appears somewhere in a name
)

// Candidate is one possible resolution of a name.
//
// Resolve returns a ranked list rather than a single node on purpose. The same
// synonym regularly designates several clusters — sometimes across different
// galaxies — so collapsing to one answer produces silent misattribution. The
// caller (or the analyst) picks; this only orders the options and says why.
type Candidate struct {
	UUID      string   `json:"uuid"`
	Tag       string   `json:"tag,omitempty" jsonschema:"canonical MISP galaxy tag, e.g. misp-galaxy:threat-actor=\"APT28\" — this is what gets attached to a MISP event"`
	Value     string   `json:"value"`
	Galaxy    string   `json:"galaxy"`
	Reason    string   `json:"reason" jsonschema:"why this matched: value, synonym, value_prefix, synonym_prefix or substring"`
	Matched   string   `json:"matched" jsonschema:"the name or synonym that actually matched"`
	Score     int      `json:"score"`
	Degree    int      `json:"degree" jsonschema:"number of relations on this entry. 0 means it cannot be traversed: gx_neighbors and gx_path will return nothing from it. When several candidates name the same thing, prefer the one with a non-zero degree"`
	Revoked   bool     `json:"revoked,omitempty" jsonschema:"the corpus marks this entry as deprecated; it is ranked below live entries but still returned"`
	Synthetic bool     `json:"synthetic,omitempty" jsonschema:"the corpus published this entry without a uuid; the uuid field is a locally derived key, not a MISP identifier, and no relation can point at it"`
	Synonyms  []string `json:"synonyms,omitempty"`
}

// normalise folds the spelling variants that plague actor names: case, spacing
// and the hyphen/space/nothing alternation (APT28 / APT-28 / APT 28 all fold
// to the same key). Applied at index time, not at query time.
func normalise(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToLower(r))
		default:
			// spaces, hyphens, underscores, dots and punctuation all drop out
		}
	}
	return b.String()
}

// buildIndex maps every normalised name and synonym to the nodes carrying it.
// A key holding several nodes is the normal case, not an anomaly.
func (g *Graph) buildIndex() {
	add := func(key string, n *Node) {
		if key == "" {
			return
		}
		for _, existing := range g.index[key] {
			if existing == n {
				return
			}
		}
		g.index[key] = append(g.index[key], n)
	}
	for _, n := range g.nodes {
		if n.Dangling {
			continue
		}
		add(normalise(n.Value), n)
		for _, syn := range n.Synonyms {
			add(normalise(syn), n)
		}
	}
}

// scopeSet turns a list of galaxy types into a lookup set. An empty or nil list
// means "no restriction".
func scopeSet(galaxies []string) map[string]bool {
	if len(galaxies) == 0 {
		return nil
	}
	set := make(map[string]bool, len(galaxies))
	for _, g := range galaxies {
		if g = strings.ToLower(strings.TrimSpace(g)); g != "" {
			set[g] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// Resolve ranks the nodes matching q, restricted to the given galaxy types.
//
// The scope is not an optimisation. misp-galaxy long ago stopped being a
// threat-intelligence corpus: its two largest galaxies are microbial culture
// collections and firearms, and together they outweigh malpedia, threat-actor,
// tool, mitre-malware and attack-pattern combined. Resolving an actor name
// against the whole corpus searches a firearms catalogue.
//
// Passing no galaxies searches everything, which is occasionally what you want
// and never what you want by default.
func (g *Graph) Resolve(q string, galaxies []string, limit int) []Candidate {
	key := normalise(q)
	if key == "" {
		return nil
	}
	if limit <= 0 {
		limit = 20
	}
	scope := scopeSet(galaxies)

	seen := make(map[*Node]Candidate)

	consider := func(n *Node, reason, matched string, score int) {
		if n.Dangling {
			return
		}
		if scope != nil && !scope[strings.ToLower(n.Galaxy)] {
			return
		}
		// A revoked entry always ranks below any live one, whatever the quality
		// of its match — but it is still returned, flagged.
		if n.Revoked {
			score -= 200
		}
		if prev, ok := seen[n]; ok && prev.Score >= score {
			return
		}
		seen[n] = Candidate{
			UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
			Reason: reason, Matched: matched, Score: score,
			// Degree is what tells a caller which candidate is usable for
			// traversal. The relations in this corpus sit almost entirely in
			// the MITRE galaxies: the same malware can resolve to three
			// entries, of which only one has any edges at all, and nothing
			// else in the result says which.
			Degree:  len(n.Out) + len(n.In),
			Revoked: n.Revoked, Synthetic: n.Synthetic, Synonyms: n.Synonyms,
		}
	}

	// Exact bucket first — cheap map hit.
	for _, n := range g.index[key] {
		if normalise(n.Value) == key {
			consider(n, MatchValue, n.Value, 100)
			continue
		}
		matched := key
		for _, syn := range n.Synonyms {
			if normalise(syn) == key {
				matched = syn
				break
			}
		}
		consider(n, MatchSynonym, matched, 90)
	}

	// Then a scan for prefix and substring. Linear over the key set, which is
	// tens of thousands of entries — fast enough that a trie is not worth the
	// extra structure until measurement says otherwise.
	for indexed, nodes := range g.index {
		if indexed == key {
			continue
		}
		var reason string
		var base int
		switch {
		case strings.HasPrefix(indexed, key):
			reason, base = MatchValuePrefix, 70
		case strings.Contains(indexed, key):
			reason, base = MatchSubstring, 40
		default:
			continue
		}
		for _, n := range nodes {
			r, score, matched := reason, base, n.Value
			if normalise(n.Value) != indexed {
				// matched via a synonym rather than the canonical name
				if reason == MatchValuePrefix {
					r = MatchSynonymPre
				}
				score -= 5
				for _, syn := range n.Synonyms {
					if normalise(syn) == indexed {
						matched = syn
						break
					}
				}
			}
			// Shorter names that contain the query are likelier to be what was
			// meant than long ones that merely mention it.
			if d := len(indexed) - len(key); d < 20 {
				score += (20 - d) / 4
			}
			consider(n, r, matched, score)
		}
	}

	out := make([]Candidate, 0, len(seen))
	for _, c := range seen {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		// Degree breaks ties, because relations are concentrated in the MITRE
		// galaxies: an entry matched through a synonym may be the only
		// traversable one while two exact matches lead nowhere. Secondary only
		// — match quality still decides first, so a weak match never climbs
		// above a strong one on connectivity alone.
		if out[i].Degree != out[j].Degree {
			return out[i].Degree > out[j].Degree
		}
		if out[i].Value != out[j].Value {
			return out[i].Value < out[j].Value
		}
		return out[i].UUID < out[j].UUID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// GroupByGalaxy splits candidates by galaxy, largest group first. Useful when
// a name spans several naming conventions — which for well-known actors is the
// normal case, and is itself worth seeing.
func GroupByGalaxy(cands []Candidate) []CandidateGroup {
	byGalaxy := map[string][]Candidate{}
	for _, c := range cands {
		byGalaxy[c.Galaxy] = append(byGalaxy[c.Galaxy], c)
	}
	out := make([]CandidateGroup, 0, len(byGalaxy))
	for gx, cs := range byGalaxy {
		out = append(out, CandidateGroup{Galaxy: gx, Count: len(cs), Candidates: cs})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Galaxy < out[j].Galaxy
	})
	return out
}

// CandidateGroup is the candidates from one galaxy.
type CandidateGroup struct {
	Galaxy     string      `json:"galaxy"`
	Count      int         `json:"count"`
	Candidates []Candidate `json:"candidates"`
}
