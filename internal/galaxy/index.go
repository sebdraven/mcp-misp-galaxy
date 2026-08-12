package galaxy

import (
	"regexp"
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
	UUID       string   `json:"uuid"`
	Tag        string   `json:"tag,omitempty" jsonschema:"canonical MISP galaxy tag, e.g. misp-galaxy:threat-actor=\"APT28\" — this is what gets attached to a MISP event"`
	Value      string   `json:"value"`
	Galaxy     string   `json:"galaxy"`
	Reason     string   `json:"reason" jsonschema:"why this matched: value, synonym, value_prefix, synonym_prefix or substring"`
	Matched    string   `json:"matched" jsonschema:"the name or synonym that actually matched"`
	Score      int      `json:"score"`
	Degree     int      `json:"degree" jsonschema:"number of relations on this entry. 0 means it cannot be traversed: gx_neighbors and gx_path will return nothing from it. When several candidates name the same thing, prefer the one with a non-zero degree"`
	GroupCount int      `json:"group_count" jsonschema:"how many distinct threat actors are linked to this entry. 1 means only one actor is known to use it; 0 means none is recorded, which is absence of data rather than exclusivity; high values mean the entry is generic and carries little attribution value"`
	Revoked    bool     `json:"revoked,omitempty" jsonschema:"the corpus marks this entry as deprecated; it is ranked below live entries but still returned"`
	Synthetic  bool     `json:"synthetic,omitempty" jsonschema:"the corpus published this entry without a uuid; the uuid field is a locally derived key, not a MISP identifier, and no relation can point at it"`
	Synonyms   []string `json:"synonyms,omitempty"`
}

// Normalisation selects how names are folded before matching.
type Normalisation string

const (
	// Standard folds case and punctuation only. APT28, APT-28 and APT 28 match;
	// "LightSpy - S1185" and "LightSpy" do not.
	Standard Normalisation = "standard"

	// Aggressive additionally strips the decorations vendors and taxonomies
	// attach to a name: MITRE identifier suffixes, platform prefixes,
	// collective suffixes, a leading "the", and a trailing vendor in
	// parentheses.
	//
	// It matches more, and some of what it matches is wrong: dropping "group"
	// merges an actor with a tool of the same stem, and dropping platform
	// prefixes merges win.foo with apk.foo, which may be unrelated families.
	// Offered alongside Standard rather than replacing it so the two can be
	// compared on the same query.
	Aggressive Normalisation = "aggressive"
)

// mitreSuffix matches the identifier MITRE appends to display names, as in
// "APT28 - G0096", "LightSpy - S1185" or "PowerShell - T1059.001".
//
// The two-letter prefixes are listed before the single letters: Go's regexp is
// leftmost-first over an alternation, so `[GSTMC]` placed first would match the
// S of "DS0009" and leave the D behind.
var mitreSuffix = regexp.MustCompile(`\s*-\s*(?:DS|DC|[GSTMC])\d{3,4}(\.\d{3,4})?\s*$`)

// vendorSuffix matches a trailing parenthetical, which is usually a vendor:
// "Earth Preta (Trendmicro)", "Hive 0081 (IBM)".
//
// Usually, not always. The corpus also uses the parenthetical to disambiguate —
// "Foo (malware)" against "Foo (group)" — and stripping it merges precisely the
// two entries someone took care to separate. Both then come back as exact
// matches, which is why an aggressive resolve reports Ambiguous rather than
// letting a caller take the first candidate.
var vendorSuffix = regexp.MustCompile(`\s*\([^)]*\)\s*$`)

// platformPrefixPattern matches a platform qualifier followed by a separator,
// as Malpedia writes them: win.icefog, apk.dragonegg.
//
// The separator is required. Matching the bare prefix against a folded key
// would strip the start of any name that merely begins with those letters —
// "window" would lose its "win", "iOSCheck" its "ios" — and nothing downstream
// would reveal the mangling.
//
// Whitespace is NOT a separator here. Malpedia only ever writes the dotted
// form, whereas a space is how ordinary names are built: allowing it turns
// "Win Locker" into "locker" and "JS Sniffer" into "sniffer", silently.
var platformPrefixPattern = regexp.MustCompile(
	`(?i)^(win|elf|apk|osx|py|js|vbs|jar|symbian|ios)[._\-/]+`)

// collectiveSuffixPattern matches the words taxonomies append to an actor name
// without changing who it refers to: "Callisto" and "Callisto Group" are one
// entity.
//
// A word boundary is required for the same reason as above: without it,
// "adapt" ends in "apt" and would be truncated to "ad".
var collectiveSuffixPattern = regexp.MustCompile(
	`(?i)[._\-/\s]+(group|groups|gang|team|crew|apt|cyberespionage|framework|lair)\s*$`)

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

// normaliseAggressive strips taxonomy decoration, then folds.
//
// Every strip happens on the ORIGINAL string, where the separators that mark a
// decoration still exist. Doing it on the folded key would leave no way to
// tell "win.icefog" from "window" or "Callisto Group" from "adapt" — the
// delimiter is the only thing that says a prefix is a qualifier rather than
// the first letters of a name.
func normaliseAggressive(s string) string {
	// Strip only if something remains: a name that IS the decoration keeps it.
	// A value folding to the empty key would not be rejected, it would simply
	// never be added to the aggressive index — present under standard folding,
	// absent under aggressive, with nothing saying so.
	strip := func(s string, re *regexp.Regexp) string {
		if out := re.ReplaceAllString(s, ""); strings.TrimSpace(out) != "" {
			return out
		}
		return s
	}

	s = strings.TrimSpace(s)
	s = strip(s, mitreSuffix)
	s = strip(s, vendorSuffix)
	s = strings.TrimSpace(s)

	if lower := strings.ToLower(s); strings.HasPrefix(lower, "the ") && strings.TrimSpace(s[4:]) != "" {
		s = s[4:]
	}

	s = strip(s, platformPrefixPattern)
	s = strip(s, collectiveSuffixPattern)
	return normalise(s)
}

// buildIndex maps every normalised name and synonym to the nodes carrying it.
// A key holding several nodes is the normal case, not an anomaly.
//
// Two indexes are built, one per normalisation. Keeping both lets a caller run
// the same query under each and see what the aggressive form gains and what it
// wrongly merges — a claim worth checking rather than trusting. The second map
// costs a few megabytes against a corpus already holding 55,000 nodes.
func (g *Graph) buildIndex() {
	add := func(idx map[string][]*Node, key string, n *Node) {
		if key == "" {
			return
		}
		for _, existing := range idx[key] {
			if existing == n {
				return
			}
		}
		idx[key] = append(idx[key], n)
	}
	for _, n := range g.nodes {
		if n.Dangling {
			continue
		}
		add(g.index, normalise(n.Value), n)
		add(g.indexAggressive, normaliseAggressive(n.Value), n)
		for _, syn := range n.Synonyms {
			add(g.index, normalise(syn), n)
			add(g.indexAggressive, normaliseAggressive(syn), n)
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
	return g.ResolveWith(q, galaxies, limit, Standard)
}

// ResolveWith is Resolve under an explicit normalisation.
func (g *Graph) ResolveWith(q string, galaxies []string, limit int, mode Normalisation) []Candidate {
	fold := normalise
	index := g.index
	if mode == Aggressive {
		fold = normaliseAggressive
		index = g.indexAggressive
	}

	key := fold(q)
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
			Degree:     len(n.Out) + len(n.In),
			GroupCount: n.GroupCount,
			Revoked:    n.Revoked, Synthetic: n.Synthetic, Synonyms: n.Synonyms,
		}
	}

	// Exact bucket first — cheap map hit.
	for _, n := range index[key] {
		if fold(n.Value) == key {
			consider(n, MatchValue, n.Value, 100)
			continue
		}
		matched := key
		for _, syn := range n.Synonyms {
			if fold(syn) == key {
				matched = syn
				break
			}
		}
		consider(n, MatchSynonym, matched, 90)
	}

	// Then a scan for prefix and substring. Linear over the key set, which is
	// tens of thousands of entries — fast enough that a trie is not worth the
	// extra structure until measurement says otherwise.
	for indexed, nodes := range index {
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
			if fold(n.Value) != indexed {
				// matched via a synonym rather than the canonical name
				if reason == MatchValuePrefix {
					r = MatchSynonymPre
				}
				score -= 5
				for _, syn := range n.Synonyms {
					if fold(syn) == indexed {
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
