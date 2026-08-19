package galaxy

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode"
)

// NameSignals is the per-signal breakdown behind a fuzzy match.
//
// Reported alongside the score rather than folded into it: a match attributable
// to a strong phonetic signal with moderate edit-distance support is a
// different claim from one resting on token overlap alone, and an opaque number
// hides that. The CTI naming literature is full of pairs that score well for
// the wrong reason.
//
// Not every signal applies to every pair. A single-word name has no token
// structure and no abbreviation to detect, and scoring those as 0 would be a
// verdict where there is no evidence — it drags a genuine typo like
// Kimsuki/Kimsuky down to 0.70 purely because the names are one word long.
// Inapplicable signals are marked and left out of the weighted average, and
// the remaining weights are renormalised.
type NameSignals struct {
	JaroWinkler  float64 `json:"jaro_winkler"`
	Levenshtein  float64 `json:"levenshtein" jsonschema:"1 minus the edit distance normalised by the longer string"`
	TokenOverlap float64 `json:"token_overlap,omitempty" jsonschema:"word-level Jaccard, robust to reordered tokens. Omitted when neither name has more than one token"`
	Abbreviation float64 `json:"abbreviation,omitempty" jsonschema:"confidence that one name abbreviates the other; requires an actual single-letter token, not merely a shared first letter. Omitted when neither name contains one"`
	DigitMatch   float64 `json:"digit_match" jsonschema:"agreement on the numbers in the names. APT28 and APT29 differ here, which is the whole point"`

	// Applied lists the signals that carried weight, so a caller can see that
	// a score rests on two measures rather than five.
	Applied []string `json:"applied"`
}

// Signal weights for the composite score.
//
// Taken from the entity-resolution literature, which reports 0.30 Jaro-Winkler,
// 0.25 phonetic, 0.20 token overlap, 0.15 abbreviation. Two departures: there
// is no phonetic signal here because actor names are not transliterated
// personal names — Double Metaphone would fold APT28 and APT29 together — and
// its weight goes to a digit-agreement signal instead, which is what actually
// separates the numbered families that dominate this corpus.
//
// These are a starting point tuned on nothing. The literature admits the same
// of its own: hand-set on a development corpus, never learned, and not
// guaranteed to transfer.
const (
	weightJaroWinkler  = 0.30
	weightLevenshtein  = 0.20
	weightTokenOverlap = 0.20
	weightAbbreviation = 0.05
	weightDigitMatch   = 0.25
)

// FuzzyThreshold is the default composite score below which a fuzzy candidate
// is not reported.
//
// 0.85 rather than the 0.75 the literature uses for personal names: actor names
// are short, share heavy prefixes by convention (APT, UNC, TEMP, Earth, Storm),
// and a permissive floor turns every numbered family into a cluster of
// look-alikes.
const FuzzyThreshold = 0.85

// FuzzyMatch is one entry found by approximate name matching.
type FuzzyMatch struct {
	UUID       string      `json:"uuid"`
	Tag        string      `json:"tag,omitempty"`
	Value      string      `json:"value"`
	Galaxy     string      `json:"galaxy"`
	Matched    string      `json:"matched" jsonschema:"the name or synonym the query was compared against"`
	Similarity float64     `json:"similarity"`
	Signals    NameSignals `json:"signals" jsonschema:"per-signal breakdown, so a match can be judged on why it scored rather than on the score alone"`

	// Blocked is set when a hard conflict forbids treating this as the same
	// entity, whatever the score. The candidate is still returned — hiding it
	// would leave a caller wondering why an obvious look-alike is missing —
	// but flagged so it is never read as a match.
	Blocked       bool   `json:"blocked,omitempty"`
	BlockedReason string `json:"blocked_reason,omitempty"`
}

// FuzzyOpts tunes an approximate search.
type FuzzyOpts struct {
	Galaxies []string

	// MinSimilarity is a pointer so that "unset" and "0" stay distinguishable:
	// 0 is a legitimate threshold meaning "report every candidate the blocking
	// filter admits", and folding it into the default would make a documented
	// value unreachable.
	MinSimilarity *float64

	Limit int
}

// FuzzyResolve finds entries whose names are close to q without being equal.
//
// Meant for typos and transliteration variants, which the naming literature
// documents as a real cause of alias proliferation — Kimsuki for Kimsuky,
// Calisto for Callisto, Red Bald Night for Red Bald Knight. It is NOT a way to
// discover that two differently-named entities are related: orthographic
// proximity is not identity, and in this corpus it is frequently the opposite.
// APT28 and APT29 are one edit apart and are two different actors.
func (g *Graph) FuzzyResolve(q string, opt FuzzyOpts) []FuzzyMatch {
	key := normalise(q)
	if key == "" {
		return nil
	}
	threshold := FuzzyThreshold
	if opt.MinSimilarity != nil {
		threshold = *opt.MinSimilarity
	}
	if opt.Limit <= 0 {
		opt.Limit = 20
	}
	inScope := scopeSet(opt.Galaxies)

	// Blocking, in the sense the literature uses: a cheap filter before the
	// expensive comparison. Comparing the query to all 56,000 index keys with
	// five signals each would be pointless when a length gap alone rules most
	// of them out.
	const maxLenGap = 4

	seen := map[*Node]FuzzyMatch{}
	consider := func(n *Node, candidate, indexed string) {
		if n.Dangling {
			return
		}
		if inScope != nil && !inScope[strings.ToLower(n.Galaxy)] {
			return
		}
		if indexed == key {
			return // exact matches belong to Resolve, not here
		}
		if abs(len(indexed)-len(key)) > maxLenGap {
			return
		}
		sig := scoreName(key, indexed)
		score := sig.composite()
		if score < opt.MinSimilarity {
			return
		}
		if prev, ok := seen[n]; ok && prev.Similarity >= score {
			return
		}
		m := FuzzyMatch{
			UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
			Matched: candidate, Similarity: score, Signals: sig,
		}
		seen[n] = m
	}

	for indexed, nodes := range g.index {
		for _, n := range nodes {
			candidate := n.Value
			if normalise(candidate) != indexed {
				for _, syn := range n.Synonyms {
					if normalise(syn) == indexed {
						candidate = syn
						break
					}
				}
			}
			consider(n, candidate, indexed)
		}
	}

	out := make([]FuzzyMatch, 0, len(seen))
	for n, m := range seen {
		// The hard conflict guard, applied after scoring rather than before: the
		// candidate is reported but marked, because a caller who searched for a
		// near-name and gets nothing back cannot tell "no such entry" from "an
		// entry exists and was withheld".
		if reason := g.hardConflict(q, n); reason != "" {
			m.Blocked, m.BlockedReason = true, reason
		}
		out = append(out, m)
	}

	sort.Slice(out, func(i, j int) bool {
		// Blocked candidates last whatever they scored: they are the ones the
		// caller must not act on, and a high score makes that easy to forget.
		if out[i].Blocked != out[j].Blocked {
			return out[j].Blocked
		}
		if out[i].Similarity != out[j].Similarity {
			return out[i].Similarity > out[j].Similarity
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > opt.Limit {
		out = out[:opt.Limit]
	}
	return out
}

// discriminators are the meta keys on which a disagreement forbids treating two
// entries as the same thing.
//
// The entity-resolution literature calls this a hard-conflict guard and applies
// it to date of birth, nationality and identity numbers: no similarity score,
// however high, may override a documented disagreement. The threat-actor
// analogue is attributed country — two actors placed in different countries by
// their own catalogues are not one actor with a typo, and the naming literature
// is full of merges that happened anyway.
var discriminators = []string{"country"}

// hardConflict reports why the query's own entry and a candidate cannot be the
// same, or "" when nothing forbids it.
//
// Only fires when the query itself resolves to a single entry: without one
// there is nothing to compare against, and guessing would be worse than
// staying silent.
func (g *Graph) hardConflict(query string, candidate *Node) string {
	exact := g.index[normalise(query)]
	if len(exact) != 1 {
		return ""
	}
	source := exact[0]
	if source == candidate {
		return ""
	}
	sm, cm := source.metaStrings(), candidate.metaStrings()
	for _, key := range discriminators {
		a, aok := sm[key]
		b, bok := cm[key]
		if !aok || !bok || a == "" || b == "" {
			continue // absent evidence is not conflicting evidence
		}
		if !strings.EqualFold(a, b) {
			return "conflicting " + key + ": " + a + " vs " + b
		}
	}
	return ""
}

// metaStrings decodes the scalar meta values of a node, ignoring anything that
// is not a plain string.
func (n *Node) metaStrings() map[string]string {
	out := map[string]string{}
	if n == nil || len(n.Meta) == 0 {
		return out
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal(n.Meta, &raw) != nil {
		return out
	}
	for k, v := range raw {
		var s string
		if json.Unmarshal(v, &s) == nil {
			out[k] = s
		}
	}
	return out
}

func (s NameSignals) composite() float64 {
	// Only applicable signals contribute, with the weights renormalised over
	// them. A signal that cannot say anything about a pair must not be counted
	// as saying "nothing in common".
	type term struct {
		value  float64
		weight float64
	}
	terms := []term{
		{s.JaroWinkler, weightJaroWinkler},
		{s.Levenshtein, weightLevenshtein},
		{s.DigitMatch, weightDigitMatch},
	}
	for _, name := range s.Applied {
		switch name {
		case "token_overlap":
			terms = append(terms, term{s.TokenOverlap, weightTokenOverlap})
		case "abbreviation":
			terms = append(terms, term{s.Abbreviation, weightAbbreviation})
		}
	}

	var sum, totalWeight float64
	var max float64
	for _, t := range terms {
		sum += t.value * t.weight
		totalWeight += t.weight
		if t.value > max {
			max = t.value
		}
	}
	if totalWeight == 0 {
		return 0
	}
	score := sum / totalWeight

	// Strong-signal boost, as the literature applies it: one signal at 0.90 or
	// above should not be dragged under by the others.
	if max >= 0.90 && score < 0.8*max {
		score = 0.8 * max
	}
	if score > 1 {
		score = 1
	}
	return score
}

// scoreName computes every applicable signal for a pair of normalised keys.
func scoreName(a, b string) NameSignals {
	s := NameSignals{
		JaroWinkler: jaroWinkler(a, b),
		Levenshtein: levenshteinRatio(a, b),
		DigitMatch:  digitAgreement(a, b),
		Applied:     []string{"jaro_winkler", "levenshtein", "digit_match"},
	}

	// Token overlap needs token structure on at least one side; on two
	// single-word names it can only ever return 0 or 1, and a one-character
	// typo makes it 0.
	ta, tb := strings.Fields(spaceOut(a)), strings.Fields(spaceOut(b))
	if len(ta) > 1 || len(tb) > 1 {
		s.TokenOverlap = tokenOverlap(a, b)
		s.Applied = append(s.Applied, "token_overlap")
	}

	// Abbreviation needs an actual single-letter token somewhere.
	if hasInitial(ta) || hasInitial(tb) {
		s.Abbreviation = abbreviationConfidence(a, b)
		s.Applied = append(s.Applied, "abbreviation")
	}
	return s
}

func hasInitial(tokens []string) bool {
	if len(tokens) < 2 {
		return false
	}
	for _, t := range tokens {
		if len([]rune(t)) == 1 {
			return true
		}
	}
	return false
}

// digitAgreement compares the numbers in two names.
//
// This signal replaces the phonetic one the literature uses, and it earns its
// weight here: a corpus where APT28, APT29, APT31, UNC1151 and UNC1549 are all
// distinct actors needs the digits to count for something. Every string metric
// treats a digit as just another character, so APT28/APT29 score 0.95 or better
// on all of them.
func digitAgreement(a, b string) float64 {
	da, db := digitsOf(a), digitsOf(b)
	switch {
	case da == "" && db == "":
		return 1 // neither is numbered; the signal has nothing to say
	case da == "" || db == "":
		return 0.5 // one numbered, one not: weak evidence either way
	case da == db:
		return 1
	default:
		// Different numbers in otherwise similar names is the strongest
		// evidence available that these are different entities.
		return 0
	}
}

func digitsOf(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// abbreviationConfidence reports whether one name genuinely abbreviates the
// other.
//
// A shared first letter is NOT an abbreviation. The literature documents this
// exact bug: a scorer that accepted any first-letter agreement rated "Michael
// Cruz" against "Mario Chavez" at 0.92 and produced 79 false positives. At
// least one part-pair must involve an actual single-character token.
func abbreviationConfidence(a, b string) float64 {
	ta, tb := strings.Fields(spaceOut(a)), strings.Fields(spaceOut(b))
	if len(ta) != len(tb) || len(ta) == 0 {
		return 0
	}
	sawAbbrev := false
	for i := range ta {
		p, q := ta[i], tb[i]
		switch {
		case p == q:
			continue
		case len(p) == 1 && strings.HasPrefix(q, p):
			sawAbbrev = true
		case len(q) == 1 && strings.HasPrefix(p, q):
			sawAbbrev = true
		default:
			return 0 // a part-pair that is neither equal nor an abbreviation
		}
	}
	if !sawAbbrev {
		return 0
	}
	return 1
}

// spaceOut re-inserts boundaries a normalised key has lost, so token-level
// signals have something to work with. Digits are treated as their own token:
// "apt28" becomes "apt 28".
func spaceOut(s string) string {
	var b strings.Builder
	var prev rune
	for i, r := range s {
		if i > 0 && unicode.IsDigit(r) != unicode.IsDigit(prev) {
			b.WriteRune(' ')
		}
		b.WriteRune(r)
		prev = r
	}
	return b.String()
}

func tokenOverlap(a, b string) float64 {
	ta := map[string]bool{}
	for _, t := range strings.Fields(spaceOut(a)) {
		ta[t] = true
	}
	tb := map[string]bool{}
	for _, t := range strings.Fields(spaceOut(b)) {
		tb[t] = true
	}
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	shared := 0
	for t := range ta {
		if tb[t] {
			shared++
		}
	}
	union := len(ta) + len(tb) - shared
	return float64(shared) / float64(union)
}

// levenshteinRatio is 1 minus the edit distance normalised by the longer input.
func levenshteinRatio(a, b string) float64 {
	if a == b {
		return 1
	}
	d := levenshtein([]rune(a), []rune(b))
	longer := len(a)
	if len(b) > longer {
		longer = len(b)
	}
	if longer == 0 {
		return 1
	}
	return 1 - float64(d)/float64(longer)
}

func levenshtein(a, b []rune) int {
	// Two-row variant: the full matrix is never needed for the distance alone.
	prev := make([]int, len(b)+1)
	cur := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min3(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(b)]
}

// jaroWinkler favours agreement in the first characters, which suits names
// where the distinguishing part usually comes first.
func jaroWinkler(a, b string) float64 {
	j := jaro([]rune(a), []rune(b))
	if j < 0.7 {
		// Below this the prefix bonus flatters a pair that is not close.
		return j
	}
	ra, rb := []rune(a), []rune(b)
	prefix := 0
	for prefix < 4 && prefix < len(ra) && prefix < len(rb) && ra[prefix] == rb[prefix] {
		prefix++
	}
	return j + float64(prefix)*0.1*(1-j)
}

func jaro(a, b []rune) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	window := max2(len(a), len(b))/2 - 1
	if window < 0 {
		window = 0
	}
	aMatched := make([]bool, len(a))
	bMatched := make([]bool, len(b))

	matches := 0
	for i := range a {
		lo := i - window
		if lo < 0 {
			lo = 0
		}
		hi := i + window + 1
		if hi > len(b) {
			hi = len(b)
		}
		for j := lo; j < hi; j++ {
			if bMatched[j] || a[i] != b[j] {
				continue
			}
			aMatched[i], bMatched[j] = true, true
			matches++
			break
		}
	}
	if matches == 0 {
		return 0
	}

	transpositions := 0
	k := 0
	for i := range a {
		if !aMatched[i] {
			continue
		}
		for !bMatched[k] {
			k++
		}
		if a[i] != b[k] {
			transpositions++
		}
		k++
	}
	m := float64(matches)
	return (m/float64(len(a)) + m/float64(len(b)) + (m-float64(transpositions)/2)/m) / 3
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func max2(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min3(a, b, c int) int {
	if b < a {
		a = b
	}
	if c < a {
		a = c
	}
	return a
}
