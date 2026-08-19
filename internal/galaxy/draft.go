package galaxy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DraftRelation is a relation to declare on a new entry.
type DraftRelation struct {
	DestUUID string   `json:"dest-uuid"`
	Tags     []string `json:"tags,omitempty"`
	Type     string   `json:"type"`
}

// DraftMeta is the metadata block of a new entry.
type DraftMeta struct {
	Date string   `json:"date,omitempty"`
	Refs []string `json:"refs,omitempty"`
}

// DraftEntry is a cluster entry ready to paste into a MISP galaxy file.
//
// Field order and JSON tags follow what the corpus already contains, so the
// block survives the repository's own `jq --sort-keys` pass unchanged.
type DraftEntry struct {
	Description string          `json:"description"`
	Meta        DraftMeta       `json:"meta"`
	Related     []DraftRelation `json:"related,omitempty"`
	UUID        string          `json:"uuid"`
	Value       string          `json:"value"`
}

// DraftConflict is an existing entry that stands in the way of a new one.
type DraftConflict struct {
	UUID       string  `json:"uuid"`
	Value      string  `json:"value"`
	Galaxy     string  `json:"galaxy"`
	Tag        string  `json:"tag,omitempty"`
	MatchedVia string  `json:"matched_via" jsonschema:"the name or synonym that collided"`
	Similarity float64 `json:"similarity,omitempty" jsonschema:"absent for an exact collision"`
}

// DraftResult is what came of a drafting request.
type DraftResult struct {
	Name    string `json:"name"`
	Galaxy  string `json:"galaxy"`
	Refused bool   `json:"refused" jsonschema:"true when the name already exists and contributing it would create a duplicate"`

	// Exact lists entries already carrying this name, canonical or synonym.
	// Any at all means the draft is refused: the naming literature traces most
	// alias proliferation to exactly this, a name added without checking.
	Exact []DraftConflict `json:"exact,omitempty"`

	// Near lists entries whose names are close. These do not block the draft —
	// APT28 and APT29 are near and distinct — but they are the pairs a
	// reviewer will ask about, so they come back with it.
	Near []DraftConflict `json:"near,omitempty"`

	Entry *DraftEntry `json:"entry,omitempty"`
	Note  string      `json:"note"`
}

// DraftOpts describes the entry to prepare.
type DraftOpts struct {
	Name        string
	Galaxy      string
	Description string
	Refs        []string
	Date        string

	// UsedBy is the UUID of an actor to link the new entry to. Optional: an
	// entry with no credible attribution is better filed unlinked than tied to
	// a guess.
	UsedBy string

	// Confidence is the estimative-language tag on that relation. Defaults to
	// "likely", the cautious reading, because a contributor is rarely the right
	// person to certify their own attribution.
	Confidence string
}

// estimativeTags are the values the corpus accepts on a relation.
var estimativeTags = map[string]bool{
	"almost-no-chance": true, "very-unlikely": true, "unlikely": true,
	"roughly-even-chance": true, "likely": true, "very-likely": true,
	"almost-certain": true,
}

// DraftClusterEntry prepares an entry for contribution, after checking that the
// name is not already in the corpus.
//
// The check is the point. Generating a UUID takes a line; establishing that a
// name is genuinely new is the work, and it is the step that gets skipped —
// which is how a corpus ends up with five names for one thing and no way to
// tell which are aliases and which are distinct entities.
func (g *Graph) DraftClusterEntry(opt DraftOpts) (DraftResult, error) {
	name := strings.TrimSpace(opt.Name)
	if name == "" {
		return DraftResult{}, fmt.Errorf("a name is required")
	}
	galaxyType := strings.TrimSpace(opt.Galaxy)
	if galaxyType == "" {
		return DraftResult{}, fmt.Errorf("a target galaxy is required")
	}
	// Resolved against the corpus rather than taken on trust: a typo like
	// "tools" would otherwise yield a JSON block for a cluster file that does
	// not exist, and the error would surface as a failed paste rather than as a
	// wrong galaxy.
	canonical := ""
	for _, info := range g.Galaxies() {
		if strings.EqualFold(info.Type, galaxyType) {
			canonical = info.Type
			break
		}
	}
	if canonical == "" {
		return DraftResult{}, fmt.Errorf("no galaxy %q in this corpus; call gx_galaxies for the list", galaxyType)
	}
	galaxyType = canonical

	res := DraftResult{Name: name, Galaxy: galaxyType}

	// Exact collisions, across the WHOLE corpus rather than the target galaxy:
	// a name already used elsewhere is what a reviewer will find, and the
	// question of whether the two are the same thing has to be answered before
	// contributing, not after.
	for _, n := range g.index[normalise(name)] {
		if n.Dangling {
			continue
		}
		matched := n.Value
		if normalise(n.Value) != normalise(name) {
			for _, syn := range n.Synonyms {
				if normalise(syn) == normalise(name) {
					matched = syn
					break
				}
			}
		}
		res.Exact = append(res.Exact, DraftConflict{
			UUID: n.UUID, Value: n.Value, Galaxy: n.Galaxy,
			Tag: n.Tag(), MatchedVia: matched,
		})
	}

	if len(res.Exact) > 0 {
		res.Refused = true
		res.Note = "this name already exists in the corpus. Contributing it again would create a duplicate; if the existing entry is a different thing that happens to share the name, say so explicitly in your pull request rather than adding a second entry silently"
		return res, nil
	}

	// Near misses are reported, never blocking.
	for _, m := range g.FuzzyResolve(name, FuzzyOpts{Limit: 10}) {
		res.Near = append(res.Near, DraftConflict{
			UUID: m.UUID, Value: m.Value, Galaxy: m.Galaxy,
			Tag: m.Tag, MatchedVia: m.Matched, Similarity: m.Similarity,
		})
	}

	uuid, err := newUUIDv4()
	if err != nil {
		return DraftResult{}, fmt.Errorf("generating uuid: %w", err)
	}

	entry := &DraftEntry{
		Description: strings.TrimSpace(opt.Description),
		Meta:        DraftMeta{Date: opt.Date, Refs: opt.Refs},
		UUID:        uuid,
		Value:       name,
	}

	if opt.UsedBy != "" {
		target, ok := g.Node(opt.UsedBy)
		if !ok {
			return DraftResult{}, fmt.Errorf("no entry with uuid %s to link to", opt.UsedBy)
		}
		if target.Dangling {
			return DraftResult{}, fmt.Errorf("%s is referenced but not defined in this corpus; linking to it would create a dangling relation", opt.UsedBy)
		}
		confidence := strings.TrimSpace(opt.Confidence)
		if confidence == "" {
			confidence = "likely"
		}
		if !estimativeTags[confidence] {
			return DraftResult{}, fmt.Errorf("unknown confidence %q; use one of almost-no-chance, very-unlikely, unlikely, roughly-even-chance, likely, very-likely, almost-certain", confidence)
		}
		entry.Related = []DraftRelation{{
			DestUUID: target.UUID,
			Tags:     []string{`estimative-language:likelihood-probability="` + confidence + `"`},
			Type:     "used-by",
		}}
	}

	res.Entry = entry
	switch {
	case len(res.Near) > 0:
		res.Note = "the name is new, but similar ones exist. They do not block the contribution — APT28 and APT29 are one character apart and are different actors — but a reviewer will ask, so check them and be ready to say why this is not one of them"
	case entry.Related == nil:
		res.Note = "the name is new to this corpus. No relation was declared: an entry with no credible attribution is better filed unlinked than tied to a guess"
	default:
		res.Note = "the name is new to this corpus. Paste the entry into the galaxy's values array, bump the file's version field, then run ./jq_all_the_things.sh and ./validate_all.sh before opening the pull request"
	}
	return res, nil
}

// MarshalDraft renders an entry as the corpus formats it: two-space indent,
// keys in the order the files already use.
func MarshalDraft(e *DraftEntry) (string, error) {
	if e == nil {
		return "", nil
	}
	b, err := json.MarshalIndent(e, "    ", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// newUUIDv4 generates a random UUID.
//
// Hand-rolled rather than pulling a dependency for sixteen bytes: the corpus
// only needs a well-formed v4, and adding a module to a server whose selling
// point is that it needs nothing at runtime would be a poor trade.
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}
