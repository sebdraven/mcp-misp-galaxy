// Package galaxy loads the MISP galaxy JSON corpus into an immutable in-memory
// graph and answers name-resolution and traversal queries against it.
//
// The graph is built once and never mutated, so reads need no locking. A
// reload builds a fresh graph alongside the live one and swaps it in
// atomically; in-flight readers keep walking the old graph until they are done
// and it is collected normally.
package galaxy

import (
	"encoding/json"
	"strings"
)

// ---- on-disk shapes ---------------------------------------------------------
//
// Only the fields the graph needs are modelled. Everything else stays in Raw so
// a caller can ask for it without the loader having to know the shape of every
// galaxy's meta block — which varies a lot between galaxies.

// clusterFile is one file under clusters/.
type clusterFile struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	UUID        string         `json:"uuid"`
	Description string         `json:"description"`
	Category    string         `json:"category"`
	Source      string         `json:"source"`
	Version     int            `json:"version"`
	Values      []clusterValue `json:"values"`
}

// clusterValue is one entry in a cluster's values array — one node.
type clusterValue struct {
	UUID        string          `json:"uuid"`
	Value       string          `json:"value"`
	Description string          `json:"description"`
	Revoked     bool            `json:"revoked"`
	Meta        json.RawMessage `json:"meta"`
	Related     []relatedEntry  `json:"related"`
}

// relatedEntry is one declared edge. The dest-uuid key is hyphenated, so the
// tag is mandatory: field-name inference would never find it.
type relatedEntry struct {
	DestUUID string   `json:"dest-uuid"`
	Type     string   `json:"type"`
	Tags     []string `json:"tags,omitempty"`
}

// metaBlock is the only part of meta the index cares about. Decoded separately
// from Raw so the rest of meta stays untouched.
type metaBlock struct {
	Synonyms []string `json:"synonyms"`
}

// galaxyFile is one file under galaxies/ — the galaxy definition itself,
// carrying the human-readable name for a cluster type.
type galaxyFile struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	UUID        string `json:"uuid"`
	Description string `json:"description"`
	Namespace   string `json:"namespace"`
	Icon        string `json:"icon"`
}

// ---- graph shapes -----------------------------------------------------------

// Node is one cluster value. Pointers are stable for the lifetime of a Graph.
type Node struct {
	UUID        string
	Value       string
	Galaxy      string // the cluster's "type", e.g. threat-actor, mitre-attack-pattern
	Description string
	Synonyms    []string

	// Meta is the value's meta block, kept encoded. Decoding every meta map at
	// load time is the single biggest memory cost in this corpus and most nodes
	// are never looked at; callers decode the ones they need.
	Meta json.RawMessage

	// Dangling marks a node that only ever appeared as a related.dest-uuid,
	// never as a value of its own. Usually it means a galaxy is missing from
	// the checkout rather than that the data is broken — worth surfacing, not
	// worth dropping.
	Dangling bool

	// Revoked mirrors the corpus's own deprecation flag: merged or withdrawn
	// entries, common in the ATT&CK galaxies. Kept and demoted rather than
	// hidden — an older report may legitimately cite a revoked id, and finding
	// nothing would be worse than finding it flagged.
	Revoked bool

	// Synthetic marks an entry the corpus published without a uuid. Its UUID
	// field then holds a key this loader derived from galaxy and value, stable
	// across loads of the same checkout but meaningless outside this process —
	// so it must never be reported as a corpus identifier.
	Synthetic bool

	// GroupCount is how many distinct threat actors are linked to this entry.
	//
	// It measures specificity, not importance. A technique used by 79 groups
	// tells you almost nothing about who is behind an intrusion, while one used
	// by a single group is a candidate behavioural signature. The CTI
	// literature is blunt about this: most techniques are generic, and treating
	// them as evidence is how misattribution happens.
	GroupCount int

	Out []Edge
	In  []Edge
}

// Edge is one typed relation between two nodes.
//
// Several declarations can back the same link — the corpus may declare it from
// both sides, or under more than one relation type. They are merged into a
// single edge carrying how many declarations support it, because a link
// asserted once is weaker evidence than one asserted repeatedly.
type Edge struct {
	To   *Node
	Type string // the first relation type declared for this link

	// Types lists every relation type declared between the two nodes.
	Types []string

	// Confidence counts the declarations backing this link. It is a weaker
	// signal than the cross-vendor agreement the CTI literature uses: the
	// corpus is one source, so this counts repetition within it, not
	// independent corroboration.
	Confidence int

	// Bridge marks a link whose removal would disconnect the graph. Combined
	// with a Confidence of 1, it is the profile of an assertion that merges two
	// otherwise separate clusters on its own — the single most likely place for
	// a wrong link to have outsized consequences.
	Bridge bool
}

// TagNamespace prefixes every canonical MISP galaxy tag.
const TagNamespace = "misp-galaxy"

// Tag renders the canonical MISP tag for this entry, e.g.
//
//	misp-galaxy:threat-actor="APT28"
//
// This is what gets attached to a MISP event. A UUID identifies the entry but
// attaches to nothing, so every result carries the tag alongside it.
//
// Empty for a dangling node: it has no galaxy and no value, so there is
// nothing to tag with.
func (n *Node) Tag() string {
	if n == nil || n.Galaxy == "" || n.Value == "" {
		return ""
	}
	return Tag(n.Galaxy, n.Value)
}

// Tag builds a canonical MISP galaxy tag from a galaxy type and a value.
//
// A handful of corpus values contain a double quote, which would break the
// quoted form; they are escaped rather than dropped, since a tag that cannot
// round-trip is worse than an unusual-looking one.
func Tag(galaxyType, value string) string {
	if galaxyType == "" || value == "" {
		return ""
	}
	return TagNamespace + ":" + galaxyType + `="` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

// ActorGalaxies are the galaxy types whose entries denote a threat actor.
//
// Specificity is counted against these and nothing else: "how many actors use
// this" is the question that separates a behavioural signature from background
// noise. Counting every neighbour instead would make a technique linked to
// dozens of sub-techniques look popular when no actor uses it at all.
var ActorGalaxies = map[string]bool{
	"threat-actor":                          true,
	"mitre-intrusion-set":                   true,
	"mitre-enterprise-attack-intrusion-set":  true,
	"mitre-ics-groups":                      true,
	"mitre-mobile-attack-intrusion-set":     true,
	"groups":                                true,
	"microsoft-activity-group":              true,
	"360net-threat-actor":                   true,
	"intelligence-agency":                   true,
}

// GalaxyInfo describes one galaxy and how many nodes it contributed.
type GalaxyInfo struct {
	Type        string `json:"type"`
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Description string `json:"description,omitempty"`
	Nodes       int    `json:"nodes"`
}

// Stats summarises a built graph.
type Stats struct {
	Nodes       int    `json:"nodes"`
	Edges       int    `json:"edges"`
	Bridges     int    `json:"bridges" jsonschema:"links whose removal would disconnect the graph; those with a confidence of 1 are the weakest joins in the corpus"`
	Dangling    int    `json:"dangling" jsonschema:"nodes referenced by an edge but never defined as a cluster value"`
	Revoked     int    `json:"revoked" jsonschema:"nodes the corpus marks as deprecated"`
	Synthetic   int    `json:"synthetic" jsonschema:"entries the corpus published without a uuid; searchable but never the target of a relation"`
	Galaxies    int    `json:"galaxies"`
	IndexedKeys int    `json:"indexed_keys" jsonschema:"distinct normalised names and synonyms in the resolver index"`
	SourceRef   string `json:"source_ref,omitempty" jsonschema:"commit of the misp-galaxy checkout the graph was built from"`
	LoadedAt    string `json:"loaded_at,omitempty"`
}
