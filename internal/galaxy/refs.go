package galaxy

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// Reference is one report documenting an entry.
type Reference struct {
	URL    string `json:"url"`
	Domain string `json:"domain,omitempty" jsonschema:"publisher host, e.g. securelist.com — a rough proxy for who documented this"`

	// SelfReferential marks a link back to the entry's own catalogue page
	// rather than to a report about it. Every Malpedia entry carries one as
	// its first reference, so leaving them unmarked puts a non-report at the
	// top of thousands of lists.
	SelfReferential bool `json:"self_referential,omitempty"`
}

// selfReferentialHosts publish a page per catalogue entry. A link to one is
// the entry's own record, not a report analysing it.
var selfReferentialHosts = map[string]bool{
	"malpedia.caad.fkie.fraunhofer.de": true,
	"attack.mitre.org":                 true,
	"apt.etda.or.th":                   true,
}

// References returns the reports documenting a node.
//
// They live in meta.refs and nowhere else: the references galaxy holds 5,000+
// entries but nothing links to it, so no traversal reaches a report. That is
// why this is an accessor rather than a walk — gx_neighbors will never find
// them, however deep it goes.
func (n *Node) References() []Reference {
	if n == nil || len(n.Meta) == 0 {
		return nil
	}
	var meta struct {
		Refs         []string `json:"refs"`
		OfficialRefs []string `json:"official-refs"`
		References   []string `json:"references"`
	}
	if json.Unmarshal(n.Meta, &meta) != nil {
		return nil
	}

	seen := map[string]bool{}
	var out []Reference
	for _, list := range [][]string{meta.Refs, meta.OfficialRefs, meta.References} {
		for _, raw := range list {
			raw = strings.TrimSpace(raw)
			if raw == "" || seen[raw] {
				continue
			}
			seen[raw] = true
			ref := Reference{URL: raw}
			if u, err := url.Parse(raw); err == nil {
				ref.Domain = strings.TrimPrefix(strings.ToLower(u.Host), "www.")
				ref.SelfReferential = selfReferentialHosts[ref.Domain]
			}
			out = append(out, ref)
		}
	}

	// Reports first, catalogue pages last: the question is almost always "what
	// has been written about this", and the entry's own record answers nothing.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SelfReferential != out[j].SelfReferential {
			return !out[i].SelfReferential
		}
		return false
	})
	return out
}

// ReferenceSummary counts how many reports come from one publisher.
type ReferenceSummary struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// ByPublisher groups references by host, most prolific first.
//
// A crude proxy for who has documented an entry, and worth seeing: an entry
// described by one vendor is a single point of view, one described by eight is
// something several teams looked at independently.
func ByPublisher(refs []Reference) []ReferenceSummary {
	counts := map[string]int{}
	for _, r := range refs {
		if r.SelfReferential || r.Domain == "" {
			continue
		}
		counts[r.Domain]++
	}
	out := make([]ReferenceSummary, 0, len(counts))
	for d, c := range counts {
		out = append(out, ReferenceSummary{Domain: d, Count: c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Domain < out[j].Domain
	})
	return out
}
