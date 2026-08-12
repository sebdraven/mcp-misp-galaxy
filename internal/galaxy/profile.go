package galaxy

import (
	"sort"
	"strings"
)

// ProfileGroup is one slice of a profile: everything of a given kind linked to
// the entry.
type ProfileGroup struct {
	Galaxy   string      `json:"galaxy"`
	Count    int         `json:"count"`
	Specific int         `json:"specific" jsonschema:"how many of these are linked to exactly one actor, and so could serve as a signature"`
	Generic  int         `json:"generic" jsonschema:"how many are shared by enough actors to distinguish nobody"`
	Entries  []Neighbour `json:"entries"`
}

// Profile is what a corpus records about one entry, grouped by the kind of
// thing it is linked to.
//
// The CTI literature works in these terms — a group's profile is the set of
// techniques, software and vulnerabilities attributed to it — because that is
// the unit attribution claims are made about. A flat list of neighbours holds
// the same facts but hides the shape: fifty techniques and one actor reads very
// differently from one technique and fifty actors.
type Profile struct {
	UUID   string `json:"uuid"`
	Tag    string `json:"tag,omitempty"`
	Value  string `json:"value"`
	Galaxy string `json:"galaxy"`

	Total    int `json:"total" jsonschema:"entries linked at this depth"`
	Specific int `json:"specific" jsonschema:"linked to exactly one actor across the whole profile"`
	Generic  int `json:"generic" jsonschema:"shared widely enough to carry no attribution value"`

	// Unattributed counts entries no actor is linked to. Kept separate from
	// Specific on purpose: an entry with one actor is evidence, an entry with
	// none is a gap in the corpus, and conflating them is how under-reporting
	// becomes false confidence.
	Unattributed int `json:"unattributed" jsonschema:"linked to no actor at all — absence of data, not exclusivity"`

	Groups []ProfileGroup `json:"groups"`
	Note   string         `json:"note,omitempty"`
}

// Profile builds the profile of a node at the given depth.
func (g *Graph) Profile(uuid string, depth, limit int) (Profile, bool) {
	n, ok := g.nodes[uuid]
	if !ok {
		return Profile{}, false
	}
	if depth <= 0 {
		depth = 1
	}
	if limit <= 0 {
		limit = 500
	}

	neighbours := g.Neighbours(uuid, NeighbourOpts{Depth: depth, Limit: limit})

	p := Profile{
		UUID: n.UUID, Tag: n.Tag(), Value: n.Value, Galaxy: n.Galaxy,
		Total: len(neighbours),
	}

	byGalaxy := map[string][]Neighbour{}
	for _, nb := range neighbours {
		key := nb.Galaxy
		if key == "" {
			key = "(undefined in this checkout)"
		}
		byGalaxy[key] = append(byGalaxy[key], nb)

		switch {
		case nb.Generic:
			p.Generic++
		case nb.GroupCount == 1:
			p.Specific++
		case nb.GroupCount == 0 && !ActorGalaxies[strings.ToLower(nb.Galaxy)]:
			p.Unattributed++
		}
	}

	for galaxyType, entries := range byGalaxy {
		grp := ProfileGroup{Galaxy: galaxyType, Count: len(entries), Entries: entries}
		for _, e := range entries {
			switch {
			case e.Generic:
				grp.Generic++
			case e.GroupCount == 1:
				grp.Specific++
			}
		}
		p.Groups = append(p.Groups, grp)
	}

	// Actor galaxies first, then by size: walking out from a malware, who uses
	// it is the answer and the technique list is context.
	sort.Slice(p.Groups, func(i, j int) bool {
		ai := ActorGalaxies[strings.ToLower(p.Groups[i].Galaxy)]
		aj := ActorGalaxies[strings.ToLower(p.Groups[j].Galaxy)]
		if ai != aj {
			return ai
		}
		if p.Groups[i].Count != p.Groups[j].Count {
			return p.Groups[i].Count > p.Groups[j].Count
		}
		return p.Groups[i].Galaxy < p.Groups[j].Galaxy
	})

	switch {
	case p.Total == 0:
		p.Note = "nothing is linked to this entry in this corpus; relations live almost entirely in the MITRE galaxies, so another entry for the same thing may be richer"
	case p.Specific == 0 && p.Total > 0:
		// The finding the literature keeps arriving at: most entries have
		// nothing exclusive about them, and saying so is more useful than
		// letting a caller assume the list is discriminating.
		p.Note = "no entry in this profile is exclusive to a single actor, so none of it can identify who was behind an intrusion"
	}
	return p, true
}
