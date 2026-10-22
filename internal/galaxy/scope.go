package galaxy

import "strings"

// Scope selectors pick galaxies by the category or sub_category their
// definition declares, e.g. "category:named-threat" or "sub_category:actor".
const (
	SelectorCategory    = "category"
	SelectorSubCategory = "sub_category"
)

// IsScopeSelector reports whether a scope entry is a category or sub_category
// selector rather than a galaxy type.
func IsScopeSelector(entry string) bool {
	_, _, ok := parseSelector(entry)
	return ok
}

func parseSelector(entry string) (field, value string, ok bool) {
	key, value, found := strings.Cut(strings.TrimSpace(entry), ":")
	if !found {
		return "", "", false
	}
	switch field = strings.ToLower(strings.TrimSpace(key)); field {
	case SelectorCategory, SelectorSubCategory:
		return field, strings.TrimSpace(value), true
	}
	return "", "", false
}

// ExpandScope resolves the selectors in a scope against the galaxy inventory
// and returns their union with the galaxy types named explicitly, plus the
// entries that match no galaxy holding entries. Unresolved entries stay in the
// returned scope, so it never widens to the whole corpus. A nil or empty scope
// returns nil.
func (g *Graph) ExpandScope(entries []string) (galaxies, unresolved []string) {
	var inventory []GalaxyInfo
	seen := make(map[string]bool, len(entries))
	add := func(t string) {
		if k := strings.ToLower(t); !seen[k] {
			seen[k] = true
			galaxies = append(galaxies, t)
		}
	}
	for _, e := range entries {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		field, value, ok := parseSelector(e)
		if !ok {
			if !g.HasGalaxy(e) {
				unresolved = append(unresolved, e)
			}
			add(e)
			continue
		}
		if inventory == nil {
			inventory = g.Galaxies()
		}
		matched := false
		for _, info := range inventory {
			got := info.Category
			if field == SelectorSubCategory {
				got = info.SubCategory
			}
			if got != "" && strings.EqualFold(got, value) {
				add(info.Type)
				matched = true
			}
		}
		if !matched {
			unresolved = append(unresolved, e)
			add(e)
		}
	}
	return galaxies, unresolved
}
