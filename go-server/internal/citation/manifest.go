// dns-tool:scrutiny science
package citation

import (
	"sort"
	"strings"
	"sync"
)

type ManifestEntry struct {
	ID      string `json:"id"`
	Section string `json:"section,omitempty"`
	Title   string `json:"title"`
	URL     string `json:"url"`
	Type    string `json:"type"`
}

type Manifest struct {
	mu   sync.Mutex
	seen map[string]struct{}
	ids  []string
}

func NewManifest() *Manifest {
	return &Manifest{
		seen: make(map[string]struct{}),
	}
}

func (m *Manifest) Cite(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.seen[id]; ok {
		return
	}
	m.seen[id] = struct{}{}
	m.ids = append(m.ids, id)
}

func (m *Manifest) CiteSection(baseID, section string) {
	full := baseID + "§" + section
	m.Cite(full)
}

func (m *Manifest) IDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.ids))
	copy(out, m.ids)
	sort.Strings(out)
	return out
}

func (m *Manifest) Entries(reg *Registry) []ManifestEntry {
	ids := m.IDs()
	entries := make([]ManifestEntry, 0, len(ids))
	for _, id := range ids {
		base := id
		section := ""
		if idx := strings.Index(id, "§"); idx != -1 {
			base = strings.TrimSpace(id[:idx])
			section = strings.TrimSpace(id[idx+len("§"):])
		}

		e, ok := reg.Lookup(base)
		if !ok {
			continue
		}

		me := ManifestEntry{
			ID:      base,
			Section: section,
			Title:   e.Title,
			URL:     e.URL,
			Type:    e.Type,
		}

		if section != "" {
			me.URL = e.URL + "#section-" + section
		}

		entries = append(entries, me)
	}
	return entries
}
