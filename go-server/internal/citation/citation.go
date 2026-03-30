// dns-tool:scrutiny science
package citation

import (
        "embed"
        "fmt"
        "log/slog"
        "strings"
        "sync"

        "github.com/goccy/go-yaml"
)

//go:embed registry.yaml
var registryFS embed.FS

type Entry struct {
        ID             string `yaml:"id"             json:"id"`
        Type           string `yaml:"type"           json:"type"`
        Title          string `yaml:"title"          json:"title"`
        URL            string `yaml:"url"            json:"url"`
        Status         string `yaml:"status"         json:"status"`
        FunctionalArea string `yaml:"functional_area" json:"functional_area"`
        Publisher      string `yaml:"publisher"      json:"publisher"`
        Date           string `yaml:"date,omitempty" json:"date,omitempty"`
        ObsoletedBy    string `yaml:"obsoleted_by,omitempty" json:"obsoleted_by,omitempty"`
        Obsoletes      string `yaml:"obsoletes,omitempty"    json:"obsoletes,omitempty"`
}

type registryFile struct {
        Citations []Entry `yaml:"citations"`
}

type Registry struct {
        mu      sync.RWMutex
        entries map[string]*Entry
        all     []Entry
}

var (
        globalRegistry *Registry
        initOnce       sync.Once
)

func Global() *Registry {
        initOnce.Do(func() {
                r, err := loadEmbedded()
                if err != nil {
                        slog.Error("Failed to load citation registry", "error", err)
                        r = &Registry{entries: make(map[string]*Entry)}
                }
                globalRegistry = r
        })
        return globalRegistry
}

func loadEmbedded() (*Registry, error) {
        data, err := registryFS.ReadFile("registry.yaml")
        if err != nil {
                return nil, fmt.Errorf("read embedded registry: %w", err)
        }
        return parseRegistry(data)
}

func parseRegistry(data []byte) (*Registry, error) {
        var rf registryFile
        if err := yaml.Unmarshal(data, &rf); err != nil {
                return nil, fmt.Errorf("parse registry YAML: %w", err)
        }

        r := &Registry{
                entries: make(map[string]*Entry, len(rf.Citations)),
                all:     rf.Citations,
        }
        for i := range rf.Citations {
                e := &rf.Citations[i]
                if _, exists := r.entries[e.ID]; exists {
                        return nil, fmt.Errorf("duplicate citation ID: %s", e.ID)
                }
                if e.ID == "" {
                        return nil, fmt.Errorf("citation entry at index %d has empty ID", i)
                }
                r.entries[e.ID] = e
        }

        slog.Info("Citation registry loaded", "entries", len(r.entries))
        return r, nil
}

func (r *Registry) Lookup(id string) (*Entry, bool) {
        r.mu.RLock()
        defer r.mu.RUnlock()

        base := id
        if idx := strings.Index(id, "§"); idx != -1 {
                base = strings.TrimSpace(id[:idx])
        }

        e, ok := r.entries[base]
        return e, ok
}

func (r *Registry) MustLookup(id string) *Entry {
        e, ok := r.Lookup(id)
        if !ok {
                slog.Warn("Citation not found in registry", "id", id)
                return &Entry{
                        ID:    id,
                        Title: id,
                        URL:   "",
                }
        }
        return e
}

func (r *Registry) ResolveRFC(id string) (rfcLabel string, rfcURL string) {
        section := ""
        base := id
        if idx := strings.Index(id, "§"); idx != -1 {
                base = strings.TrimSpace(id[:idx])
                section = strings.TrimSpace(id[idx+len("§"):])
        }

        e, ok := r.entries[base]
        if !ok {
                return id, ""
        }

        rfcNum := strings.TrimPrefix(base, "rfc:")
        if section != "" {
                rfcLabel = fmt.Sprintf("RFC %s §%s", rfcNum, section)
                rfcURL = fmt.Sprintf("%s#section-%s", e.URL, section)
        } else {
                rfcLabel = fmt.Sprintf("RFC %s", rfcNum)
                rfcURL = e.URL
        }
        return rfcLabel, rfcURL
}

func (r *Registry) ResolveSectionURL(id, section string) string {
        e, ok := r.Lookup(id)
        if !ok {
                return ""
        }
        if section == "" {
                return e.URL
        }
        return fmt.Sprintf("%s#section-%s", e.URL, section)
}

func (r *Registry) IsObsolete(id string) bool {
        e, ok := r.Lookup(id)
        if !ok {
                return false
        }
        return e.ObsoletedBy != ""
}

func (r *Registry) All() []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()
        out := make([]Entry, len(r.all))
        copy(out, r.all)
        return out
}

func (r *Registry) ByType(typ string) []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()
        var out []Entry
        for _, e := range r.all {
                if e.Type == typ {
                        out = append(out, e)
                }
        }
        return out
}

func (r *Registry) ByFunctionalArea(area string) []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()
        var out []Entry
        for _, e := range r.all {
                if e.FunctionalArea == area {
                        out = append(out, e)
                }
        }
        return out
}

func (r *Registry) ByStatus(status string) []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()
        var out []Entry
        for _, e := range r.all {
                if e.Status == status {
                        out = append(out, e)
                }
        }
        return out
}

func (r *Registry) Search(query string) []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()
        q := strings.ToLower(query)
        var out []Entry
        for _, e := range r.all {
                if strings.Contains(strings.ToLower(e.ID), q) ||
                        strings.Contains(strings.ToLower(e.Title), q) ||
                        strings.Contains(strings.ToLower(e.Publisher), q) ||
                        strings.Contains(strings.ToLower(e.FunctionalArea), q) {
                        out = append(out, e)
                }
        }
        return out
}

func (r *Registry) Filter(typ, status, area, query string) []Entry {
        r.mu.RLock()
        defer r.mu.RUnlock()

        var out []Entry
        q := strings.ToLower(query)
        for _, e := range r.all {
                if typ != "" && e.Type != typ {
                        continue
                }
                if status != "" && e.Status != status {
                        continue
                }
                if area != "" && e.FunctionalArea != area {
                        continue
                }
                if q != "" &&
                        !strings.Contains(strings.ToLower(e.ID), q) &&
                        !strings.Contains(strings.ToLower(e.Title), q) &&
                        !strings.Contains(strings.ToLower(e.Publisher), q) {
                        continue
                }
                out = append(out, e)
        }
        return out
}
