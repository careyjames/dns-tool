// dns-tool:scrutiny science
package citation

import (
        "encoding/json"
        "fmt"
        "strings"
)

func EntriesToBibTeX(entries []ManifestEntry) string {
        var sb strings.Builder
        for _, e := range entries {
                key := bibKey(e.ID)
                if e.Section != "" {
                        key = bibKey(e.ID + "_s" + e.Section)
                }
                sb.WriteString(fmt.Sprintf("@misc{%s,\n", key))
                title := e.Title
                if e.Section != "" {
                        title = fmt.Sprintf("%s, Section %s", e.Title, e.Section)
                }
                sb.WriteString(fmt.Sprintf("  title  = {%s},\n", escapeBibTeX(title)))
                sb.WriteString(fmt.Sprintf("  url    = {%s},\n", e.URL))
                note := fmt.Sprintf("Stable ID: %s", e.ID)
                if e.Section != "" {
                        note = fmt.Sprintf("Stable ID: %s, Section: %s", e.ID, e.Section)
                }
                sb.WriteString(fmt.Sprintf("  note   = {%s},\n", note))
                sb.WriteString("}\n\n")
        }
        return sb.String()
}

func EntriesToRIS(entries []ManifestEntry) string {
        var sb strings.Builder
        for _, e := range entries {
                sb.WriteString("TY  - ELEC\n")
                title := e.Title
                if e.Section != "" {
                        title = fmt.Sprintf("%s, Section %s", e.Title, e.Section)
                }
                sb.WriteString(fmt.Sprintf("TI  - %s\n", title))
                sb.WriteString(fmt.Sprintf("UR  - %s\n", e.URL))
                id := e.ID
                if e.Section != "" {
                        id = fmt.Sprintf("%s§%s", e.ID, e.Section)
                }
                sb.WriteString(fmt.Sprintf("ID  - %s\n", id))
                sb.WriteString("ER  - \n\n")
        }
        return sb.String()
}

type cslItem struct {
        ID      string `json:"id"`
        Type    string `json:"type"`
        Title   string `json:"title"`
        URL     string `json:"URL"`
        Section string `json:"section,omitempty"`
}

func EntriesToCSLJSON(entries []ManifestEntry) (string, error) {
        items := make([]cslItem, 0, len(entries))
        for _, e := range entries {
                items = append(items, cslItem{
                        ID:      e.ID,
                        Type:    mapCSLType(e.Type),
                        Title:   e.Title,
                        URL:     e.URL,
                        Section: e.Section,
                })
        }
        data, err := json.MarshalIndent(items, "", "  ")
        if err != nil {
                return "", err
        }
        return string(data), nil
}

func SoftwareToBibTeX(title, version, doi, url, authorFamily, authorGiven, date string) string {
        var sb strings.Builder
        sb.WriteString("@software{dnstool,\n")
        sb.WriteString(fmt.Sprintf("  title   = {%s},\n", escapeBibTeX(title)))
        sb.WriteString(fmt.Sprintf("  author  = {%s, %s},\n", authorFamily, authorGiven))
        sb.WriteString(fmt.Sprintf("  version = {%s},\n", version))
        sb.WriteString(fmt.Sprintf("  date    = {%s},\n", date))
        sb.WriteString(fmt.Sprintf("  doi     = {%s},\n", doi))
        sb.WriteString(fmt.Sprintf("  url     = {%s},\n", url))
        sb.WriteString("}\n")
        return sb.String()
}

func SoftwareToRIS(title, version, doi, url, authorFamily, authorGiven, date string) string {
        var sb strings.Builder
        sb.WriteString("TY  - COMP\n")
        sb.WriteString(fmt.Sprintf("TI  - %s\n", title))
        sb.WriteString(fmt.Sprintf("AU  - %s, %s\n", authorFamily, authorGiven))
        sb.WriteString(fmt.Sprintf("ET  - %s\n", version))
        sb.WriteString(fmt.Sprintf("DA  - %s\n", date))
        sb.WriteString(fmt.Sprintf("DO  - %s\n", doi))
        sb.WriteString(fmt.Sprintf("UR  - %s\n", url))
        sb.WriteString("ER  - \n")
        return sb.String()
}

func SoftwareToCSLJSON(title, version, doi, url, authorFamily, authorGiven, date string) (string, error) {
        item := map[string]any{
                "id":      "dnstool",
                "type":    "software",
                "title":   title,
                "version": version,
                "DOI":     doi,
                "URL":     url,
                "author": []map[string]string{
                        {"family": authorFamily, "given": authorGiven},
                },
                "issued": map[string]any{
                        "raw": date,
                },
        }
        data, err := json.MarshalIndent([]any{item}, "", "  ")
        if err != nil {
                return "", err
        }
        return string(data), nil
}

func bibKey(id string) string {
        r := strings.NewReplacer(":", "_", ".", "_", "-", "_", " ", "_")
        return r.Replace(id)
}

func escapeBibTeX(s string) string {
        r := strings.NewReplacer(
                "&", `\&`,
                "%", `\%`,
                "#", `\#`,
                "_", `\_`,
        )
        return r.Replace(s)
}

func mapCSLType(entryType string) string {
        switch entryType {
        case "rfc", "draft":
                return "report"
        case "standard", "directive":
                return "standard"
        case "tool":
                return "software"
        case "data-source":
                return "webpage"
        default:
                return "document"
        }
}
