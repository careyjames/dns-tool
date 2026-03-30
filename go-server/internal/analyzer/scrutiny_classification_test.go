package analyzer

import (
        "bufio"
        "os"
        "path/filepath"
        "strings"
        "testing"
)

var scienceDirectories = map[string]bool{
        "go-server/internal/analyzer":            true,
        "go-server/internal/analyzer/ai_surface": true,
        "go-server/internal/icae":                true,
        "go-server/internal/icuae":               true,
        "go-server/internal/unified":             true,
        "go-server/internal/scanner":             true,
        "go-server/internal/dnsclient":           true,
        "go-server/internal/zoneparse":           true,
}

var scienceFiles = map[string]bool{
        "go-server/internal/config/rfc_citations.go": true,
}

var designDirectories = map[string]bool{
        "go-server/internal/handlers": true,
}

var plumbingDirectories = map[string]bool{
        "go-server/cmd/server":          true,
        "go-server/cmd/probe":           true,
        "go-server/internal/db":         true,
        "go-server/internal/dbq":        true,
        "go-server/internal/middleware":  true,
        "go-server/internal/models":     true,
        "go-server/internal/templates":  true,
        "go-server/internal/providers":  true,
        "go-server/internal/telemetry":  true,
        "go-server/internal/notifier":   true,
        "go-server/internal/wayback":    true,
        "go-server/internal/icons":      true,
}

var plumbingFiles = map[string]bool{
        "go-server/internal/config/config.go": true,
}

var validScrutinyValues = map[string]bool{
        "science":  true,
        "design":   true,
        "plumbing": true,
}

func isGoGeneratedFile(path string) bool {
        f, err := os.Open(path)
        if err != nil {
                return false
        }
        defer f.Close()
        scanner := bufio.NewScanner(f)
        if scanner.Scan() {
                return strings.Contains(scanner.Text(), "Code generated")
        }
        return false
}

func extractScrutinyTag(path string) (string, bool) {
        f, err := os.Open(path)
        if err != nil {
                return "", false
        }
        defer f.Close()

        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
                line := scanner.Text()
                trimmed := strings.TrimSpace(line)
                if trimmed == "// dns-tool:scrutiny science" ||
                        trimmed == "// dns-tool:scrutiny design" ||
                        trimmed == "// dns-tool:scrutiny plumbing" {
                        tag := strings.TrimPrefix(trimmed, "// dns-tool:scrutiny ")
                        return tag, true
                }
        }
        return "", false
}

func countScrutinyTags(path string) int {
        f, err := os.Open(path)
        if err != nil {
                return 0
        }
        defer f.Close()

        count := 0
        scanner := bufio.NewScanner(f)
        for scanner.Scan() {
                line := strings.TrimSpace(scanner.Text())
                if line == "// dns-tool:scrutiny science" ||
                        line == "// dns-tool:scrutiny design" ||
                        line == "// dns-tool:scrutiny plumbing" {
                        count++
                }
        }
        return count
}

func TestScrutinyClassificationAllFiles(t *testing.T) {
        root := filepath.Join("..", "..", "..")
        goServerDir := filepath.Join(root, "go-server")

        err := filepath.Walk(goServerDir, func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() {
                        return err
                }
                if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }
                if isGoGeneratedFile(path) {
                        return nil
                }

                relPath, _ := filepath.Rel(root, path)

                tag, found := extractScrutinyTag(path)
                if !found {
                        t.Errorf("MISSING scrutiny tag in %s — add '// dns-tool:scrutiny science|design|plumbing'", relPath)
                        return nil
                }
                if !validScrutinyValues[tag] {
                        t.Errorf("INVALID scrutiny tag '%s' in %s — must be science, design, or plumbing", tag, relPath)
                }

                tagCount := countScrutinyTags(path)
                if tagCount > 1 {
                        t.Errorf("DUPLICATE scrutiny tags (%d) in %s — each file must have exactly one", tagCount, relPath)
                }

                return nil
        })
        if err != nil {
                t.Fatalf("Walk failed: %v", err)
        }
}

func TestScrutinyClassificationConsistency(t *testing.T) {
        root := filepath.Join("..", "..", "..")
        goServerDir := filepath.Join(root, "go-server")

        err := filepath.Walk(goServerDir, func(path string, info os.FileInfo, err error) error {
                if err != nil || info.IsDir() {
                        return err
                }
                if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
                        return nil
                }

                tag, found := extractScrutinyTag(path)
                if !found {
                        return nil
                }

                relPath, _ := filepath.Rel(root, path)
                dir := filepath.Dir(relPath)

                if scienceDirectories[dir] && tag != "science" && !plumbingFiles[relPath] {
                        base := filepath.Base(path)
                        if !strings.Contains(base, "_oss") && base != "scrutiny_classification.go" {
                                t.Errorf("%s is in science directory %s but tagged '%s'", relPath, dir, tag)
                        }
                }

                if designDirectories[dir] && tag != "design" {
                        t.Errorf("%s is in design directory %s but tagged '%s'", relPath, dir, tag)
                }

                if plumbingDirectories[dir] && tag != "plumbing" {
                        t.Errorf("%s is in plumbing directory %s but tagged '%s'", relPath, dir, tag)
                }

                if scienceFiles[relPath] && tag != "science" {
                        t.Errorf("%s is a science file but tagged '%s'", relPath, tag)
                }

                if plumbingFiles[relPath] && tag != "plumbing" {
                        t.Errorf("%s is a plumbing file but tagged '%s'", relPath, tag)
                }

                return nil
        })
        if err != nil {
                t.Fatalf("Walk failed: %v", err)
        }
}
