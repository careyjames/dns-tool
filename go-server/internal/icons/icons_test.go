package icons

import (
	"html/template"
	"strings"
	"testing"
)

func TestIconExists(t *testing.T) {
	tests := []struct {
		name   string
		exists bool
	}{
		{"shield", true},
		{"lock", true},
		{"nonexistent-icon-xyz", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IconExists(tt.name); got != tt.exists {
			t.Errorf("IconExists(%q) = %v, want %v", tt.name, got, tt.exists)
		}
	}
}

func TestIcon_KnownIcon(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Fatal("registry is empty")
	}
	name := names[0]
	svg := Icon(name)
	s := string(svg)
	if !strings.Contains(s, "<svg") {
		t.Errorf("Icon(%q) missing <svg tag: %s", name, s)
	}
	if !strings.Contains(s, "icon-"+name) {
		t.Errorf("Icon(%q) missing class: %s", name, s)
	}
	if !strings.Contains(s, "<path d=") {
		t.Errorf("Icon(%q) missing path: %s", name, s)
	}
	if !strings.Contains(s, `aria-hidden="true"`) {
		t.Errorf("Icon(%q) missing aria-hidden: %s", name, s)
	}
}

func TestIcon_UnknownIcon(t *testing.T) {
	svg := Icon("nonexistent-icon-xyz")
	s := string(svg)
	if !strings.Contains(s, "icon not found") {
		t.Errorf("expected fallback comment for unknown icon, got: %s", s)
	}
}

func TestIcon_ExtraClasses(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Fatal("registry is empty")
	}
	svg := Icon(names[0], "text-danger", "ms-2")
	s := string(svg)
	if !strings.Contains(s, "text-danger") {
		t.Errorf("expected extra class text-danger in: %s", s)
	}
	if !strings.Contains(s, "ms-2") {
		t.Errorf("expected extra class ms-2 in: %s", s)
	}
}

func TestIcon_EmbeddedClasses(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Fatal("registry is empty")
	}
	nameWithClass := names[0] + " my-custom-class"
	svg := Icon(nameWithClass)
	s := string(svg)
	if !strings.Contains(s, "my-custom-class") {
		t.Errorf("expected embedded class in: %s", s)
	}
}

func TestIcon_EmbeddedAndExtraClasses(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Fatal("registry is empty")
	}
	svg := Icon(names[0]+" embedded-cls", "extra-cls")
	s := string(svg)
	if !strings.Contains(s, "embedded-cls") {
		t.Errorf("expected embedded class in: %s", s)
	}
	if !strings.Contains(s, "extra-cls") {
		t.Errorf("expected extra class in: %s", s)
	}
}

func TestAllIconNames(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Fatal("expected non-empty icon names")
	}
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if n == "" {
			t.Error("found empty icon name")
		}
		if seen[n] {
			t.Errorf("duplicate icon name: %s", n)
		}
		seen[n] = true
	}
}

func TestIconSVGJSON(t *testing.T) {
	result := IconSVGJSON()
	if len(result) == 0 {
		t.Fatal("expected non-empty SVG JSON map")
	}
	for name, svg := range result {
		if !strings.Contains(svg, "<svg") {
			t.Errorf("IconSVGJSON[%s] missing <svg: %s", name, svg)
		}
		if !strings.Contains(svg, "icon-"+name) {
			t.Errorf("IconSVGJSON[%s] missing class: %s", name, svg)
		}
	}
}

func TestIconSVGJSON_ConsistentWithAllNames(t *testing.T) {
	names := AllIconNames()
	jsonMap := IconSVGJSON()
	if len(names) != len(jsonMap) {
		t.Errorf("AllIconNames count %d != IconSVGJSON count %d", len(names), len(jsonMap))
	}
	for _, n := range names {
		if _, ok := jsonMap[n]; !ok {
			t.Errorf("icon %q in AllIconNames but not in IconSVGJSON", n)
		}
	}
}

func TestIcon_HTMLEscapesUnknown(t *testing.T) {
	svg := Icon("<script>alert(1)</script>")
	s := string(svg)
	if strings.Contains(s, "<script>") {
		t.Error("unknown icon name was not HTML-escaped")
	}
}

func TestIcon_ReturnType(t *testing.T) {
	names := AllIconNames()
	if len(names) == 0 {
		t.Skip("no icons")
	}
	var _ template.HTML = Icon(names[0])
}

func TestRegistryNotEmpty(t *testing.T) {
	if len(registry) == 0 {
		t.Fatal("icon registry is empty")
	}
	for name, def := range registry {
		if name == "" {
			t.Error("empty key in registry")
		}
		if def.W <= 0 || def.H <= 0 {
			t.Errorf("icon %q has invalid dimensions: %dx%d", name, def.W, def.H)
		}
		if def.D == "" {
			t.Errorf("icon %q has empty path data", name)
		}
	}
}
