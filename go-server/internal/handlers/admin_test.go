package handlers

import (
	"strings"
	"testing"
)

func TestOpsTaskList(t *testing.T) {
	tasks := opsTaskList()

	expectedOrder := []string{
		"css-cohesion",
		"feature-inventory",
		"scientific-colors",
		"render-diagrams",
		"figma-bundle",
		"figma-verify",
		"miro-sync",
		"full-pipeline",
	}

	if len(tasks) != len(expectedOrder) {
		t.Fatalf("expected %d tasks, got %d", len(expectedOrder), len(tasks))
	}

	for i, expected := range expectedOrder {
		if tasks[i].ID != expected {
			t.Errorf("task[%d].ID = %q, want %q", i, tasks[i].ID, expected)
		}
	}
}

func TestOpsTaskList_Labels(t *testing.T) {
	tasks := opsTaskList()
	for _, task := range tasks {
		if task.Label == "" {
			t.Errorf("task %q has empty label", task.ID)
		}
		if task.Icon == "" {
			t.Errorf("task %q has empty icon", task.ID)
		}
		if task.Command == "" {
			t.Errorf("task %q has empty command", task.ID)
		}
		if len(task.Args) == 0 {
			t.Errorf("task %q has empty args", task.ID)
		}
	}
}

func TestOpsWhitelist_AllEntriesPresent(t *testing.T) {
	expectedIDs := []string{
		"css-cohesion",
		"feature-inventory",
		"scientific-colors",
		"render-diagrams",
		"figma-bundle",
		"figma-verify",
		"miro-sync",
		"full-pipeline",
	}
	for _, id := range expectedIDs {
		if _, ok := opsWhitelist[id]; !ok {
			t.Errorf("expected opsWhitelist to contain %q", id)
		}
	}
}

func TestOpsWhitelist_Commands(t *testing.T) {
	nodeCommands := []string{"css-cohesion", "feature-inventory", "scientific-colors", "figma-bundle", "figma-verify", "miro-sync", "full-pipeline"}
	for _, id := range nodeCommands {
		task := opsWhitelist[id]
		if task.Command != "node" {
			t.Errorf("task %q command = %q, want 'node'", id, task.Command)
		}
	}

	renderTask := opsWhitelist["render-diagrams"]
	if renderTask.Command != "bash" {
		t.Errorf("render-diagrams command = %q, want 'bash'", renderTask.Command)
	}
}

func TestOpsTaskList_Count(t *testing.T) {
	tasks := opsTaskList()
	if len(tasks) != 8 {
		t.Errorf("expected 8 ops tasks, got %d", len(tasks))
	}
}

func TestOpsTaskList_IDsMatchWhitelist(t *testing.T) {
	tasks := opsTaskList()
	for _, task := range tasks {
		if wl, ok := opsWhitelist[task.ID]; !ok {
			t.Errorf("task %q not found in opsWhitelist", task.ID)
		} else if wl.Label != task.Label {
			t.Errorf("task %q label mismatch: list=%q whitelist=%q", task.ID, task.Label, wl.Label)
		}
	}
}

func TestOpsWhitelist_ScriptPaths(t *testing.T) {
	for id, task := range opsWhitelist {
		if len(task.Args) == 0 {
			t.Errorf("task %q has no args", id)
			continue
		}
		arg := task.Args[0]
		if !strings.HasPrefix(arg, "scripts/") {
			t.Errorf("task %q arg %q does not start with scripts/", id, arg)
		}
	}
}

func TestOpsTaskStruct(t *testing.T) {
	task := opsTask{
		ID:      "test-task",
		Label:   "Test Task",
		Icon:    "fa-test",
		Command: "echo",
		Args:    []string{"hello"},
	}
	if task.ID != "test-task" {
		t.Errorf("unexpected ID: %s", task.ID)
	}
	if task.Label != "Test Task" {
		t.Errorf("unexpected Label: %s", task.Label)
	}
}

func TestAdminConstants(t *testing.T) {
	if timeFormatAdmin != "2006-01-02 15:04" {
		t.Errorf("unexpected timeFormatAdmin: %q", timeFormatAdmin)
	}
}

func TestAdminStatsZeroValue(t *testing.T) {
	s := AdminStats{}
	if s.TotalUsers != 0 || s.TotalAnalyses != 0 || s.UniqueDomainsCount != 0 {
		t.Error("expected zero values for AdminStats")
	}
}

func TestAdminUserStruct(t *testing.T) {
	u := AdminUser{
		ID:    1,
		Email: "test@example.com",
		Name:  "Test",
		Role:  "admin",
	}
	if u.ID != 1 {
		t.Errorf("unexpected ID: %d", u.ID)
	}
	if u.Email != "test@example.com" {
		t.Errorf("unexpected Email: %s", u.Email)
	}
	if u.Role != "admin" {
		t.Errorf("unexpected Role: %s", u.Role)
	}
}

func TestAdminAnalysisStruct(t *testing.T) {
	a := AdminAnalysis{
		ID:       42,
		Domain:   "example.com",
		Success:  true,
		Duration: "2.5s",
	}
	if a.ID != 42 {
		t.Errorf("unexpected ID: %d", a.ID)
	}
	if !a.Success {
		t.Error("expected Success=true")
	}
}

func TestAdminICAERunStruct(t *testing.T) {
	r := AdminICAERun{
		ID:          1,
		AppVersion:  "v1.0",
		TotalCases:  100,
		TotalPassed: 95,
		TotalFailed: 5,
		DurationMs:  1500,
	}
	if r.TotalPassed+r.TotalFailed != r.TotalCases {
		t.Errorf("passed+failed should equal total: %d+%d != %d", r.TotalPassed, r.TotalFailed, r.TotalCases)
	}
}

func TestAdminScannerAlertStruct(t *testing.T) {
	a := AdminScannerAlert{
		ID:     1,
		Domain: "suspicious.com",
		Source: "cisa",
		IP:     "1.2.3.4",
	}
	if a.Domain != "suspicious.com" {
		t.Errorf("unexpected Domain: %s", a.Domain)
	}
	if a.Source != "cisa" {
		t.Errorf("unexpected Source: %s", a.Source)
	}
}
