// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
package handlers

import (
        "html/template"
        "net/http"
        "net/http/httptest"
        "net/url"
        "os"
        "path/filepath"
        "strings"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        tmplfuncs "dnstool/go-server/internal/templates"

        "github.com/gin-gonic/gin"
)

var defaultTestConfig = config.Config{
        AppVersion:      "26.37.11",
        MaintenanceNote: "",
        BetaPages:       map[string]bool{},
        BaseURL:         "https://test.example.com",
}

func mustParseTime(s string) time.Time {
        t, err := time.Parse(time.RFC3339, s)
        if err != nil {
                panic("mustParseTime: " + err.Error())
        }
        return t
}

func mustParseMinimalTemplate(name string) *template.Template {
        return template.Must(template.New(name).Parse("{{define \"" + name + "\"}}ok{{end}}"))
}

func mustLoadRealTemplates(t *testing.T) *template.Template {
        t.Helper()
        candidates := []string{
                "go-server/templates",
                "../../../go-server/templates",
                "../../../../go-server/templates",
        }
        var templatesDir string
        for _, c := range candidates {
                if _, err := os.Stat(filepath.Join(c, "_nav.html")); err == nil {
                        templatesDir = c
                        break
                }
        }
        if templatesDir == "" {
                cwd, _ := os.Getwd()
                t.Skipf("cannot find go-server/templates from cwd=%s", cwd)
        }
        globPattern := filepath.Join(templatesDir, "*.html")
        tmpl, err := template.New("").Funcs(tmplfuncs.FuncMap()).ParseGlob(globPattern)
        if err != nil {
                t.Fatalf("failed to parse templates: %v", err)
        }
        return tmpl
}

func init() {
        gin.SetMode(gin.TestMode)
}

func mockGinContext() *gin.Context {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
        return c
}

func mockGinContextWithForm(sel1, sel2 string) *gin.Context {
        form := url.Values{}
        form.Set("dkim_selector1", sel1)
        form.Set("dkim_selector2", sel2)

        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
        c.Request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
        return c
}

func mockGinContextWithCovert(covert string) *gin.Context {
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        queryURL := "/"
        if covert != "" {
                queryURL = "/?covert=" + covert
        }
        c.Request = httptest.NewRequest(http.MethodGet, queryURL, nil)
        return c
}
