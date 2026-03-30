package handlers

import (
	"dnstool/go-server/internal/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestMergeAuthData_NoGoogleClient(t *testing.T) {
	cfg := &config.Config{GoogleClientID: ""}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	data := gin.H{}
	result := mergeAuthData(c, cfg, data)
	if _, ok := result["GoogleAuthEnabled"]; ok {
		t.Error("GoogleAuthEnabled should not be set when GoogleClientID is empty")
	}
}

func TestMergeAuthData_WithGoogleClient(t *testing.T) {
	cfg := &config.Config{GoogleClientID: "test-client-id"}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	data := gin.H{}
	result := mergeAuthData(c, cfg, data)
	if val, ok := result["GoogleAuthEnabled"]; !ok || val != true {
		t.Error("expected GoogleAuthEnabled = true")
	}
}

func TestMergeAuthData_PreservesExistingData(t *testing.T) {
	cfg := &config.Config{}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)

	data := gin.H{"existing_key": "existing_value"}
	result := mergeAuthData(c, cfg, data)
	if result["existing_key"] != "existing_value" {
		t.Error("existing data should be preserved")
	}
}
