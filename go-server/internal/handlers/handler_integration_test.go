package handlers_test

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"

	"dnstool/go-server/internal/handlers"

	"github.com/gin-gonic/gin"
)

func testRouter() *gin.Engine {
	router := gin.New()
	tmpl := template.Must(template.New("stats.html").Parse(`OK`))
	template.Must(tmpl.New("history.html").Parse(`OK`))
	template.Must(tmpl.New("failures.html").Parse(`OK`))
	router.SetHTMLTemplate(tmpl)
	return router
}

func TestStatsHandlerIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewStatsHandler(database, cfg)
	router.GET("/stats", handler.Stats)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stats", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHistoryHandlerIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewHistoryHandler(database, cfg)
	router.GET("/history", handler.History)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/history", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHistoryHandlerWithSearchIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewHistoryHandler(database, cfg)
	router.GET("/history", handler.History)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/history?domain=example.com", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestHistoryHandlerPaginationIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewHistoryHandler(database, cfg)
	router.GET("/history", handler.History)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/history?page=2", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestFailuresHandlerIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewFailuresHandler(database, cfg)
	router.GET("/failures", handler.Failures)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/failures", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d; body: %s", w.Code, w.Body.String())
	}
}

func TestStatsRedirectIntegration(t *testing.T) {
	database := setupTestDB(t)
	defer cleanupTestDB(t, database)

	cfg := testConfig()
	router := testRouter()
	handler := handlers.NewStatsHandler(database, cfg)
	router.GET("/statistics", handler.StatisticsRedirect)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/statistics", nil)
	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected status 302, got %d", w.Code)
	}
	location := w.Header().Get("Location")
	if location != "/stats" {
		t.Fatalf("expected redirect to /stats, got %s", location)
	}
}
