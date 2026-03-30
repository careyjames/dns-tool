package handlers

import (
        "context"
        "errors"
        "net/http"
        "net/http/httptest"
        "strings"
        "sync/atomic"
        "testing"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/dbq"

        "github.com/gin-gonic/gin"
        "github.com/jackc/pgx/v5/pgtype"
)

type mockAuthStore struct {
        upsertUserFn                    func(ctx context.Context, arg dbq.UpsertUserParams) (dbq.User, error)
        promoteUserToAdminFn            func(ctx context.Context, id int32) error
        countAdminUsersFn               func(ctx context.Context) (int64, error)
        createSessionFn                 func(ctx context.Context, arg dbq.CreateSessionParams) error
        deleteSessionFn                 func(ctx context.Context, id string) error
        listWatchlistByUserFn           func(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error)
        insertWatchlistEntryFn          func(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error)
        listNotificationEndpointsByUserFn func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error)
        insertNotificationEndpointFn    func(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error)
}

func (m *mockAuthStore) UpsertUser(ctx context.Context, arg dbq.UpsertUserParams) (dbq.User, error) {
        if m.upsertUserFn != nil {
                return m.upsertUserFn(ctx, arg)
        }
        return dbq.User{}, nil
}

func (m *mockAuthStore) PromoteUserToAdmin(ctx context.Context, id int32) error {
        if m.promoteUserToAdminFn != nil {
                return m.promoteUserToAdminFn(ctx, id)
        }
        return nil
}

func (m *mockAuthStore) CountAdminUsers(ctx context.Context) (int64, error) {
        if m.countAdminUsersFn != nil {
                return m.countAdminUsersFn(ctx)
        }
        return 0, nil
}

func (m *mockAuthStore) CreateSession(ctx context.Context, arg dbq.CreateSessionParams) error {
        if m.createSessionFn != nil {
                return m.createSessionFn(ctx, arg)
        }
        return nil
}

func (m *mockAuthStore) DeleteSession(ctx context.Context, id string) error {
        if m.deleteSessionFn != nil {
                return m.deleteSessionFn(ctx, id)
        }
        return nil
}

func (m *mockAuthStore) ListWatchlistByUser(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error) {
        if m.listWatchlistByUserFn != nil {
                return m.listWatchlistByUserFn(ctx, userID)
        }
        return nil, nil
}

func (m *mockAuthStore) InsertWatchlistEntry(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error) {
        if m.insertWatchlistEntryFn != nil {
                return m.insertWatchlistEntryFn(ctx, arg)
        }
        return dbq.InsertWatchlistEntryRow{}, nil
}

func (m *mockAuthStore) ListNotificationEndpointsByUser(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
        if m.listNotificationEndpointsByUserFn != nil {
                return m.listNotificationEndpointsByUserFn(ctx, userID)
        }
        return nil, nil
}

func (m *mockAuthStore) InsertNotificationEndpoint(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error) {
        if m.insertNotificationEndpointFn != nil {
                return m.insertNotificationEndpointFn(ctx, arg)
        }
        return dbq.InsertNotificationEndpointRow{}, nil
}

func TestDetermineRole_AdminBootstrap(t *testing.T) {
        mock := &mockAuthStore{
                countAdminUsersFn: func(ctx context.Context) (int64, error) {
                        return 0, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{InitialAdminEmail: "admin@example.com"},
                authStore: mock,
        }

        role, shouldBootstrap := h.determineRole(context.Background(), "admin@example.com")
        if role != "admin" {
                t.Errorf("role = %q, want %q", role, "admin")
        }
        if !shouldBootstrap {
                t.Error("shouldBootstrap = false, want true")
        }
}

func TestDetermineRole_NoMatch(t *testing.T) {
        h := &AuthHandler{
                Config:    &config.Config{InitialAdminEmail: "admin@example.com"},
                authStore: &mockAuthStore{},
        }

        role, shouldBootstrap := h.determineRole(context.Background(), "user@example.com")
        if role != "user" {
                t.Errorf("role = %q, want %q", role, "user")
        }
        if shouldBootstrap {
                t.Error("shouldBootstrap = true, want false")
        }
}

func TestDetermineRole_CaseInsensitive(t *testing.T) {
        mock := &mockAuthStore{
                countAdminUsersFn: func(ctx context.Context) (int64, error) {
                        return 0, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{InitialAdminEmail: "Admin@Example.COM"},
                authStore: mock,
        }

        role, shouldBootstrap := h.determineRole(context.Background(), "admin@example.com")
        if role != "admin" {
                t.Errorf("role = %q, want %q", role, "admin")
        }
        if !shouldBootstrap {
                t.Error("shouldBootstrap = false, want true")
        }
}

func TestDetermineRole_AdminsExist(t *testing.T) {
        mock := &mockAuthStore{
                countAdminUsersFn: func(ctx context.Context) (int64, error) {
                        return 2, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{InitialAdminEmail: "admin@example.com"},
                authStore: mock,
        }

        role, shouldBootstrap := h.determineRole(context.Background(), "admin@example.com")
        if role != "user" {
                t.Errorf("role = %q, want %q", role, "user")
        }
        if shouldBootstrap {
                t.Error("shouldBootstrap = true, want false")
        }
}

func TestBootstrapAdminIfNeeded_Success(t *testing.T) {
        promoted := false
        mock := &mockAuthStore{
                promoteUserToAdminFn: func(ctx context.Context, id int32) error {
                        promoted = true
                        return nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        result := h.bootstrapAdminIfNeeded(context.Background(), 1, "user", true, "admin@example.com")
        if result != "admin" {
                t.Errorf("result = %q, want %q", result, "admin")
        }
        if !promoted {
                t.Error("PromoteUserToAdmin was not called")
        }
}

func TestBootstrapAdminIfNeeded_AlreadyAdmin(t *testing.T) {
        promoted := false
        mock := &mockAuthStore{
                promoteUserToAdminFn: func(ctx context.Context, id int32) error {
                        promoted = true
                        return nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        result := h.bootstrapAdminIfNeeded(context.Background(), 1, "admin", true, "admin@example.com")
        if result != "admin" {
                t.Errorf("result = %q, want %q", result, "admin")
        }
        if promoted {
                t.Error("PromoteUserToAdmin should not be called when currentRole is admin")
        }
}

func TestBootstrapAdminIfNeeded_NoBootstrap(t *testing.T) {
        promoted := false
        mock := &mockAuthStore{
                promoteUserToAdminFn: func(ctx context.Context, id int32) error {
                        promoted = true
                        return nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        result := h.bootstrapAdminIfNeeded(context.Background(), 1, "user", false, "user@example.com")
        if result != "user" {
                t.Errorf("result = %q, want %q", result, "user")
        }
        if promoted {
                t.Error("PromoteUserToAdmin should not be called when shouldBootstrap is false")
        }
}

func TestSeedAdminWatchlist_EmptyExisting(t *testing.T) {
        insertedDomains := make([]string, 0)
        mock := &mockAuthStore{
                listWatchlistByUserFn: func(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error) {
                        return []dbq.DomainWatchlist{}, nil
                },
                insertWatchlistEntryFn: func(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error) {
                        insertedDomains = append(insertedDomains, arg.Domain)
                        return dbq.InsertWatchlistEntryRow{ID: 1}, nil
                },
                listNotificationEndpointsByUserFn: func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
                        return nil, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{BaseURL: "https://app.example.com"},
                authStore: mock,
        }

        h.seedAdminWatchlist(context.Background(), 1)

        expectedDomains := missionCriticalDomainsFromBaseURL("https://app.example.com")
        if len(insertedDomains) != len(expectedDomains) {
                t.Errorf("inserted %d domains, want %d", len(insertedDomains), len(expectedDomains))
        }
        for i, d := range expectedDomains {
                if i < len(insertedDomains) && insertedDomains[i] != d {
                        t.Errorf("inserted[%d] = %q, want %q", i, insertedDomains[i], d)
                }
        }
}

func TestSeedDiscordEndpoint_NoExisting(t *testing.T) {
        inserted := false
        mock := &mockAuthStore{
                listNotificationEndpointsByUserFn: func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
                        return []dbq.NotificationEndpoint{}, nil
                },
                insertNotificationEndpointFn: func(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error) {
                        inserted = true
                        if arg.EndpointType != "discord" {
                                t.Errorf("endpoint type = %q, want %q", arg.EndpointType, "discord")
                        }
                        return dbq.InsertNotificationEndpointRow{ID: 1}, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{DiscordWebhookURL: "https://discord.com/api/webhooks/test"},
                authStore: mock,
        }

        h.seedDiscordEndpoint(context.Background(), 1)

        if !inserted {
                t.Error("InsertNotificationEndpoint was not called")
        }
}

func TestSeedDiscordEndpoint_AlreadyExists(t *testing.T) {
        webhookURL := "https://discord.com/api/webhooks/test"
        inserted := false
        mock := &mockAuthStore{
                listNotificationEndpointsByUserFn: func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
                        return []dbq.NotificationEndpoint{
                                {ID: 1, UserID: 1, EndpointType: "discord", Url: webhookURL},
                        }, nil
                },
                insertNotificationEndpointFn: func(ctx context.Context, arg dbq.InsertNotificationEndpointParams) (dbq.InsertNotificationEndpointRow, error) {
                        inserted = true
                        return dbq.InsertNotificationEndpointRow{}, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{DiscordWebhookURL: webhookURL},
                authStore: mock,
        }

        h.seedDiscordEndpoint(context.Background(), 1)

        if inserted {
                t.Error("InsertNotificationEndpoint should not be called when endpoint already exists")
        }
}

func TestCreateUserSession_Success(t *testing.T) {
        sessionCreated := false
        mock := &mockAuthStore{
                createSessionFn: func(ctx context.Context, arg dbq.CreateSessionParams) error {
                        sessionCreated = true
                        if arg.UserID != 42 {
                                t.Errorf("expected UserID=42, got %d", arg.UserID)
                        }
                        if arg.ID == "" {
                                t.Error("session ID should not be empty")
                        }
                        if !arg.ExpiresAt.Valid {
                                t.Error("ExpiresAt should be valid")
                        }
                        return nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        sessionID, err := h.createUserSession(context.Background(), 42)
        if err != nil {
                t.Fatalf("createUserSession returned error: %v", err)
        }
        if sessionID == "" {
                t.Error("sessionID should not be empty")
        }
        if !sessionCreated {
                t.Error("CreateSession was not called")
        }
}

func TestCreateUserSession_DBError(t *testing.T) {
        mock := &mockAuthStore{
                createSessionFn: func(ctx context.Context, arg dbq.CreateSessionParams) error {
                        return errors.New("db connection refused")
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        sessionID, err := h.createUserSession(context.Background(), 42)
        if err == nil {
                t.Fatal("expected error from createUserSession")
        }
        if sessionID != "" {
                t.Errorf("expected empty session ID on error, got %q", sessionID)
        }
}

func TestFinalizeLogin_AdminSeedsWatchlist(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/auth/callback", nil)

        seedCalled := int32(0)
        mock := &mockAuthStore{
                listWatchlistByUserFn: func(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error) {
                        atomic.AddInt32(&seedCalled, 1)
                        return nil, nil
                },
                insertWatchlistEntryFn: func(ctx context.Context, arg dbq.InsertWatchlistEntryParams) (dbq.InsertWatchlistEntryRow, error) {
                        return dbq.InsertWatchlistEntryRow{}, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{BaseURL: "https://dnstool.it-help.tech"},
                authStore: mock,
        }

        user := dbq.User{
                ID:   1,
                Role: "admin",
                CreatedAt: pgtype.Timestamp{
                        Time:  time.Now().Add(-24 * time.Hour),
                        Valid: true,
                },
                LastLoginAt: pgtype.Timestamp{
                        Time:  time.Now(),
                        Valid: true,
                },
        }
        h.finalizeLogin(c, "test-session-id", user, "Admin", "admin@example.com")

        time.Sleep(100 * time.Millisecond)

        if atomic.LoadInt32(&seedCalled) == 0 {
                t.Error("seedAdminWatchlist was not called for admin user")
        }

        if w.Code != http.StatusFound {
                t.Errorf("expected redirect 302, got %d", w.Code)
        }
}

func TestFinalizeLogin_NonAdmin(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/auth/callback", nil)

        seedCalled := false
        mock := &mockAuthStore{
                listWatchlistByUserFn: func(ctx context.Context, userID int32) ([]dbq.DomainWatchlist, error) {
                        seedCalled = true
                        return nil, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: mock,
        }

        user := dbq.User{
                ID:   2,
                Role: "user",
                CreatedAt: pgtype.Timestamp{
                        Time:  time.Now().Add(-24 * time.Hour),
                        Valid: true,
                },
                LastLoginAt: pgtype.Timestamp{
                        Time:  time.Now(),
                        Valid: true,
                },
        }
        h.finalizeLogin(c, "test-session-id", user, "User", "user@example.com")

        time.Sleep(50 * time.Millisecond)

        if seedCalled {
                t.Error("seedAdminWatchlist should not be called for non-admin user")
        }

        if w.Code != http.StatusFound {
                t.Errorf("expected redirect 302, got %d", w.Code)
        }
}

func TestFinalizeLogin_FirstLogin(t *testing.T) {
        gin.SetMode(gin.TestMode)
        w := httptest.NewRecorder()
        c, _ := gin.CreateTestContext(w)
        c.Request = httptest.NewRequest("GET", "/auth/callback", nil)

        h := &AuthHandler{
                Config:    &config.Config{},
                authStore: &mockAuthStore{},
        }

        now := time.Now()
        user := dbq.User{
                ID:   3,
                Role: "user",
                CreatedAt: pgtype.Timestamp{
                        Time:  now,
                        Valid: true,
                },
                LastLoginAt: pgtype.Timestamp{
                        Time:  now.Add(2 * time.Second),
                        Valid: true,
                },
        }
        h.finalizeLogin(c, "test-session-id", user, "New User", "new@example.com")

        location := w.Header().Get("Location")
        if !strings.Contains(location, "welcome=") {
                t.Errorf("first login should redirect with welcome param, got Location=%q", location)
        }
}

func TestSeedDiscordEndpoint_EmptyWebhookURL(t *testing.T) {
        listCalled := false
        mock := &mockAuthStore{
                listNotificationEndpointsByUserFn: func(ctx context.Context, userID int32) ([]dbq.NotificationEndpoint, error) {
                        listCalled = true
                        return nil, nil
                },
        }
        h := &AuthHandler{
                Config:    &config.Config{DiscordWebhookURL: ""},
                authStore: mock,
        }

        h.seedDiscordEndpoint(context.Background(), 1)

        if listCalled {
                t.Error("ListNotificationEndpointsByUser should not be called when DiscordWebhookURL is empty")
        }
}
