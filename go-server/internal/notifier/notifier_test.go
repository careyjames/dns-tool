package notifier

import (
        "context"
        "encoding/json"
        "fmt"
        "io"
        "net/http"
        "net/http/httptest"
        "testing"
        "time"

        "dnstool/go-server/internal/dbq"
)

func TestSeverityColor(t *testing.T) {
        tests := []struct {
                severity string
                want     int
        }{
                {"critical", 0xDC3545},
                {"Critical", 0xDC3545},
                {"CRITICAL", 0xDC3545},
                {"high", 0xFD7E14},
                {"High", 0xFD7E14},
                {"medium", 0xFFC107},
                {"Medium", 0xFFC107},
                {"low", 0x17A2B8},
                {"Low", 0x17A2B8},
                {"unknown", 0x6C757D},
                {"", 0x6C757D},
                {"info", 0x6C757D},
        }
        for _, tt := range tests {
                t.Run(tt.severity, func(t *testing.T) {
                        got := severityColor(tt.severity)
                        if got != tt.want {
                                t.Errorf("severityColor(%q) = 0x%X, want 0x%X", tt.severity, got, tt.want)
                        }
                })
        }
}

func TestNew(t *testing.T) {
        n := New(nil)
        if n == nil {
                t.Fatal("New returned nil")
        }
        if n.Client == nil {
                t.Fatal("Client is nil")
        }
        if n.Client.Timeout != httpTimeout {
                t.Errorf("Client.Timeout = %v, want %v", n.Client.Timeout, httpTimeout)
        }
        _ = n.Queries
}

func TestSendDiscord_Success(t *testing.T) {
        var receivedBody []byte
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                if r.Header.Get("Content-Type") != "application/json" {
                        t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
                }
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusNoContent)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}

        diffJSON, _ := json.Marshal([]struct {
                Field string `json:"field"`
                Old   string `json:"old"`
                New   string `json:"new"`
        }{
                {Field: "SPF", Old: "pass", New: "fail"},
        })

        notif := dbq.ListPendingNotificationsRow{
                ID:           1,
                DriftEventID: 10,
                EndpointID:   5,
                Status:       "pending",
                Url:          srv.URL,
                EndpointType: "discord",
                Domain:       "example.com",
                DiffSummary:  diffJSON,
                Severity:     "high",
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err != nil {
                t.Fatalf("sendDiscord returned error: %v", err)
        }
        if code != http.StatusNoContent {
                t.Errorf("status code = %d, want %d", code, http.StatusNoContent)
        }

        var payload discordPayload
        if err := json.Unmarshal(receivedBody, &payload); err != nil {
                t.Fatalf("failed to unmarshal payload: %v", err)
        }
        if payload.Username != "DNS Tool Drift Engine" {
                t.Errorf("Username = %q", payload.Username)
        }
        if len(payload.Embeds) != 1 {
                t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
        }
        if payload.Embeds[0].Color != 0xFD7E14 {
                t.Errorf("embed color = 0x%X, want 0x%X", payload.Embeds[0].Color, 0xFD7E14)
        }
        if len(payload.Embeds[0].Fields) != 1 {
                t.Fatalf("expected 1 field, got %d", len(payload.Embeds[0].Fields))
        }
        if payload.Embeds[0].Fields[0].Name != "SPF" {
                t.Errorf("field name = %q", payload.Embeds[0].Fields[0].Name)
        }
}

func TestSendDiscord_ErrorStatus(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusForbidden)
                w.Write([]byte("forbidden"))
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Domain:   "example.com",
                Severity: "low",
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for non-2xx status")
        }
        if code != http.StatusForbidden {
                t.Errorf("status code = %d, want %d", code, http.StatusForbidden)
        }
}

func TestSendDiscord_NoDiffSummary(t *testing.T) {
        var receivedBody []byte
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Domain:   "test.com",
                Severity: "medium",
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if code != http.StatusOK {
                t.Errorf("code = %d", code)
        }

        var payload discordPayload
        json.Unmarshal(receivedBody, &payload)
        if len(payload.Embeds[0].Fields) != 0 {
                t.Errorf("expected 0 fields with empty diff, got %d", len(payload.Embeds[0].Fields))
        }
}

func TestSendGenericWebhook_Success(t *testing.T) {
        secret := "my-secret"
        var receivedBody []byte
        var receivedSecret string
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                receivedSecret = r.Header.Get("X-Webhook-Secret")
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}

        diffJSON := []byte(`[{"field":"DMARC","old":"none","new":"reject"}]`)
        notif := dbq.ListPendingNotificationsRow{
                Url:         srv.URL,
                Secret:      &secret,
                Domain:      "example.org",
                DiffSummary: diffJSON,
                Severity:    "critical",
        }

        code, err := n.sendGenericWebhook(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if code != http.StatusOK {
                t.Errorf("code = %d", code)
        }
        if receivedSecret != secret {
                t.Errorf("secret header = %q, want %q", receivedSecret, secret)
        }

        var payload map[string]any
        json.Unmarshal(receivedBody, &payload)
        if payload["event"] != "drift_detected" {
                t.Errorf("event = %v", payload["event"])
        }
        if payload["domain"] != "example.org" {
                t.Errorf("domain = %v", payload["domain"])
        }
        if payload["diff_summary"] == nil {
                t.Error("diff_summary missing")
        }
}

func TestSendGenericWebhook_NoSecret(t *testing.T) {
        var receivedSecret string
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                receivedSecret = r.Header.Get("X-Webhook-Secret")
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Domain:   "test.com",
                Severity: "low",
        }

        _, err := n.sendGenericWebhook(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if receivedSecret != "" {
                t.Errorf("expected no secret header, got %q", receivedSecret)
        }
}

func TestSendGenericWebhook_ErrorStatus(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte("server error"))
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Domain:   "fail.com",
                Severity: "high",
        }

        code, err := n.sendGenericWebhook(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for 500")
        }
        if code != http.StatusInternalServerError {
                t.Errorf("code = %d", code)
        }
}

func TestSendTestDiscord_Success(t *testing.T) {
        var receivedBody []byte
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusNoContent)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        err := n.SendTestDiscord(context.Background(), srv.URL)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }

        var payload discordPayload
        json.Unmarshal(receivedBody, &payload)
        if payload.Username != "DNS Tool Drift Engine" {
                t.Errorf("Username = %q", payload.Username)
        }
        if len(payload.Embeds) != 1 {
                t.Fatalf("expected 1 embed, got %d", len(payload.Embeds))
        }
        if payload.Embeds[0].Title != "Drift Engine Connected" {
                t.Errorf("Title = %q", payload.Embeds[0].Title)
        }
        if payload.Embeds[0].Color != 0x28A745 {
                t.Errorf("Color = 0x%X", payload.Embeds[0].Color)
        }
        if len(payload.Embeds[0].Fields) != 3 {
                t.Errorf("expected 3 fields, got %d", len(payload.Embeds[0].Fields))
        }
}

func TestSendTestDiscord_Error(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusBadRequest)
                w.Write([]byte("bad request"))
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        err := n.SendTestDiscord(context.Background(), srv.URL)
        if err == nil {
                t.Fatal("expected error for 400")
        }
}

type mockDBTX struct{}

func (m *mockDBTX) Exec(ctx context.Context, sql string, args ...interface{}) (interface{ RowsAffected() int64 }, error) {
        return nil, nil
}

func TestDeliverPending_DiscordEndpoint(t *testing.T) {
        callCount := 0
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                callCount++
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{
                Client:     srv.Client(),
                Queries:    nil,
                AllowLocal: true,
        }

        notif := dbq.ListPendingNotificationsRow{
                ID:           1,
                EndpointType: "discord",
                Url:          srv.URL,
                Domain:       "example.com",
                Severity:     "high",
        }
        code, err := n.sendDiscord(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if code != http.StatusOK {
                t.Errorf("code = %d", code)
        }
        if callCount != 1 {
                t.Errorf("expected 1 call, got %d", callCount)
        }
}

func TestSendGenericWebhook_EmptySecret(t *testing.T) {
        var receivedSecret string
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                receivedSecret = r.Header.Get("X-Webhook-Secret")
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        emptySecret := ""
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Secret:   &emptySecret,
                Domain:   "test.com",
                Severity: "low",
        }

        _, err := n.sendGenericWebhook(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if receivedSecret != "" {
                t.Errorf("expected no secret header for empty secret, got %q", receivedSecret)
        }
}

func TestSendGenericWebhook_NoDiffSummary(t *testing.T) {
        var receivedBody []byte
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:      srv.URL,
                Domain:   "nodiff.com",
                Severity: "medium",
        }

        _, err := n.sendGenericWebhook(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }

        var payload map[string]any
        json.Unmarshal(receivedBody, &payload)
        if _, ok := payload["diff_summary"]; ok {
                t.Error("diff_summary should not be present when empty")
        }
}

func TestMissionCriticalDomains(t *testing.T) {
        if len(missionCriticalDomains) == 0 {
                t.Fatal("missionCriticalDomains should not be empty")
        }
        found := false
        for _, d := range missionCriticalDomains {
                if d == "it-help.tech" {
                        found = true
                }
        }
        if !found {
                t.Error("expected it-help.tech in missionCriticalDomains")
        }
}

func TestSendDiscord_MalformedDiffSummary(t *testing.T) {
        var receivedBody []byte
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                var err error
                receivedBody, err = io.ReadAll(r.Body)
                if err != nil {
                        t.Fatal(err)
                }
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        n := &Notifier{Client: srv.Client(), AllowLocal: true}
        notif := dbq.ListPendingNotificationsRow{
                Url:         srv.URL,
                Domain:      "test.com",
                Severity:    "high",
                DiffSummary: []byte(`not valid json`),
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if code != http.StatusOK {
                t.Errorf("code = %d", code)
        }

        var payload discordPayload
        json.Unmarshal(receivedBody, &payload)
        if len(payload.Embeds[0].Fields) != 0 {
                t.Errorf("expected 0 fields with malformed diff, got %d", len(payload.Embeds[0].Fields))
        }
}

func TestSendDiscord_ConnectionError(t *testing.T) {
        n := &Notifier{Client: &http.Client{Timeout: 1 * time.Millisecond}}
        notif := dbq.ListPendingNotificationsRow{
                Url:      "http://192.0.2.1:1",
                Domain:   "fail.com",
                Severity: "critical",
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for connection failure")
        }
        if code != 0 {
                t.Errorf("expected code 0 for connection error, got %d", code)
        }
}

func TestSendGenericWebhook_ConnectionError(t *testing.T) {
        n := &Notifier{Client: &http.Client{Timeout: 1 * time.Millisecond}}
        notif := dbq.ListPendingNotificationsRow{
                Url:      "http://192.0.2.1:1",
                Domain:   "fail.com",
                Severity: "high",
        }

        code, err := n.sendGenericWebhook(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for connection failure")
        }
        if code != 0 {
                t.Errorf("expected code 0 for connection error, got %d", code)
        }
}

func TestSendTestDiscord_ConnectionError(t *testing.T) {
        n := &Notifier{Client: &http.Client{Timeout: 1 * time.Millisecond}}
        err := n.SendTestDiscord(context.Background(), "http://192.0.2.1:1")
        if err == nil {
                t.Fatal("expected error for connection failure")
        }
}

func TestSendDiscord_InvalidURL(t *testing.T) {
        n := &Notifier{Client: &http.Client{}}
        notif := dbq.ListPendingNotificationsRow{
                Url:      "://bad-url",
                Domain:   "test.com",
                Severity: "low",
        }

        code, err := n.sendDiscord(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for invalid URL")
        }
        if code != 0 {
                t.Errorf("expected code 0 for bad URL, got %d", code)
        }
}

func TestSendGenericWebhook_InvalidURL(t *testing.T) {
        n := &Notifier{Client: &http.Client{}}
        notif := dbq.ListPendingNotificationsRow{
                Url:      "://bad-url",
                Domain:   "test.com",
                Severity: "low",
        }

        code, err := n.sendGenericWebhook(context.Background(), notif)
        if err == nil {
                t.Fatal("expected error for invalid URL")
        }
        if code != 0 {
                t.Errorf("expected code 0 for bad URL, got %d", code)
        }
}

func TestSendTestDiscord_InvalidURL(t *testing.T) {
        n := &Notifier{Client: &http.Client{}}
        err := n.SendTestDiscord(context.Background(), "://bad-url")
        if err == nil {
                t.Fatal("expected error for invalid URL")
        }
}

type mockDB struct {
        pending   []dbq.ListPendingNotificationsRow
        listErr   error
        updateErr error
        updated   []dbq.UpdateDriftNotificationStatusParams
}

func (m *mockDB) ListPendingNotifications(_ context.Context, _ int32) ([]dbq.ListPendingNotificationsRow, error) {
        return m.pending, m.listErr
}

func (m *mockDB) UpdateDriftNotificationStatus(_ context.Context, arg dbq.UpdateDriftNotificationStatusParams) error {
        m.updated = append(m.updated, arg)
        return m.updateErr
}

func TestDeliverPending_ListError(t *testing.T) {
        db := &mockDB{listErr: fmt.Errorf("db down")}
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err == nil {
                t.Fatal("expected error")
        }
        if count != 0 {
                t.Errorf("expected 0, got %d", count)
        }
}

func TestDeliverPending_EmptyList(t *testing.T) {
        db := &mockDB{pending: nil}
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 0 {
                t.Errorf("expected 0, got %d", count)
        }
}

func TestDeliverPending_DiscordSuccess(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusNoContent)
        }))
        defer srv.Close()

        diff := `[{"field":"A","old":"1.2.3.4","new":"5.6.7.8"}]`
        db := &mockDB{
                pending: []dbq.ListPendingNotificationsRow{
                        {
                                ID:           1,
                                EndpointType: "discord",
                                Url:          srv.URL,
                                Domain:       "example.com",
                                DiffSummary:  []byte(diff),
                                Severity:     "high",
                        },
                },
        }
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 1 {
                t.Errorf("expected 1 delivered, got %d", count)
        }
        if len(db.updated) != 1 {
                t.Fatalf("expected 1 update call, got %d", len(db.updated))
        }
        if db.updated[0].Status != "delivered" {
                t.Errorf("expected status delivered, got %s", db.updated[0].Status)
        }
}

func TestDeliverPending_GenericWebhookSuccess(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        diff := `[{"field":"MX","old":"mx1.example.com","new":"mx2.example.com"}]`
        db := &mockDB{
                pending: []dbq.ListPendingNotificationsRow{
                        {
                                ID:           2,
                                EndpointType: "webhook",
                                Url:          srv.URL,
                                Domain:       "test.com",
                                DiffSummary:  []byte(diff),
                                Severity:     "medium",
                        },
                },
        }
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 1 {
                t.Errorf("expected 1 delivered, got %d", count)
        }
}

func TestDeliverPending_SendFailure(t *testing.T) {
        db := &mockDB{
                pending: []dbq.ListPendingNotificationsRow{
                        {
                                ID:           3,
                                EndpointType: "discord",
                                Url:          "http://192.0.2.1:1/nope",
                                Domain:       "fail.com",
                                DiffSummary:  []byte(`[]`),
                                Severity:     "critical",
                        },
                },
        }
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 1 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 0 {
                t.Errorf("expected 0 delivered (send failed), got %d", count)
        }
        if len(db.updated) != 1 {
                t.Fatalf("expected 1 update, got %d", len(db.updated))
        }
        if db.updated[0].Status != "failed" {
                t.Errorf("expected status failed, got %s", db.updated[0].Status)
        }
}

func TestDeliverPending_UpdateError(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusNoContent)
        }))
        defer srv.Close()

        db := &mockDB{
                pending: []dbq.ListPendingNotificationsRow{
                        {
                                ID:           4,
                                EndpointType: "discord",
                                Url:          srv.URL,
                                Domain:       "update-fail.com",
                                DiffSummary:  []byte(`[]`),
                                Severity:     "low",
                        },
                },
                updateErr: fmt.Errorf("update failed"),
        }
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 1 {
                t.Errorf("expected 1 delivered, got %d", count)
        }
}

func TestDeliverPending_MultipleNotifications(t *testing.T) {
        srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
        }))
        defer srv.Close()

        db := &mockDB{
                pending: []dbq.ListPendingNotificationsRow{
                        {
                                ID:           10,
                                EndpointType: "discord",
                                Url:          srv.URL,
                                Domain:       "a.com",
                                DiffSummary:  []byte(`[]`),
                                Severity:     "low",
                        },
                        {
                                ID:           11,
                                EndpointType: "webhook",
                                Url:          srv.URL,
                                Domain:       "b.com",
                                DiffSummary:  []byte(`[{"field":"NS","old":"ns1","new":"ns2"}]`),
                                Severity:     "high",
                        },
                },
        }
        n := &Notifier{Queries: db, Client: &http.Client{Timeout: 2 * time.Second}, AllowLocal: true}
        count, err := n.DeliverPending(context.Background(), 10)
        if err != nil {
                t.Fatalf("unexpected error: %v", err)
        }
        if count != 2 {
                t.Errorf("expected 2 delivered, got %d", count)
        }
        if len(db.updated) != 2 {
                t.Fatalf("expected 2 updates, got %d", len(db.updated))
        }
}
