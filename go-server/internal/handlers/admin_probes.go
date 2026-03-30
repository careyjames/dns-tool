// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.

// dns-tool:scrutiny design
package handlers

import (
        "bytes"
        "context"
        "crypto/tls"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "io"
        "log/slog"
        "net/http"
        "os"
        "strings"
        "time"

        "dnstool/go-server/internal/config"
        "dnstool/go-server/internal/db"

        "github.com/gin-gonic/gin"
        "golang.org/x/crypto/ssh"
)

const (
        mapKeyAction  = "action"
        mapKeyAudit   = "audit"
        mapKeyHealth  = "health"
        mapKeyRestart = "restart"
        mapKeyUpdate  = "update"
        strProbe01    = "probe-01"
        strProbe02    = "probe-02"
)

type ProbeAdminHandler struct {
        DB     *db.Database
        Config *config.Config
}

func NewProbeAdminHandler(database *db.Database, cfg *config.Config) *ProbeAdminHandler {
        return &ProbeAdminHandler{DB: database, Config: cfg}
}

type probeInfo struct {
        ID    string
        Label string
        URL   string
}

type probeActionResult struct {
        Probe   probeInfo
        Action  string
        Success bool
        Output  string
        Elapsed float64
}

func (h *ProbeAdminHandler) configuredProbes() []probeInfo {
        var probes []probeInfo
        if url := os.Getenv("PROBE_API_URL"); url != "" {
                label := os.Getenv("PROBE_LABEL")
                if label == "" {
                        label = "US-East (Boston)"
                }
                probes = append(probes, probeInfo{ID: strProbe01, Label: label, URL: url})
        }
        if url := os.Getenv("PROBE_API_URL_2"); url != "" {
                label := os.Getenv("PROBE_LABEL_2")
                if label == "" {
                        label = "US-East (Kali/02)"
                }
                probes = append(probes, probeInfo{ID: strProbe02, Label: label, URL: url})
        }
        return probes
}

func (h *ProbeAdminHandler) ProbeDashboard(c *gin.Context) {
        probes := h.configuredProbes()

        var healthResults []probeActionResult
        for _, p := range probes {
                result := checkProbeHealth(p)
                healthResults = append(healthResults, result)
        }

        nonce, _ := c.Get("csp_nonce")
        csrfToken, _ := c.Get("csrf_token")

        data := gin.H{
                keyAppVersion:      h.Config.AppVersion,
                keyMaintenanceNote: h.Config.MaintenanceNote,
                keyBetaPages:       h.Config.BetaPages,
                keyCspNonce:        nonce,
                "CsrfToken":       csrfToken,
                keyActivePage:      "admin",
                "Probes":          probes,
                "HealthResults":   healthResults,
        }
        mergeAuthData(c, h.Config, data)

        if actionResult, ok := c.Get("probeActionResult"); ok {
                data["ActionResult"] = actionResult
        }

        c.HTML(http.StatusOK, "admin_probes.html", data)
}

func (h *ProbeAdminHandler) RunProbeAction(c *gin.Context) {
        probeID := c.Param("id")
        action := c.Param(mapKeyAction)

        probes := h.configuredProbes()
        var target *probeInfo
        for i := range probes {
                if probes[i].ID == probeID {
                        target = &probes[i]
                        break
                }
        }
        if target == nil {
                c.String(http.StatusNotFound, "Probe not found")
                return
        }

        slog.Info("Admin: probe action requested", "probe", probeID, mapKeyAction, action)

        var result probeActionResult
        switch action {
        case mapKeyHealth:
                result = checkProbeHealth(*target)
        case mapKeyUpdate:
                result = runProbeSSH(*target, mapKeyUpdate)
        case mapKeyRestart:
                result = runProbeSSH(*target, mapKeyRestart)
        case mapKeyAudit:
                result = runProbeSSH(*target, mapKeyAudit)
        default:
                c.String(http.StatusBadRequest, "Unknown action")
                return
        }

        slog.Info("Admin: probe action completed", "probe", probeID, mapKeyAction, action, "success", result.Success)

        c.Set("probeActionResult", result)
        h.ProbeDashboard(c)
}

func checkProbeHealth(p probeInfo) probeActionResult {
        start := time.Now()
        client := &http.Client{
                Timeout: 10 * time.Second,
                Transport: &http.Transport{
                        TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
                },
        }

        resp, err := client.Get(p.URL + "/health")
        elapsed := time.Since(start).Seconds()

        if err != nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  mapKeyHealth,
                        Success: false,
                        Output:  fmt.Sprintf("Connection failed: %v", err),
                        Elapsed: elapsed,
                }
        }
        defer safeClose(resp.Body, "probe-health-response")

        body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

        var pretty bytes.Buffer
        if json.Indent(&pretty, body, "", "  ") == nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  mapKeyHealth,
                        Success: resp.StatusCode == 200,
                        Output:  pretty.String(),
                        Elapsed: elapsed,
                }
        }

        return probeActionResult{
                Probe:   p,
                Action:  mapKeyHealth,
                Success: resp.StatusCode == 200,
                Output:  string(body),
                Elapsed: elapsed,
        }
}

func runProbeSSH(p probeInfo, action string) probeActionResult {
        start := time.Now()

        sshConfig, err := resolveProbeSSH(p.ID)
        if err != nil {
                return probeActionResult{
                        Probe:   p,
                        Action:  action,
                        Success: false,
                        Output:  fmt.Sprintf("SSH config error: %v", err),
                        Elapsed: time.Since(start).Seconds(),
                }
        }

        var script string
        switch action {
        case mapKeyUpdate:
                script = probeUpdateScript()
        case mapKeyRestart:
                script = probeRestartScript()
        case mapKeyAudit:
                script = probeAuditScript()
        default:
                return probeActionResult{
                        Probe:   p,
                        Action:  action,
                        Success: false,
                        Output:  "Unknown action: " + action,
                        Elapsed: time.Since(start).Seconds(),
                }
        }

        ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
        defer cancel()

        output, err := executeSSH(ctx, sshConfig, script)
        elapsed := time.Since(start).Seconds()

        if err != nil {
                slog.Error("Probe SSH action failed",
                        "probe", p.ID,
                        mapKeyAction, action,
                        "error", err.Error(),
                        "output", output,
                        "elapsed_s", elapsed)
                if output == "" {
                        output = fmt.Sprintf("SSH error: %v", err)
                }
        }

        return probeActionResult{
                Probe:   p,
                Action:  action,
                Success: err == nil,
                Output:  output,
                Elapsed: elapsed,
        }
}

type sshTarget struct {
        host   string
        user   string
        signer ssh.Signer
}

func resolveProbeSSH(probeID string) (*sshTarget, error) {
        var host, user, keyB64 string
        switch probeID {
        case strProbe01:
                host = os.Getenv("PROBE_SSH_HOST")
                user = os.Getenv("PROBE_SSH_USER")
                keyB64 = os.Getenv("PROBE_SSH_PRIVATE_KEY")
                if host == "" || user == "" || keyB64 == "" {
                        return nil, fmt.Errorf("probe-01 SSH credentials not configured (PROBE_SSH_HOST, PROBE_SSH_USER, PROBE_SSH_PRIVATE_KEY)")
                }
        case strProbe02:
                host = os.Getenv("PROBE_SSH_HOST_2")
                user = os.Getenv("PROBE2_SSH_USER")
                keyB64 = os.Getenv("PROBE_SSH_PRIVATE_KEY_2")
                if host == "" || user == "" || keyB64 == "" {
                        return nil, fmt.Errorf("probe-02 SSH credentials not configured (PROBE_SSH_HOST_2, PROBE2_SSH_USER, PROBE_SSH_PRIVATE_KEY_2)")
                }
        default:
                return nil, fmt.Errorf("unknown probe: %s", probeID)
        }

        signer, err := parseSSHKey(keyB64, probeID)
        if err != nil {
                return nil, err
        }

        if !strings.Contains(host, ":") {
                host += ":22"
        }

        return &sshTarget{host: host, user: user, signer: signer}, nil
}

func parseSSHKey(b64Key, label string) (ssh.Signer, error) {
        raw := strings.TrimSpace(b64Key)

        var keyBytes []byte
        if strings.HasPrefix(raw, "-----BEGIN") {
                keyBytes = []byte(normalizePEM(raw))
        } else {
                decoded, err := base64.StdEncoding.DecodeString(raw)
                if err != nil {
                        decoded, err = base64.RawStdEncoding.DecodeString(raw)
                        if err != nil {
                                return nil, fmt.Errorf("failed to decode SSH key for %s: %w", label, err)
                        }
                }
                keyBytes = decoded
                if !bytes.HasPrefix(keyBytes, []byte("-----BEGIN")) {
                        pemWrapped := fmt.Sprintf("-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n", raw)
                        keyBytes = []byte(pemWrapped)
                }
        }

        signer, err := ssh.ParsePrivateKey(keyBytes)
        if err != nil {
                return nil, fmt.Errorf("failed to parse SSH key for %s: %w", label, err)
        }
        return signer, nil
}

func findPEMHeader(tokens []string) (header string, nextIdx int, ok bool) {
        i := 0
        for i < len(tokens) && !strings.HasSuffix(tokens[i], "-----") {
                i++
        }
        if i >= len(tokens) {
                return "", 0, false
        }
        return strings.Join(tokens[:i+1], " "), i + 1, true
}

func findPEMFooter(tokens []string, start int) (footer string, bodyTokens []string) {
        j := len(tokens) - 1
        for j > start && !strings.HasPrefix(tokens[j], "-----") {
                j--
        }
        endStart := j
        for endStart > start && !strings.HasPrefix(tokens[endStart], "-----") {
                endStart--
        }
        if endStart >= start {
                return strings.Join(tokens[endStart:], " "), tokens[start:endStart]
        }
        return "", tokens[start:]
}

func wrapPEMBody(header, body, footer string) string {
        var lines []string
        lines = append(lines, header)
        for k := 0; k < len(body); k += 70 {
                end := k + 70
                if end > len(body) {
                        end = len(body)
                }
                lines = append(lines, body[k:end])
        }
        if footer != "" {
                lines = append(lines, footer)
        }
        return strings.Join(lines, "\n") + "\n"
}

func normalizePEM(s string) string {
        s = strings.ReplaceAll(s, "\\n", "\n")

        if strings.Contains(s, "\n") && !(strings.Contains(s, " ") && strings.Count(s, "\n") < 3) {
                return s
        }

        tokens := strings.Fields(s)
        header, nextIdx, ok := findPEMHeader(tokens)
        if !ok {
                return s
        }
        footer, bodyTokens := findPEMFooter(tokens, nextIdx)
        return wrapPEMBody(header, strings.Join(bodyTokens, ""), footer)
}

func executeSSH(ctx context.Context, target *sshTarget, script string) (string, error) {
        clientConfig := &ssh.ClientConfig{
                User: target.user,
                Auth: []ssh.AuthMethod{
                        ssh.PublicKeys(target.signer),
                },
                HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // probes are known infrastructure
                Timeout:         10 * time.Second,
        }

        conn, err := ssh.Dial("tcp", target.host, clientConfig)
        if err != nil {
                return "", fmt.Errorf("SSH dial failed: %w", err)
        }
        defer conn.Close()

        session, err := conn.NewSession()
        if err != nil {
                return "", fmt.Errorf("SSH session failed: %w", err)
        }
        defer session.Close()

        var stdout, stderr bytes.Buffer
        session.Stdout = &stdout
        session.Stderr = &stderr
        session.Stdin = strings.NewReader(script)

        done := make(chan error, 1)
        go func() {
                done <- session.Run("bash -s")
        }()

        select {
        case err = <-done:
        case <-ctx.Done():
                session.Signal(ssh.SIGTERM)
                return stdout.String(), fmt.Errorf("SSH command timed out: %w", ctx.Err())
        }

        output := strings.TrimSpace(stdout.String())
        errOutput := strings.TrimSpace(stderr.String())

        if errOutput != "" && !strings.HasPrefix(errOutput, "Warning:") {
                if output != "" {
                        output += "\n" + errOutput
                } else {
                        output = errOutput
                }
        }

        return output, err
}

func probeUpdateScript() string {
        return `set -e
export DEBIAN_FRONTEND=noninteractive
echo ">>> Starting system update on $(hostname)..."
apt-get update -qq 2>&1 | tail -5
echo ">>> Upgrading packages..."
apt-get -y -qq full-upgrade 2>&1 | tail -10
echo ">>> Removing unused packages..."
apt-get -y -qq autoremove 2>&1 | tail -5
echo ">>> Cleaning cache..."
apt-get clean
echo ">>> Services check:"
systemctl is-active dns-probe && echo "  Probe: running" || echo "  Probe: NOT running"
systemctl is-active nginx && echo "  Nginx: running" || echo "  Nginx: NOT running"
systemctl is-active fail2ban 2>/dev/null && echo "  Fail2ban: running" || echo "  Fail2ban: not installed"
echo ">>> Disk:"
df -h / | tail -1
echo ">>> UPDATE COMPLETE on $(hostname)"
`
}

func probeRestartScript() string {
        return `set -e
echo ">>> Restarting dns-probe on $(hostname)..."
systemctl restart dns-probe
sleep 2
systemctl is-active dns-probe && echo "Probe: running" || echo "Probe: FAILED TO START"
curl -s http://localhost:8443/health 2>/dev/null || echo "Health endpoint not responding"
echo ">>> RESTART COMPLETE on $(hostname)"
`
}

func probeAuditScript() string {
        return `echo "=== Security Audit: $(hostname) ==="
echo ""
echo "--- SSH Configuration ---"
sshd -T 2>/dev/null | grep -E 'passwordauthentication|permitrootlogin|maxauthtries|x11forwarding|permitemptypasswords' | sort
echo ""
echo "--- Fail2ban ---"
if systemctl is-active fail2ban >/dev/null 2>&1; then
  fail2ban-client status sshd 2>/dev/null || echo "fail2ban running but sshd jail not configured"
else
  echo "fail2ban: not active"
fi
echo ""
echo "--- Firewall (UFW) ---"
ufw status 2>/dev/null || echo "UFW not installed"
echo ""
echo "--- Listening Ports ---"
ss -tlnp | grep -v '127.0.0' | grep -v '::1'
echo ""
echo "--- Services ---"
systemctl is-active dns-probe && echo "dns-probe: active" || echo "dns-probe: INACTIVE"
systemctl is-active nginx && echo "nginx: active" || echo "nginx: INACTIVE"
echo ""
echo "--- TLS Certificate ---"
certbot certificates 2>/dev/null | grep -E 'Certificate Name|Expiry|Domains' || echo "certbot not available"
echo ""
echo "--- System ---"
uname -r
uptime
df -h / | tail -1
echo ""
echo "--- Recent Auth Failures ---"
journalctl -u ssh --since "24 hours ago" --no-pager 2>/dev/null | grep -c "Failed\|Invalid" | xargs -I{} echo "SSH auth failures (24h): {}"
echo ""
echo "=== AUDIT COMPLETE ==="
`
}
