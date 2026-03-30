// dns-tool:scrutiny plumbing
package main

import (
        "bytes"
        "context"
        "crypto/subtle"
        "crypto/tls"
        "encoding/json"
        "encoding/xml"
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "os"
        "os/exec"
        "os/signal"
        "regexp"
        "strings"
        "sync"
        "syscall"
        "time"
)

const (
        probeVersion    = "2.1.0"
        maxRequestBody  = 64 * 1024
        maxHosts        = 10
        smtpDialTimeout = 3 * time.Second
        smtpReadTimeout = 2 * time.Second
        tlsTimeout      = 4 * time.Second
        requestTimeout  = 45 * time.Second

        errInvalidHostRequired = "invalid request: host required"
        ehloHostname           = "probe.dns-observe.com"

        mapKeyCertIssuer      = "cert_issuer"
        mapKeyCertValid       = "cert_valid"
        mapKeyCipher          = "cipher"
        mapKeyElapsedSeconds  = "elapsed_seconds"
        mapKeyError           = "error"
        mapKeyPorts           = "ports"
        mapKeyProbeHost       = "probe_host"
        mapKeyReachable       = "reachable"
        mapKeyStatus          = "status"
        mapKeyTlsVersion      = "tls_version"
        mapKeyVersion         = "version"
        strEhloSRN            = "EHLO %s\r\n"
        strInvalidHostname    = "invalid hostname"
        strInvalidRequestBody = "invalid request body"
        strSD                 = "%s:%d"
        strStarttlsRN         = "STARTTLS\r\n"
        mapKeyHost            = "host"
        mapKeyPort            = "port"
        protocolTCP           = "tcp"
        smtpBannerOK          = "220"
        mapKeyScripts         = "scripts"

        ipfsProbeGatewayTimeout = 8 * time.Second
        ipfsProbeBodyLimit      = 1024
        ipfsProbeMaxGateways    = 8
        ipfsProbeMaxRedirects   = 5
)

var (
        probeKey  string
        hostname  string
        startTime time.Time

        rateMu    sync.Mutex
        rateCount = make(map[string]int)

        ipfsGatewayAllowlist = map[string]bool{
                "https://dweb.link":             true,
                "https://ipfs.io":               true,
                "https://w3s.link":              true,
                "https://gateway.pinata.cloud":  true,
                "https://cloudflare-ipfs.com":   true,
                "https://4everland.io":          true,
        }

        cidV0Re = regexp.MustCompile(`^Qm[1-9A-HJ-NP-Za-km-z]{44}$`)
        cidV1Re = regexp.MustCompile(`^b[a-z2-7]{58,}$`)
)

func safeClose(c io.Closer, label string) {
        if err := c.Close(); err != nil {
                slog.Debug("close error", "label", label, mapKeyError, err)
        }
}

func main() {
        probeKey = os.Getenv("PROBE_KEY")
        if probeKey == "" {
                slog.Error("PROBE_KEY environment variable is required")
                os.Exit(1)
        }

        port := os.Getenv("PROBE_PORT")
        if port == "" {
                port = "8443"
        }

        var hostnameErr error
        hostname, hostnameErr = os.Hostname()
        if hostnameErr != nil {
                slog.Warn("failed to get hostname", mapKeyError, hostnameErr)
        }
        startTime = time.Now()

        mux := http.NewServeMux()
        mux.HandleFunc("GET /health", handleHealth)
        mux.HandleFunc("POST /probe/smtp", authMiddleware(rateLimitMiddleware(handleSMTPProbe)))
        mux.HandleFunc("POST /probe/testssl", authMiddleware(rateLimitMiddleware(handleTestSSL)))
        mux.HandleFunc("POST /probe/dane-verify", authMiddleware(rateLimitMiddleware(handleDANEVerify)))
        mux.HandleFunc("POST /probe/nmap", authMiddleware(rateLimitMiddleware(handleNmapScan)))
        mux.HandleFunc("POST /probe/ipfs", authMiddleware(rateLimitMiddleware(handleIPFSProbe)))

        go resetRateLimits()

        server := &http.Server{
                Addr:         ":" + port,
                Handler:      mux,
                ReadTimeout:  30 * time.Second,
                WriteTimeout: 120 * time.Second,
                IdleTimeout:  120 * time.Second,
        }

        go func() {
                slog.Info("DNS Tool Probe Server starting", mapKeyPort, port, mapKeyVersion, probeVersion, "hostname", hostname)
                if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
                        slog.Error("Server failed", mapKeyError, err)
                        os.Exit(1)
                }
        }()

        quit := make(chan os.Signal, 1)
        signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
        <-quit
        slog.Info("Shutting down probe server...")
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        server.Shutdown(ctx)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                if key := r.Header.Get("X-Probe-Key"); subtle.ConstantTimeCompare([]byte(key), []byte(probeKey)) != 1 {
                        http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
                        return
                }
                next(w, r)
        }
}

func rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
        return func(w http.ResponseWriter, r *http.Request) {
                ip, _, err := net.SplitHostPort(r.RemoteAddr)
                if err != nil {
                        ip = r.RemoteAddr
                }
                rateMu.Lock()
                rateCount[ip]++
                count := rateCount[ip]
                rateMu.Unlock()
                if count > 20 {
                        http.Error(w, `{"error":"rate limited"}`, http.StatusTooManyRequests)
                        return
                }
                next(w, r)
        }
}

func resetRateLimits() {
        for {
                time.Sleep(1 * time.Minute)
                rateMu.Lock()
                rateCount = make(map[string]int)
                rateMu.Unlock()
        }
}

func writeJSON(w http.ResponseWriter, status int, v any) {
        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(status)
        json.NewEncoder(w).Encode(v)
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
        writeJSON(w, http.StatusOK, map[string]any{
                mapKeyStatus:  "ok",
                mapKeyVersion: probeVersion,
                "hostname":    hostname,
                "uptime":      time.Since(startTime).String(),
                "time":        time.Now().UTC().Format(time.RFC3339),
        })
}

func handleSMTPProbe(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidRequestBody})
                return
        }

        var req struct {
                Hosts []string `json:"hosts"`
                Ports []int    `json:"ports"`
        }
        if err := json.Unmarshal(body, &req); err != nil || len(req.Hosts) == 0 {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid request: hosts required"})
                return
        }

        if len(req.Hosts) > maxHosts {
                req.Hosts = req.Hosts[:maxHosts]
        }
        for _, h := range req.Hosts {
                if !isValidHostname(h) {
                        writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid hostname: " + truncate(h, 40)})
                        return
                }
        }
        if len(req.Ports) == 0 {
                req.Ports = []int{25, 465, 587}
        }

        ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
        defer cancel()

        servers := probeAllServers(ctx, req.Hosts)

        var allPorts []map[string]any
        for _, host := range req.Hosts {
                for _, port := range req.Ports {
                        if port == 25 {
                                continue
                        }
                        result := probePort(ctx, host, port)
                        allPorts = append(allPorts, result)
                }
        }

        writeJSON(w, http.StatusOK, map[string]any{
                mapKeyProbeHost:      hostname,
                mapKeyVersion:        probeVersion,
                mapKeyElapsedSeconds: time.Since(start).Seconds(),
                "servers":            servers,
                "all_ports":          allPorts,
        })
}

func probeAllServers(ctx context.Context, hosts []string) []map[string]any {
        var mu sync.Mutex
        var wg sync.WaitGroup
        servers := make([]map[string]any, 0, len(hosts))

        for _, host := range hosts {
                wg.Add(1)
                go func(h string) {
                        defer wg.Done()
                        result := probeSMTPServer(ctx, h)
                        mu.Lock()
                        servers = append(servers, result)
                        mu.Unlock()
                }(host)
        }
        wg.Wait()
        return servers
}

func probeSMTPServer(ctx context.Context, host string) map[string]any {
        result := map[string]any{
                mapKeyHost:            host,
                mapKeyReachable:       false,
                "starttls":            false,
                mapKeyTlsVersion:      nil,
                mapKeyCipher:          nil,
                "cipher_bits":         nil,
                mapKeyCertValid:       false,
                "cert_expiry":         nil,
                "cert_days_remaining": nil,
                mapKeyCertIssuer:      nil,
                "cert_subject":        nil,
                mapKeyError:           nil,
        }

        probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
        defer cancel()

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(probeCtx, protocolTCP, net.JoinHostPort(host, "25"))
        if err != nil {
                result[mapKeyError] = classifyError(err)
                return result
        }
        defer safeClose(conn, "probeSMTPServer conn")
        result[mapKeyReachable] = true

        banner, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil || !strings.HasPrefix(banner, smtpBannerOK) {
                result[mapKeyError] = "Unexpected SMTP banner"
                return result
        }

        fmt.Fprintf(conn, strEhloSRN, ehloHostname)
        ehlo, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil {
                result[mapKeyError] = "EHLO response timeout"
                return result
        }

        if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
                result[mapKeyError] = "STARTTLS not supported"
                return result
        }
        result["starttls"] = true

        fmt.Fprintf(conn, strStarttlsRN)
        startResp, err := readSMTPResponse(conn, smtpReadTimeout)
        if err != nil || !strings.HasPrefix(startResp, smtpBannerOK) {
                result[mapKeyError] = "STARTTLS rejected"
                return result
        }

        tlsCfg := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: true, //NOSONAR — S4830/S5527: probe intentionally tests TLS; certificate validation happens separately // SECINTENT-002
        }
        tlsConn := tls.Client(conn, tlsCfg)
        if err := tlsConn.HandshakeContext(probeCtx); err != nil {
                result[mapKeyError] = fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 80))
                return result
        }
        defer safeClose(tlsConn, "probeSMTPServer tlsConn")

        state := tlsConn.ConnectionState()
        result[mapKeyTlsVersion] = tlsVersionString(state.Version)
        result[mapKeyCipher] = tls.CipherSuiteName(state.CipherSuite)
        result["cipher_bits"] = cipherBits(state.CipherSuite)

        verifySMTPCert(probeCtx, host, result)

        return result
}

func verifySMTPCert(ctx context.Context, host string, result map[string]any) {
        verifyCtx, cancel := context.WithTimeout(ctx, tlsTimeout)
        defer cancel()

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(verifyCtx, protocolTCP, net.JoinHostPort(host, "25"))
        if err != nil {
                return
        }
        defer safeClose(conn, "verifySMTPCert conn")

        banner, bannerErr := readSMTPResponse(conn, 1*time.Second)
        if bannerErr != nil {
                slog.Debug("verifySMTPCert: banner read error", mapKeyHost, host, mapKeyError, bannerErr)
        }
        if !strings.HasPrefix(banner, smtpBannerOK) {
                return
        }
        fmt.Fprintf(conn, strEhloSRN, ehloHostname)
        _, ehloErr := readSMTPResponse(conn, 1*time.Second)
        if ehloErr != nil {
                slog.Debug("verifySMTPCert: EHLO read error", mapKeyHost, host, mapKeyError, ehloErr)
        }
        fmt.Fprintf(conn, strStarttlsRN)
        resp, respErr := readSMTPResponse(conn, 1*time.Second)
        if respErr != nil {
                slog.Debug("verifySMTPCert: STARTTLS read error", mapKeyHost, host, mapKeyError, respErr)
        }
        if !strings.HasPrefix(resp, smtpBannerOK) {
                return
        }

        verifyCfg := &tls.Config{ServerName: host}
        verifyTLS := tls.Client(conn, verifyCfg)
        defer safeClose(verifyTLS, "verifySMTPCert verifyTLS")

        if err := verifyTLS.HandshakeContext(verifyCtx); err != nil {
                result[mapKeyCertValid] = false
                result[mapKeyError] = fmt.Sprintf("Certificate invalid: %s", truncate(err.Error(), 100))
                return
        }

        result[mapKeyCertValid] = true
        if certs := verifyTLS.ConnectionState().PeerCertificates; len(certs) > 0 {
                leaf := certs[0]
                result["cert_expiry"] = leaf.NotAfter.Format("2006-01-02")
                result["cert_days_remaining"] = int(time.Until(leaf.NotAfter).Hours() / 24)
                result["cert_subject"] = leaf.Subject.CommonName
                if len(leaf.Issuer.Organization) > 0 {
                        result[mapKeyCertIssuer] = leaf.Issuer.Organization[0]
                } else {
                        result[mapKeyCertIssuer] = leaf.Issuer.CommonName
                }
        }
}

func probePort(ctx context.Context, host string, port int) map[string]any {
        result := map[string]any{
                mapKeyHost:      host,
                mapKeyPort:      port,
                mapKeyReachable: false,
                "tls":           false,
                mapKeyError:     nil,
        }

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, protocolTCP, fmt.Sprintf(strSD, host, port))
        if err != nil {
                result[mapKeyError] = classifyError(err)
                return result
        }
        defer safeClose(conn, "probePort conn")
        result[mapKeyReachable] = true

        if port == 465 {
                tlsConn := tls.Client(conn, &tls.Config{
                        ServerName:         host,
                        InsecureSkipVerify: true, //NOSONAR — S4830/S5527: diagnostic probe; cert validation is separate // SECINTENT-002
                })
                if err := tlsConn.HandshakeContext(ctx); err == nil {
                        result["tls"] = true
                        state := tlsConn.ConnectionState()
                        result[mapKeyTlsVersion] = tlsVersionString(state.Version)
                }
                if err := tlsConn.Close(); err != nil {
                        slog.Debug("close error", "label", "probePort tlsConn", mapKeyError, err)
                }
        }

        return result
}

func handleTestSSL(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidRequestBody})
                return
        }

        var req struct {
                Host string `json:"host"`
                Port int    `json:"port"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: errInvalidHostRequired})
                return
        }
        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidHostname})
                return
        }
        if req.Port == 0 {
                req.Port = 25
        }

        testsslPath, err := exec.LookPath("testssl.sh")
        if err != nil {
                testsslPath, err = exec.LookPath("testssl")
                if err != nil {
                        writeJSON(w, http.StatusServiceUnavailable, map[string]string{mapKeyError: "testssl.sh not installed"})
                        return
                }
        }

        ctx, cancel := context.WithTimeout(r.Context(), 120*time.Second)
        defer cancel()

        target := fmt.Sprintf(strSD, req.Host, req.Port)
        args := []string{
                "--jsonfile", "/dev/stdout",
                "--quiet",
                "--sneaky",
                "--fast",
                "--ip", "one",
                "--warnings", "off",
        }
        if req.Port == 25 {
                args = append(args, "--starttls", "smtp")
        }
        args = append(args, target)

        cmd := exec.CommandContext(ctx, testsslPath, args...)
        cmd.Env = append(os.Environ(), "TERM=xterm")
        output, err := cmd.Output()

        response := map[string]any{
                mapKeyProbeHost:      hostname,
                mapKeyVersion:        probeVersion,
                mapKeyHost:           req.Host,
                mapKeyPort:           req.Port,
                mapKeyElapsedSeconds: time.Since(start).Seconds(),
        }

        if err != nil {
                response[mapKeyStatus] = mapKeyError
                response[mapKeyError] = fmt.Sprintf("testssl.sh failed: %s", truncate(err.Error(), 200))
                if len(output) > 0 {
                        response["partial_output"] = string(output[:min(len(output), 4096)])
                }
                writeJSON(w, http.StatusOK, response)
                return
        }

        var testsslResult any
        if err := json.Unmarshal(output, &testsslResult); err != nil {
                response[mapKeyStatus] = "raw"
                response["raw_output"] = string(output[:min(len(output), 32768)])
        } else {
                response[mapKeyStatus] = "ok"
                response["testssl"] = testsslResult
        }

        writeJSON(w, http.StatusOK, response)
}

func handleDANEVerify(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidRequestBody})
                return
        }

        var req struct {
                Host string `json:"host"`
                Port int    `json:"port"`
        }
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: errInvalidHostRequired})
                return
        }
        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidHostname})
                return
        }
        if req.Port == 0 {
                req.Port = 25
        }

        ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
        defer cancel()

        response := map[string]any{
                mapKeyProbeHost:      hostname,
                mapKeyVersion:        probeVersion,
                mapKeyHost:           req.Host,
                mapKeyPort:           req.Port,
                mapKeyElapsedSeconds: 0.0,
        }

        tlsaName := fmt.Sprintf("_%d._tcp.%s", req.Port, req.Host)
        digCtx, digCancel := context.WithTimeout(ctx, 8*time.Second)
        defer digCancel()
        digCmd := exec.CommandContext(digCtx, "dig", "+short", "TLSA", tlsaName)
        tlsaOut, err := digCmd.Output()
        tlsaRecords := strings.TrimSpace(string(tlsaOut))

        if err != nil || tlsaRecords == "" {
                response[mapKeyStatus] = "no_tlsa"
                response["message"] = fmt.Sprintf("No TLSA records found at %s", tlsaName)
                response[mapKeyElapsedSeconds] = time.Since(start).Seconds()
                writeJSON(w, http.StatusOK, response)
                return
        }

        response["tlsa_records"] = strings.Split(tlsaRecords, "\n")

        var certInfo map[string]any
        if req.Port == 25 {
                certInfo = getCertViaSMTP(ctx, req.Host)
        } else {
                certInfo = getCertViaTLS(ctx, req.Host, req.Port)
        }
        response["cert"] = certInfo

        if certInfo[mapKeyError] != nil {
                response[mapKeyStatus] = "cert_error"
        } else {
                response[mapKeyStatus] = "verified"
        }

        response[mapKeyElapsedSeconds] = time.Since(start).Seconds()
        writeJSON(w, http.StatusOK, response)
}

func getCertViaSMTP(ctx context.Context, host string) map[string]any {
        result := map[string]any{"method": "smtp_starttls"}

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, protocolTCP, net.JoinHostPort(host, "25"))
        if err != nil {
                result[mapKeyError] = classifyError(err)
                return result
        }
        defer safeClose(conn, "getCertViaSMTP conn")

        banner, bannerErr := readSMTPResponse(conn, smtpReadTimeout)
        if bannerErr != nil {
                slog.Debug("getCertViaSMTP: banner read error", mapKeyHost, host, mapKeyError, bannerErr)
        }
        if !strings.HasPrefix(banner, smtpBannerOK) {
                result[mapKeyError] = "Bad SMTP banner"
                return result
        }

        fmt.Fprintf(conn, strEhloSRN, ehloHostname)
        ehlo, ehloErr := readSMTPResponse(conn, smtpReadTimeout)
        if ehloErr != nil {
                slog.Debug("getCertViaSMTP: EHLO read error", mapKeyHost, host, mapKeyError, ehloErr)
        }
        if !strings.Contains(strings.ToUpper(ehlo), "STARTTLS") {
                result[mapKeyError] = "STARTTLS not supported"
                return result
        }

        fmt.Fprintf(conn, strStarttlsRN)
        resp, respErr := readSMTPResponse(conn, smtpReadTimeout)
        if respErr != nil {
                slog.Debug("getCertViaSMTP: STARTTLS read error", mapKeyHost, host, mapKeyError, respErr)
        }
        if !strings.HasPrefix(resp, smtpBannerOK) {
                result[mapKeyError] = "STARTTLS rejected"
                return result
        }

        return extractCertInfo(conn, host)
}

func getCertViaTLS(ctx context.Context, host string, port int) map[string]any {
        result := map[string]any{"method": "direct_tls"}

        dialer := &net.Dialer{Timeout: smtpDialTimeout}
        conn, err := dialer.DialContext(ctx, protocolTCP, fmt.Sprintf(strSD, host, port))
        if err != nil {
                result[mapKeyError] = classifyError(err)
                return result
        }
        defer safeClose(conn, "getCertViaTLS conn")

        return extractCertInfo(conn, host)
}

func extractCertInfo(conn net.Conn, host string) map[string]any {
        result := map[string]any{}

        tlsCfg := &tls.Config{
                ServerName:         host,
                InsecureSkipVerify: true, //NOSONAR — S4830/S5527: needs to connect regardless of cert validity to extract cert info // SECINTENT-002
        }
        tlsConn := tls.Client(conn, tlsCfg)
        defer safeClose(tlsConn, "extractCertInfo tlsConn")

        if err := tlsConn.Handshake(); err != nil {
                result[mapKeyError] = fmt.Sprintf("TLS handshake failed: %s", truncate(err.Error(), 100))
                return result
        }

        state := tlsConn.ConnectionState()
        result[mapKeyTlsVersion] = tlsVersionString(state.Version)
        result[mapKeyCipher] = tls.CipherSuiteName(state.CipherSuite)

        if len(state.PeerCertificates) > 0 {
                leaf := state.PeerCertificates[0]
                result["subject"] = leaf.Subject.CommonName
                result["sans"] = leaf.DNSNames
                result["not_before"] = leaf.NotBefore.Format(time.RFC3339)
                result["not_after"] = leaf.NotAfter.Format(time.RFC3339)
                result["days_remaining"] = int(time.Until(leaf.NotAfter).Hours() / 24)
                if len(leaf.Issuer.Organization) > 0 {
                        result["issuer"] = leaf.Issuer.Organization[0]
                } else {
                        result["issuer"] = leaf.Issuer.CommonName
                }

                result["fingerprint_sha256"] = fmt.Sprintf("%x", leaf.Raw)
                result["serial"] = leaf.SerialNumber.String()
        }

        return result
}

const maxSMTPResponseSize = 64 * 1024

func readSMTPResponse(conn net.Conn, timeout time.Duration) (string, error) {
        conn.SetReadDeadline(time.Now().Add(timeout))
        buf := make([]byte, 4096)
        var response strings.Builder
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        response.Write(buf[:n])
                        if response.Len() > maxSMTPResponseSize {
                                return response.String(), fmt.Errorf("SMTP response exceeded %d bytes", maxSMTPResponseSize)
                        }
                        if smtpComplete(response.String()) {
                                break
                        }
                }
                if err != nil {
                        if response.Len() > 0 {
                                return response.String(), nil
                        }
                        return "", err
                }
        }
        return response.String(), nil
}

func smtpComplete(data string) bool {
        lines := strings.Split(data, "\n")
        last := strings.TrimSpace(lines[len(lines)-1])
        if last == "" && len(lines) > 1 {
                last = strings.TrimSpace(lines[len(lines)-2])
        }
        return len(last) >= 4 && last[3] == ' '
}

func classifyError(err error) string {
        s := err.Error()
        if strings.Contains(s, "timeout") || strings.Contains(s, "deadline") {
                return "Connection timeout"
        }
        if strings.Contains(s, "refused") {
                return "Connection refused"
        }
        if strings.Contains(s, "unreachable") {
                return "Network unreachable"
        }
        if strings.Contains(s, "no such host") {
                return "DNS resolution failed"
        }
        return truncate(s, 80)
}

func tlsVersionString(v uint16) string {
        switch v {
        case tls.VersionTLS13:
                return "TLSv1.3"
        case tls.VersionTLS12:
                return "TLSv1.2"
        case tls.VersionTLS11:
                return "TLSv1.1"
        case tls.VersionTLS10:
                return "TLSv1.0"
        default:
                return fmt.Sprintf("TLS 0x%04x", v)
        }
}

func cipherBits(suite uint16) int {
        name := tls.CipherSuiteName(suite)
        if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
                return 256
        }
        if strings.Contains(name, "128") {
                return 128
        }
        return 0
}

func truncate(s string, maxLen int) string {
        if len(s) <= maxLen {
                return s
        }
        return s[:maxLen]
}

func isValidHostname(host string) bool {
        if len(host) == 0 || len(host) > 253 {
                return false
        }
        if strings.HasPrefix(host, "-") || strings.HasPrefix(host, ".") {
                return false
        }
        for _, ch := range host {
                if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
                        return false
                }
        }
        return true
}

var allowedNSEScripts = map[string]bool{
        "ssl-cert":          true,
        "http-title":        true,
        "http-headers":      true,
        "dns-zone-transfer": true,
        "banner":            true,
        "smtp-commands":     true,
}

type nmapRequest struct {
        Host    string   `json:"host"`
        Ports   string   `json:"ports"`
        Scripts []string `json:"scripts"`
}

func handleNmapScan(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidRequestBody})
                return
        }

        var req nmapRequest
        if err := json.Unmarshal(body, &req); err != nil || req.Host == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: errInvalidHostRequired})
                return
        }
        if !isValidHostname(req.Host) {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidHostname})
                return
        }
        if req.Ports == "" {
                req.Ports = "25,80,443,465,587"
        }
        if !isValidPortSpec(req.Ports) {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid port specification"})
                return
        }

        validScripts, rejectedScripts := filterNmapScripts(req.Scripts)

        nmapPath, err := exec.LookPath("nmap")
        if err != nil {
                writeJSON(w, http.StatusServiceUnavailable, map[string]string{mapKeyError: "nmap not installed"})
                return
        }

        ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
        defer cancel()

        response := runNmapScan(ctx, nmapPath, req, validScripts, rejectedScripts, start)
        writeJSON(w, http.StatusOK, response)
}

func isValidPortSpec(ports string) bool {
        for _, ch := range ports {
                if ch != ',' && (ch < '0' || ch > '9') && ch != '-' {
                        return false
                }
        }
        return true
}

func filterNmapScripts(scripts []string) (valid, rejected []string) {
        for _, s := range scripts {
                s = strings.TrimSpace(s)
                if allowedNSEScripts[s] {
                        valid = append(valid, s)
                } else if s != "" {
                        rejected = append(rejected, s)
                }
        }
        if len(valid) == 0 {
                valid = []string{"ssl-cert", "http-title", "banner"}
        }
        return valid, rejected
}

func runNmapScan(ctx context.Context, nmapPath string, req nmapRequest, validScripts, rejectedScripts []string, start time.Time) map[string]any {
        args := []string{
                "-Pn", "-sV", "--open",
                "-p", req.Ports,
                "--script", strings.Join(validScripts, ","),
                "-oX", "-",
                "--host-timeout", "60s",
                "--max-retries", "2",
                req.Host,
        }

        slog.Info("Nmap scan requested", mapKeyHost, req.Host, mapKeyPorts, req.Ports, mapKeyScripts, validScripts)

        cmd := exec.CommandContext(ctx, nmapPath, args...)
        var stdout, stderr bytes.Buffer
        cmd.Stdout = &stdout
        cmd.Stderr = &stderr
        err := cmd.Run()

        response := map[string]any{
                mapKeyProbeHost:      hostname,
                mapKeyVersion:        probeVersion,
                mapKeyHost:           req.Host,
                mapKeyPorts:          req.Ports,
                "scripts_run":        validScripts,
                mapKeyElapsedSeconds: time.Since(start).Seconds(),
        }
        if len(rejectedScripts) > 0 {
                response["rejected_scripts"] = rejectedScripts
        }

        xmlOutput := stdout.String()
        if err != nil {
                buildNmapErrorResponse(response, err, xmlOutput, stderr.String())
        } else {
                buildNmapSuccessResponse(response, xmlOutput)
        }
        return response
}

func buildNmapErrorResponse(response map[string]any, err error, xmlOutput, stderrOutput string) {
        response[mapKeyStatus] = mapKeyError
        response[mapKeyError] = fmt.Sprintf("nmap failed: %s", truncate(err.Error(), 200))
        if xmlOutput != "" {
                response["partial_xml"] = truncate(xmlOutput, 8192)
        }
        if stderrStr := strings.TrimSpace(stderrOutput); stderrStr != "" {
                response["stderr"] = truncate(stderrStr, 1024)
        }
}

func buildNmapSuccessResponse(response map[string]any, xmlOutput string) {
        response[mapKeyStatus] = "ok"
        response["xml"] = xmlOutput
        if parsed := parseNmapXML(xmlOutput); parsed != nil {
                response["parsed"] = parsed
        }
}

type nmapPortState struct {
        State  string `xml:"state,attr"`
        Reason string `xml:"reason,attr"`
}

type nmapPortService struct {
        Name    string `xml:"name,attr"`
        Product string `xml:"product,attr"`
        Version string `xml:"version,attr"`
        Tunnel  string `xml:"tunnel,attr"`
}

type nmapScriptTableElem struct {
        Key   string `xml:"key,attr"`
        Value string `xml:",chardata"`
}

type nmapScriptTable struct {
        Key   string                `xml:"key,attr"`
        Elems []nmapScriptTableElem `xml:"elem"`
}

type nmapScript struct {
        ID     string            `xml:"id,attr"`
        Output string            `xml:"output,attr"`
        Tables []nmapScriptTable `xml:"table"`
}

type nmapPort struct {
        Protocol string          `xml:"protocol,attr"`
        PortID   int             `xml:"portid,attr"`
        State    nmapPortState   `xml:"state"`
        Service  nmapPortService `xml:"service"`
        Scripts  []nmapScript    `xml:"script"`
}

type nmapHostStatus struct {
        State string `xml:"state,attr"`
}

type nmapAddress struct {
        Addr     string `xml:"addr,attr"`
        AddrType string `xml:"addrtype,attr"`
}

type nmapHostname struct {
        Name string `xml:"name,attr"`
        Type string `xml:"type,attr"`
}

type nmapHost struct {
        Status    nmapHostStatus `xml:"status"`
        Addresses []nmapAddress  `xml:"address"`
        Hostnames []nmapHostname `xml:"hostnames>hostname"`
        Ports     []nmapPort     `xml:"ports>port"`
}

type nmapFinished struct {
        TimeStr string `xml:"timestr,attr"`
        Elapsed string `xml:"elapsed,attr"`
}

type nmapRunStats struct {
        Finished nmapFinished `xml:"finished"`
}

type nmapRun struct {
        Scanner  string       `xml:"scanner,attr"`
        StartStr string       `xml:"startstr,attr"`
        Version  string       `xml:"version,attr"`
        Hosts    []nmapHost   `xml:"host"`
        RunStats nmapRunStats `xml:"runstats"`
}

func parseNmapXML(xmlData string) map[string]any {
        var run nmapRun
        if err := xml.Unmarshal([]byte(xmlData), &run); err != nil {
                return nil
        }

        result := map[string]any{
                "scanner":     run.Scanner,
                mapKeyVersion: run.Version,
                "start":       run.StartStr,
                "elapsed":     run.RunStats.Finished.Elapsed,
        }

        var hosts []map[string]any
        for _, h := range run.Hosts {
                hosts = append(hosts, convertNmapHost(h))
        }
        result["hosts"] = hosts
        return result
}

func convertNmapHost(h nmapHost) map[string]any {
        host := map[string]any{mapKeyStatus: h.Status.State}

        var addrs []map[string]string
        for _, a := range h.Addresses {
                addrs = append(addrs, map[string]string{"addr": a.Addr, "type": a.AddrType})
        }
        host["addresses"] = addrs

        var names []string
        for _, hn := range h.Hostnames {
                names = append(names, hn.Name)
        }
        if len(names) > 0 {
                host["hostnames"] = names
        }

        var ports []map[string]any
        for _, p := range h.Ports {
                ports = append(ports, convertNmapPort(p))
        }
        host[mapKeyPorts] = ports
        return host
}

func convertNmapPort(p nmapPort) map[string]any {
        port := map[string]any{
                mapKeyPort: p.PortID,
                "protocol": p.Protocol,
                "state":    p.State.State,
                "service":  p.Service.Name,
        }
        if p.Service.Product != "" {
                port["product"] = p.Service.Product
        }
        if p.Service.Version != "" {
                port[mapKeyVersion] = p.Service.Version
        }
        if p.Service.Tunnel != "" {
                port["tunnel"] = p.Service.Tunnel
        }
        var scripts []map[string]any
        for _, s := range p.Scripts {
                scripts = append(scripts, map[string]any{"id": s.ID, "output": s.Output})
        }
        if len(scripts) > 0 {
                port[mapKeyScripts] = scripts
        }
        return port
}

func isValidCID(cid string) bool {
        return cid != "" && (cidV0Re.MatchString(cid) || cidV1Re.MatchString(cid))
}

func isAllowlistedGateway(gw string) bool {
        return ipfsGatewayAllowlist[gw]
}

func isAllowlistedGatewayHost(target string) bool {
        if ipfsGatewayAllowlist[target] {
                return true
        }
        for gw := range ipfsGatewayAllowlist {
                gwHost := strings.TrimPrefix(gw, "https://")
                targetHost := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
                if targetHost == gwHost || strings.HasSuffix(targetHost, "."+gwHost) {
                        return true
                }
        }
        return false
}

type ipfsProbeRequest struct {
        CID      string   `json:"cid"`
        Gateways []string `json:"gateways"`
}

type ipfsGatewayResult struct {
        Gateway       string            `json:"gateway"`
        Reachable     bool              `json:"reachable"`
        StatusCode    int               `json:"status_code,omitempty"`
        ContentType   string            `json:"content_type,omitempty"`
        LatencyMs     int64             `json:"latency_ms"`
        ServerHeader  string            `json:"server_header,omitempty"`
        TLSVersion    string            `json:"tls_version,omitempty"`
        RedirectChain []ipfsRedirectHop `json:"redirect_chain,omitempty"`
        FinalURL      string            `json:"final_url,omitempty"`
        Error         string            `json:"error,omitempty"`
}

type ipfsRedirectHop struct {
        StatusCode   int    `json:"status_code"`
        LocationHost string `json:"location_host"`
        LatencyMs    int64  `json:"latency_ms"`
}

func handleIPFSProbe(w http.ResponseWriter, r *http.Request) {
        start := time.Now()

        body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody))
        if err != nil {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: strInvalidRequestBody})
                return
        }

        var req ipfsProbeRequest
        if err := json.Unmarshal(body, &req); err != nil || req.CID == "" {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid request: cid required"})
                return
        }

        if !isValidCID(req.CID) {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid CID format"})
                return
        }

        if len(req.Gateways) == 0 {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "invalid request: gateways required"})
                return
        }
        if len(req.Gateways) > ipfsProbeMaxGateways {
                req.Gateways = req.Gateways[:ipfsProbeMaxGateways]
        }

        var safeGateways []string
        for _, gw := range req.Gateways {
                if isAllowlistedGateway(gw) {
                        safeGateways = append(safeGateways, gw)
                } else {
                        slog.Warn("IPFS probe: rejected non-allowlisted gateway", "gateway", gw)
                }
        }
        if len(safeGateways) == 0 {
                writeJSON(w, http.StatusBadRequest, map[string]string{mapKeyError: "no allowlisted gateways provided"})
                return
        }

        ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
        defer cancel()

        results := probeIPFSGateways(ctx, req.CID, safeGateways)

        writeJSON(w, http.StatusOK, map[string]any{
                mapKeyProbeHost:      hostname,
                mapKeyVersion:        probeVersion,
                mapKeyElapsedSeconds: time.Since(start).Seconds(),
                "cid":                req.CID,
                "results":            results,
        })

        slog.Info("IPFS probe completed",
                "cid", truncate(req.CID, 20),
                "gateways", len(safeGateways),
                "elapsed", time.Since(start).Seconds(),
        )
}

func probeIPFSGateways(ctx context.Context, cid string, gateways []string) []ipfsGatewayResult {
        type indexedResult struct {
                idx    int
                result ipfsGatewayResult
        }

        ch := make(chan indexedResult, len(gateways))
        sem := make(chan struct{}, 3)

        for i, gw := range gateways {
                go func(idx int, gateway string) {
                        sem <- struct{}{}
                        defer func() { <-sem }()
                        ch <- indexedResult{idx: idx, result: probeOneIPFSGateway(ctx, cid, gateway)}
                }(i, gw)
        }

        results := make([]ipfsGatewayResult, len(gateways))
        for range gateways {
                ir := <-ch
                results[ir.idx] = ir.result
        }
        return results
}

func probeOneIPFSGateway(ctx context.Context, cid, gateway string) ipfsGatewayResult {
        gwResult := ipfsGatewayResult{Gateway: gateway}
        probeURL := fmt.Sprintf("%s/ipfs/%s", gateway, cid)

        gwCtx, cancel := context.WithTimeout(ctx, ipfsProbeGatewayTimeout)
        defer cancel()

        transport := &http.Transport{
                TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
                DisableKeepAlives: true,
        }
        client := &http.Client{
                Transport: transport,
                Timeout:   ipfsProbeGatewayTimeout,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        if len(via) >= ipfsProbeMaxRedirects {
                                return http.ErrUseLastResponse
                        }
                        targetHost := req.URL.Scheme + "://" + req.URL.Host
                        if !isAllowlistedGatewayHost(targetHost) {
                                slog.Warn("IPFS probe: blocked redirect to non-allowlisted host", "target", targetHost, "gateway", gateway)
                                return http.ErrUseLastResponse
                        }
                        return nil
                },
        }

        start := time.Now()
        req, err := http.NewRequestWithContext(gwCtx, "GET", probeURL, nil)
        if err != nil {
                gwResult.Error = "request creation error"
                gwResult.LatencyMs = time.Since(start).Milliseconds()
                return gwResult
        }
        req.Header.Set("User-Agent", "DNS-Tool-IPFS-Probe/1.0")

        var redirectChain []ipfsRedirectHop
        origTransport := client.Transport
        client.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
                hopStart := time.Now()
                resp, rtErr := origTransport.RoundTrip(r)
                if rtErr == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 {
                        loc := resp.Header.Get("Location")
                        locHost := ""
                        if parsed, parseErr := r.URL.Parse(loc); parseErr == nil {
                                locHost = parsed.Host
                        }
                        redirectChain = append(redirectChain, ipfsRedirectHop{
                                StatusCode:   resp.StatusCode,
                                LocationHost: locHost,
                                LatencyMs:    time.Since(hopStart).Milliseconds(),
                        })
                }
                return resp, rtErr
        })

        resp, err := client.Do(req)
        gwResult.LatencyMs = time.Since(start).Milliseconds()
        if err != nil {
                gwResult.Error = classifyIPFSError(err)
                return gwResult
        }
        defer func() {
                _, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, int64(ipfsProbeBodyLimit)))
                resp.Body.Close()
        }()

        gwResult.StatusCode = resp.StatusCode
        gwResult.Reachable = resp.StatusCode >= 200 && resp.StatusCode < 400
        gwResult.ContentType = resp.Header.Get("Content-Type")
        gwResult.ServerHeader = resp.Header.Get("Server")
        gwResult.FinalURL = resp.Request.URL.String()

        if resp.TLS != nil {
                gwResult.TLSVersion = ipfsTLSVersionString(resp.TLS.Version)
        }

        if len(redirectChain) > 0 {
                gwResult.RedirectChain = redirectChain
        }

        return gwResult
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func ipfsTLSVersionString(v uint16) string {
        switch v {
        case tls.VersionTLS10:
                return "TLS 1.0"
        case tls.VersionTLS11:
                return "TLS 1.1"
        case tls.VersionTLS12:
                return "TLS 1.2"
        case tls.VersionTLS13:
                return "TLS 1.3"
        default:
                return fmt.Sprintf("unknown (0x%04x)", v)
        }
}

func classifyIPFSError(err error) string {
        s := err.Error()
        switch {
        case strings.Contains(s, "timeout"):
                return "timeout"
        case strings.Contains(s, "refused"):
                return "connection refused"
        case strings.Contains(s, "no such host"):
                return "DNS resolution failed"
        case strings.Contains(s, "certificate"):
                return "TLS certificate error"
        default:
                return "connection error"
        }
}
