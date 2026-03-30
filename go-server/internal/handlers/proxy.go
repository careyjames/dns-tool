// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny design
package handlers

import (
        "fmt"
        "io"
        "log/slog"
        "net"
        "net/http"
        "net/url"
        "strings"
        "time"

        "dnstool/go-server/internal/dnsclient"

        "github.com/gin-gonic/gin"
)

const (
        bimiMaxRedirects     = 5
        bimiMaxResponseBytes = 512 * 1024
        bimiUserAgent        = "DNS-Analyzer/1.0 BIMI-Logo-Fetcher"
        hdrUserAgent         = "User-Agent"
        msgInternalError     = "Internal error"
        ctSVGXML             = "image/svg+xml"
)

var bimiAllowedContentTypes = map[string]bool{
        ctSVGXML: true,
        "image/png":     true,
        "image/jpeg":    true,
        "image/gif":     true,
        "image/webp":    true,
}

type ProxyHandler struct{}

func NewProxyHandler() *ProxyHandler {
        return &ProxyHandler{}
}

func (h *ProxyHandler) BIMILogo(c *gin.Context) {
        logoURL := c.Query("url")
        if logoURL == "" {
                c.String(http.StatusBadRequest, "Missing URL parameter")
                return
        }

        parsed, err := url.Parse(logoURL)
        if err != nil {
                c.String(http.StatusBadRequest, "Invalid URL")
                return
        }

        if err := validateParsedURL(parsed); err != nil {
                c.String(http.StatusBadRequest, err.Error())
                return
        }

        if err := checkSSRF(parsed.Hostname()); err != nil {
                c.String(http.StatusBadRequest, err.Error())
                return
        }

        safeURL := buildSafeURL(parsed)

        client := &http.Client{
                Timeout: 5 * time.Second,
                CheckRedirect: func(req *http.Request, via []*http.Request) error {
                        return http.ErrUseLastResponse
                },
        }

        req, err := http.NewRequestWithContext(c.Request.Context(), "GET", safeURL, nil)
        if err != nil {
                slog.Error("Failed to create BIMI request", "error", err)
                c.String(http.StatusInternalServerError, msgInternalError)
                return
        }
        req.Header.Set(hdrUserAgent, bimiUserAgent)

        resp, err := client.Do(req)
        if err != nil {
                slog.Error("Failed to fetch BIMI logo", "error", err)
                c.String(http.StatusBadGateway, "Failed to fetch logo")
                return
        }
        defer safeClose(resp.Body, "BIMI response body")

        resp, err = h.followRedirects(c, client, resp)
        if err != nil {
                return
        }
        defer safeClose(resp.Body, "BIMI redirect response body")

        body, safeCT, err := validateBIMIResponse(resp)
        if err != nil {
                if ve, ok := err.(*bimiFetchError); ok {
                        c.String(ve.status, ve.msg)
                } else {
                        c.String(http.StatusInternalServerError, "Error reading response")
                }
                return
        }

        c.Header("Cache-Control", "public, max-age=3600")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("Content-Security-Policy", "default-src 'none'; style-src 'none'")
        c.Header("X-Frame-Options", "DENY")
        c.Data(http.StatusOK, safeCT, body)
}

func validateParsedURL(parsed *url.URL) error {
        if parsed.Scheme != "https" {
                return &validationError{"Only HTTPS URLs allowed"}
        }
        if parsed.Hostname() == "" {
                return &validationError{"Invalid URL"}
        }
        return nil
}

func checkSSRF(hostname string) error {
        ips, err := net.LookupIP(hostname)
        if err != nil {
                return &validationError{"Could not resolve hostname"}
        }
        for _, ip := range ips {
                if dnsclient.IsPrivateIP(ip.String()) {
                        return &validationError{"URL points to a disallowed address"}
                }
        }
        return nil
}

func buildSafeURL(parsed *url.URL) string {
        u := &url.URL{
                Scheme:   "https",
                Host:     parsed.Host,
                Path:     parsed.Path,
                RawQuery: parsed.RawQuery,
                Fragment: parsed.Fragment,
        }
        return u.String()
}

type bimiFetchError struct {
        status int
        msg    string
}

func (e *bimiFetchError) Error() string {
        return e.msg
}

func (h *ProxyHandler) followRedirects(c *gin.Context, client *http.Client, resp *http.Response) (*http.Response, error) {
        redirectCount := 0
        for resp.StatusCode >= 301 && resp.StatusCode <= 308 && redirectCount < bimiMaxRedirects {
                redirectCount++
                redirectURL := resp.Header.Get("Location")
                if redirectURL == "" {
                        resp.Body.Close()
                        c.String(http.StatusBadGateway, "Redirect without Location header")
                        return nil, fmt.Errorf("redirect without location")
                }

                rParsed, err := url.Parse(redirectURL)
                if err != nil {
                        resp.Body.Close()
                        c.String(http.StatusBadRequest, "Invalid redirect URL")
                        return nil, err
                }
                if err := validateParsedURL(rParsed); err != nil {
                        resp.Body.Close()
                        c.String(http.StatusBadRequest, err.Error())
                        return nil, err
                }
                if err := checkSSRF(rParsed.Hostname()); err != nil {
                        resp.Body.Close()
                        c.String(http.StatusBadRequest, err.Error())
                        return nil, err
                }

                resp.Body.Close()
                validatedRedirect := buildSafeURL(rParsed)
                req, err := http.NewRequestWithContext(c.Request.Context(), "GET", validatedRedirect, nil)
                if err != nil {
                        slog.Error("Failed to create redirect request", "error", err)
                        c.String(http.StatusInternalServerError, msgInternalError)
                        return nil, err
                }
                req.Header.Set(hdrUserAgent, bimiUserAgent)
                resp, err = client.Do(req)
                if err != nil {
                        c.String(http.StatusBadGateway, "Failed to follow redirect")
                        return nil, err
                }
        }
        return resp, nil
}

func validateBIMIResponse(resp *http.Response) ([]byte, string, error) {
        if resp.StatusCode != 200 {
                return nil, "", &bimiFetchError{http.StatusBadGateway, fmt.Sprintf("Failed to fetch logo: %d", resp.StatusCode)}
        }

        contentType := resp.Header.Get("Content-Type")
        isImage := strings.Contains(strings.ToLower(contentType), "svg") ||
                strings.Contains(strings.ToLower(contentType), "image")
        if !isImage {
                return nil, "", &bimiFetchError{http.StatusBadRequest, "Response is not an image"}
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, bimiMaxResponseBytes+1))
        if err != nil {
                return nil, "", err
        }
        if len(body) > bimiMaxResponseBytes {
                return nil, "", &bimiFetchError{http.StatusBadRequest, "Response too large"}
        }

        safeCT := strings.TrimSpace(strings.Split(strings.ToLower(contentType), ";")[0])
        if !bimiAllowedContentTypes[safeCT] {
                safeCT = ctSVGXML
        }
        return body, safeCT, nil
}

var sonarBadgeURLs = map[string]string{
        "qg-full":  "https://sonarcloud.io/api/project_badges/measure?project=ithelpsandiego_dns-tool-full&metric=alert_status",
        "ai-full":  "https://sonarcloud.io/api/project_badges/ai_code_assurance?project=ithelpsandiego_dns-tool-full",
        "qg-cli":   "https://sonarcloud.io/api/project_badges/measure?project=ithelpsandiego_dns-tool-cli&metric=alert_status",
        "ai-cli":   "https://sonarcloud.io/api/project_badges/ai_code_assurance?project=ithelpsandiego_dns-tool-cli",
}

func (h *ProxyHandler) SonarBadge(c *gin.Context) {
        key := c.Param("key")
        badgeURL, ok := sonarBadgeURLs[key]
        if !ok {
                c.String(http.StatusNotFound, "Unknown badge")
                return
        }

        client := &http.Client{Timeout: 10 * time.Second}
        req, err := http.NewRequestWithContext(c.Request.Context(), "GET", badgeURL, nil)
        if err != nil {
                slog.Error("Failed to create SonarCloud badge request", "key", key, "error", err)
                c.String(http.StatusInternalServerError, msgInternalError)
                return
        }
        req.Header.Set(hdrUserAgent, "DNS-Tool/1.0 Badge-Proxy")

        resp, err := client.Do(req)
        if err != nil {
                slog.Error("Failed to fetch SonarCloud badge", "key", key, "error", err)
                c.String(http.StatusBadGateway, "Failed to fetch badge")
                return
        }
        defer safeClose(resp.Body, "SonarCloud badge response body")

        if resp.StatusCode != http.StatusOK {
                c.String(http.StatusBadGateway, "Badge service returned %d", resp.StatusCode)
                return
        }

        body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
        if err != nil {
                c.String(http.StatusInternalServerError, "Error reading badge")
                return
        }

        c.Header("Cache-Control", "public, max-age=300, stale-while-revalidate=60")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Data(http.StatusOK, ctSVGXML, body)
}

type validationError struct {
        msg string
}

func (e *validationError) Error() string {
        return e.msg
}
