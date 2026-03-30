// Copyright (c) 2024-2026 IT Help San Diego Inc.
// Licensed under BUSL-1.1 — See LICENSE for terms.
// dns-tool:scrutiny science
package analyzer

import (
        "encoding/json"
        "strings"
)

const (
        headerSubject    = "Subject: "
        headerFrom       = "From: "
        headerSep        = "\r\n"
        jsonKeyValue     = "value"
        jsonKeyHeaders   = "headers"
        jsonKeyName      = "name"
        formatRaw        = "raw"
        jsonKeyHeadersUC = "Headers"
)

type DetectedFormat struct {
        Format  string
        Headers string
        Error   string
}

func DetectAndExtractHeaders(raw, filename string) *DetectedFormat {
        trimmed := strings.TrimSpace(raw)

        if isBinaryContent(trimmed) {
                return handleBinaryFile(filename)
        }

        if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
                return tryExtractFromJSON(trimmed)
        }

        if strings.HasPrefix(trimmed, "From ") && isMboxFormat(trimmed) {
                return extractFromMbox(trimmed)
        }

        return &DetectedFormat{
                Format:  formatRaw,
                Headers: raw,
        }
}

func isBinaryContent(data string) bool {
        if len(data) < 8 {
                return false
        }
        checkLen := 512
        if len(data) < checkLen {
                checkLen = len(data)
        }
        nullCount := 0
        for i := 0; i < checkLen; i++ {
                if data[i] == 0 {
                        nullCount++
                }
        }
        return nullCount > 4
}

func handleBinaryFile(filename string) *DetectedFormat {
        if lower := strings.ToLower(filename); strings.HasSuffix(lower, ".msg") {
                return &DetectedFormat{
                        Format: "msg",
                        Error:  "Outlook .msg files use a proprietary binary format we can't read directly. In Outlook, open the message → File → Save As → choose \".eml\" format, then upload that instead.",
                }
        }
        return &DetectedFormat{
                Format: "binary",
                Error:  "This appears to be a binary file. Please paste the headers as text, or save the email as .eml format and upload that.",
        }
}

func tryExtractFromJSON(raw string) *DetectedFormat {
        raw = strings.TrimSpace(raw)

        obj := unmarshalJSONObject(raw)
        if obj == nil {
                return &DetectedFormat{Format: formatRaw, Headers: raw}
        }

        return matchJSONProvider(obj)
}

func unmarshalJSONObject(raw string) map[string]interface{} {
        var obj map[string]interface{}
        if err := json.Unmarshal([]byte(raw), &obj); err == nil {
                return obj
        }
        var arr []interface{}
        if err := json.Unmarshal([]byte(raw), &arr); err != nil {
                return nil
        }
        if len(arr) > 0 {
                if first, ok := arr[0].(map[string]interface{}); ok {
                        return first
                }
        }
        return nil
}

func matchJSONProvider(obj map[string]interface{}) *DetectedFormat {
        providers := []struct {
                name string
                fn   func(map[string]interface{}) string
        }{
                {"json-microsoft-graph", extractMicrosoftGraphHeaders},
                {"json-gmail-api", extractGmailAPIHeaders},
                {"json-postmark", extractPostmarkHeaders},
                {"json-sendgrid", extractSendGridHeaders},
                {"json-mailgun", extractMailgunHeaders},
                {"json-generic", extractGenericJSONHeaders},
        }
        for _, p := range providers {
                if headers := p.fn(obj); headers != "" {
                        return &DetectedFormat{Format: p.name, Headers: headers}
                }
        }
        return &DetectedFormat{
                Format: "json",
                Error:  "We found valid JSON but couldn't locate email headers in it. Supported formats: Gmail API, Microsoft Graph API, Postmark, SendGrid, Mailgun, or any JSON with a \"headers\" key containing RFC 5322 header fields.",
        }
}

func extractMicrosoftGraphHeaders(obj map[string]interface{}) string {
        imh, ok := obj["internetMessageHeaders"]
        if !ok {
                return ""
        }
        arr, ok := imh.([]interface{})
        if !ok {
                return ""
        }
        lines := extractHeaderArray(arr, jsonKeyName, "value")

        lines = prependMissingHeader(lines, "subject:", func() string {
                if subject, ok := obj["subject"].(string); ok && subject != "" {
                        return headerSubject + subject
                }
                return ""
        })
        lines = prependMissingHeader(lines, "from:", func() string {
                return extractMSGraphFrom(obj)
        })

        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func extractMSGraphFrom(obj map[string]interface{}) string {
        from, ok := obj["from"].(map[string]interface{})
        if !ok {
                return ""
        }
        ea, ok := from["emailAddress"].(map[string]interface{})
        if !ok {
                return ""
        }
        addr, _ := ea["address"].(string)
        name, _ := ea[jsonKeyName].(string)
        if addr == "" {
                return ""
        }
        if name != "" {
                return headerFrom + name + " <" + addr + ">"
        }
        return headerFrom + addr
}

func extractHeaderArray(arr []interface{}, nameKey, valueKey string) []string {
        var lines []string
        for _, item := range arr {
                header, ok := item.(map[string]interface{})
                if !ok {
                        continue
                }
                name, _ := header[nameKey].(string)
                value, _ := header[valueKey].(string)
                if name != "" {
                        lines = append(lines, name+": "+value)
                }
        }
        return lines
}

func prependMissingHeader(lines []string, prefix string, valueFn func() string) []string {
        for _, l := range lines {
                if strings.HasPrefix(strings.ToLower(l), prefix) {
                        return lines
                }
        }
        if val := valueFn(); val != "" {
                lines = append([]string{val}, lines...)
        }
        return lines
}

func extractGmailAPIHeaders(obj map[string]interface{}) string {
        payload, ok := obj["payload"].(map[string]interface{})
        if !ok {
                return ""
        }
        headersRaw, ok := payload["headers"].([]interface{})
        if !ok {
                return ""
        }
        var lines []string
        for _, item := range headersRaw {
                header, ok := item.(map[string]interface{})
                if !ok {
                        continue
                }
                name, _ := header[jsonKeyName].(string)
                value, _ := header[jsonKeyValue].(string)
                if name != "" {
                        lines = append(lines, name+": "+value)
                }
        }
        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func extractPostmarkHeaders(obj map[string]interface{}) string {
        _, hasMessageID := obj["MessageID"]
        headersRaw, hasHeaders := obj[jsonKeyHeadersUC]
        if !hasMessageID || !hasHeaders {
                return ""
        }
        arr, ok := headersRaw.([]interface{})
        if !ok {
                return ""
        }
        lines := extractHeaderArray(arr, "Name", "Value")
        lines = appendPostmarkTopLevelFields(lines, obj)

        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func appendPostmarkTopLevelFields(lines []string, obj map[string]interface{}) []string {
        if from, ok := obj["From"].(string); ok && from != "" {
                lines = append([]string{headerFrom + from}, lines...)
        }
        if to, ok := obj["To"].(string); ok && to != "" {
                lines = append(lines, "To: "+to)
        }
        if subject, ok := obj["Subject"].(string); ok && subject != "" {
                lines = append(lines, headerSubject+subject)
        }
        if msgID, ok := obj["MessageID"].(string); ok && msgID != "" {
                lines = append(lines, "Message-ID: "+msgID)
        }
        return lines
}

func extractSendGridHeaders(obj map[string]interface{}) string {
        headersRaw, ok := obj[jsonKeyHeaders]
        if !ok {
                return ""
        }
        headersMap, ok := headersRaw.(map[string]interface{})
        if !ok {
                return ""
        }
        var lines []string
        for name, val := range headersMap {
                value, _ := val.(string)
                lines = append(lines, name+": "+value)
        }

        if from, ok := obj["from"].(map[string]interface{}); ok {
                email, _ := from["email"].(string)
                name, _ := from[jsonKeyName].(string)
                if email != "" {
                        if name != "" {
                                lines = append([]string{headerFrom + name + " <" + email + ">"}, lines...)
                        } else {
                                lines = append([]string{headerFrom + email}, lines...)
                        }
                }
        }
        if subject, ok := obj["subject"].(string); ok && subject != "" {
                lines = append(lines, headerSubject+subject)
        }

        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func extractMailgunHeaders(obj map[string]interface{}) string {
        msgHeaders, ok := obj["message-headers"]
        if !ok {
                return ""
        }
        arr, ok := msgHeaders.([]interface{})
        if !ok {
                return ""
        }
        var lines []string
        for _, item := range arr {
                pair, ok := item.([]interface{})
                if !ok || len(pair) < 2 {
                        continue
                }
                name, _ := pair[0].(string)
                value, _ := pair[1].(string)
                if name != "" {
                        lines = append(lines, name+": "+value)
                }
        }
        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func extractGenericJSONHeaders(obj map[string]interface{}) string {
        for _, key := range []string{jsonKeyHeaders, jsonKeyHeadersUC, "email_headers", "emailHeaders", "message_headers", "raw_headers", formatRaw + "Headers"} {
                val, ok := obj[key]
                if !ok {
                        continue
                }

                if result := tryExtractGenericVal(val); result != "" {
                        return result
                }
        }

        for _, key := range []string{formatRaw, "Raw"} {
                if raw, ok := obj[key].(string); ok && hasHeaderFields(raw) {
                        return raw
                }
        }

        return ""
}

func tryExtractGenericVal(val interface{}) string {
        if str, ok := val.(string); ok && hasHeaderFields(str) {
                return str
        }
        if arr, ok := val.([]interface{}); ok {
                if result := tryExtractFromHeaderArray(arr); result != "" {
                        return result
                }
        }
        if headerMap, ok := val.(map[string]interface{}); ok {
                if result := tryExtractFromHeaderMap(headerMap); result != "" {
                        return result
                }
        }
        return ""
}

func tryExtractFromHeaderArray(arr []interface{}) string {
        var lines []string
        for _, item := range arr {
                header, ok := item.(map[string]interface{})
                if !ok {
                        continue
                }
                name := firstString(header, jsonKeyName, "Name", "key", "Key", "header")
                value := firstString(header, jsonKeyValue, "Value", "val")
                if name != "" {
                        lines = append(lines, name+": "+value)
                }
        }
        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func tryExtractFromHeaderMap(headerMap map[string]interface{}) string {
        var lines []string
        for name, v := range headerMap {
                value, _ := v.(string)
                lines = append(lines, name+": "+value)
        }
        if len(lines) >= 2 {
                return strings.Join(lines, headerSep)
        }
        return ""
}

func firstString(m map[string]interface{}, keys ...string) string {
        for _, k := range keys {
                if v, ok := m[k].(string); ok {
                        return v
                }
        }
        return ""
}

func isMboxFormat(data string) bool {
        lines := strings.SplitN(data, "\n", 5)
        if len(lines) < 2 {
                return false
        }
        if firstLine := lines[0]; !strings.HasPrefix(firstLine, "From ") {
                return false
        }
        for _, line := range lines[1:] {
                if hasHeaderFields(line) {
                        return true
                }
        }
        return false
}

func extractFromMbox(data string) *DetectedFormat {
        lines := strings.SplitN(data, "\n", 2)
        if len(lines) < 2 {
                return &DetectedFormat{Format: "mbox", Error: "MBOX file appears empty."}
        }
        remainder := lines[1]

        if nextMsg := strings.Index(remainder, "\nFrom "); nextMsg > 0 {
                remainder = remainder[:nextMsg]
        }

        return &DetectedFormat{
                Format:  "mbox",
                Headers: strings.TrimSpace(remainder),
        }
}
