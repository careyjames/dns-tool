package analyzer

import (
	"strings"
	"testing"
)

func TestDetectAndExtractHeaders_RawText(t *testing.T) {
	raw := "From: test@example.com\r\nTo: user@example.com\r\nSubject: Hello"
	result := DetectAndExtractHeaders(raw, "test.eml")
	if result.Format != "raw" {
		t.Errorf("expected format 'raw', got %q", result.Format)
	}
	if result.Headers != raw {
		t.Errorf("expected headers to match input")
	}
	if result.Error != "" {
		t.Errorf("expected no error, got %q", result.Error)
	}
}

func TestDetectAndExtractHeaders_BinaryMsg(t *testing.T) {
	data := make([]byte, 100)
	for i := 0; i < 10; i++ {
		data[i] = 0
	}
	result := DetectAndExtractHeaders(string(data), "test.msg")
	if result.Format != "msg" {
		t.Errorf("expected format 'msg', got %q", result.Format)
	}
	if result.Error == "" {
		t.Error("expected error message for .msg file")
	}
}

func TestDetectAndExtractHeaders_BinaryGeneric(t *testing.T) {
	data := make([]byte, 100)
	for i := 0; i < 10; i++ {
		data[i] = 0
	}
	result := DetectAndExtractHeaders(string(data), "test.bin")
	if result.Format != "binary" {
		t.Errorf("expected format 'binary', got %q", result.Format)
	}
}

func TestIsBinaryContent(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		expect bool
	}{
		{"short string", "hello", false},
		{"normal text", "This is a normal email header with no null bytes at all and it is long enough", false},
		{"many nulls", string(make([]byte, 20)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isBinaryContent(tt.data)
			if got != tt.expect {
				t.Errorf("isBinaryContent(%q) = %v, want %v", tt.name, got, tt.expect)
			}
		})
	}
}

func TestHandleBinaryFile(t *testing.T) {
	tests := []struct {
		filename string
		format   string
	}{
		{"email.msg", "msg"},
		{"EMAIL.MSG", "msg"},
		{"file.bin", "binary"},
		{"document.pdf", "binary"},
	}
	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			result := handleBinaryFile(tt.filename)
			if result.Format != tt.format {
				t.Errorf("handleBinaryFile(%q) format = %q, want %q", tt.filename, result.Format, tt.format)
			}
			if result.Error == "" {
				t.Error("expected an error message")
			}
		})
	}
}

func TestTryExtractFromJSON_InvalidJSON(t *testing.T) {
	result := tryExtractFromJSON("not json at all")
	if result.Format != "raw" {
		t.Errorf("expected format 'raw', got %q", result.Format)
	}
}

func TestTryExtractFromJSON_ValidButNoHeaders(t *testing.T) {
	result := tryExtractFromJSON(`{"foo": "bar"}`)
	if result.Format != "json" {
		t.Errorf("expected format 'json', got %q", result.Format)
	}
	if result.Error == "" {
		t.Error("expected error message for unrecognized JSON")
	}
}

func TestUnmarshalJSONObject_Object(t *testing.T) {
	obj := unmarshalJSONObject(`{"key": "value"}`)
	if obj == nil {
		t.Fatal("expected non-nil object")
	}
	if obj["key"] != "value" {
		t.Errorf("expected key=value, got %v", obj["key"])
	}
}

func TestUnmarshalJSONObject_Array(t *testing.T) {
	obj := unmarshalJSONObject(`[{"key": "value"}, {"key2": "value2"}]`)
	if obj == nil {
		t.Fatal("expected non-nil object from first array element")
	}
	if obj["key"] != "value" {
		t.Errorf("expected key=value")
	}
}

func TestUnmarshalJSONObject_EmptyArray(t *testing.T) {
	obj := unmarshalJSONObject(`[]`)
	if obj != nil {
		t.Error("expected nil for empty array")
	}
}

func TestUnmarshalJSONObject_Invalid(t *testing.T) {
	obj := unmarshalJSONObject(`not json`)
	if obj != nil {
		t.Error("expected nil for invalid JSON")
	}
}

func TestExtractMicrosoftGraphHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"subject": "Test Subject",
		"from": map[string]interface{}{
			"emailAddress": map[string]interface{}{
				"name":    "John Doe",
				"address": "john@example.com",
			},
		},
		"internetMessageHeaders": []interface{}{
			map[string]interface{}{"name": "X-Custom", "value": "custom-val"},
			map[string]interface{}{"name": "X-Another", "value": "another-val"},
		},
	}
	result := extractMicrosoftGraphHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	if !strings.Contains(result, "Subject: Test Subject") {
		t.Error("expected Subject header")
	}
	if !strings.Contains(result, "From: John Doe <john@example.com>") {
		t.Error("expected From header")
	}
}

func TestExtractMicrosoftGraphHeaders_NoHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"subject": "Test",
	}
	result := extractMicrosoftGraphHeaders(obj)
	if result != "" {
		t.Error("expected empty result when no internetMessageHeaders")
	}
}

func TestExtractMSGraphFrom(t *testing.T) {
	tests := []struct {
		name   string
		obj    map[string]interface{}
		expect string
	}{
		{
			"with name and address",
			map[string]interface{}{
				"from": map[string]interface{}{
					"emailAddress": map[string]interface{}{
						"name":    "Jane",
						"address": "jane@example.com",
					},
				},
			},
			"From: Jane <jane@example.com>",
		},
		{
			"address only",
			map[string]interface{}{
				"from": map[string]interface{}{
					"emailAddress": map[string]interface{}{
						"address": "jane@example.com",
					},
				},
			},
			"From: jane@example.com",
		},
		{
			"no from key",
			map[string]interface{}{},
			"",
		},
		{
			"no emailAddress",
			map[string]interface{}{
				"from": map[string]interface{}{},
			},
			"",
		},
		{
			"empty address",
			map[string]interface{}{
				"from": map[string]interface{}{
					"emailAddress": map[string]interface{}{
						"name":    "Jane",
						"address": "",
					},
				},
			},
			"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMSGraphFrom(tt.obj)
			if got != tt.expect {
				t.Errorf("extractMSGraphFrom() = %q, want %q", got, tt.expect)
			}
		})
	}
}

func TestExtractHeaderArray(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "From", "value": "test@example.com"},
		map[string]interface{}{"name": "To", "value": "user@example.com"},
		"not a map",
		map[string]interface{}{"name": "", "value": "no-name"},
	}
	lines := extractHeaderArray(arr, "name", "value")
	if len(lines) != 2 {
		t.Errorf("expected 2 lines, got %d", len(lines))
	}
}

func TestPrependMissingHeader(t *testing.T) {
	lines := []string{"To: user@example.com"}
	result := prependMissingHeader(lines, "from:", func() string {
		return "From: test@example.com"
	})
	if len(result) != 2 {
		t.Errorf("expected 2 lines after prepend, got %d", len(result))
	}
	if result[0] != "From: test@example.com" {
		t.Error("expected From header to be prepended")
	}
}

func TestPrependMissingHeader_AlreadyExists(t *testing.T) {
	lines := []string{"From: existing@example.com", "To: user@example.com"}
	result := prependMissingHeader(lines, "from:", func() string {
		return "From: new@example.com"
	})
	if len(result) != 2 {
		t.Errorf("expected 2 lines (no change), got %d", len(result))
	}
}

func TestPrependMissingHeader_EmptyValue(t *testing.T) {
	lines := []string{"To: user@example.com"}
	result := prependMissingHeader(lines, "from:", func() string {
		return ""
	})
	if len(result) != 1 {
		t.Errorf("expected 1 line (no prepend when empty), got %d", len(result))
	}
}

func TestExtractGmailAPIHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"payload": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "From", "value": "sender@gmail.com"},
				map[string]interface{}{"name": "To", "value": "recipient@gmail.com"},
				map[string]interface{}{"name": "Subject", "value": "Test"},
			},
		},
	}
	result := extractGmailAPIHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result for Gmail API format")
	}
	if !strings.Contains(result, "From: sender@gmail.com") {
		t.Error("expected From header")
	}
}

func TestExtractGmailAPIHeaders_NoPayload(t *testing.T) {
	result := extractGmailAPIHeaders(map[string]interface{}{})
	if result != "" {
		t.Error("expected empty for missing payload")
	}
}

func TestExtractGmailAPIHeaders_NoHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"payload": map[string]interface{}{},
	}
	result := extractGmailAPIHeaders(obj)
	if result != "" {
		t.Error("expected empty for missing headers")
	}
}

func TestExtractPostmarkHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"MessageID": "msg-123",
		"From":      "sender@postmark.com",
		"To":        "recipient@example.com",
		"Subject":   "Test",
		"Headers": []interface{}{
			map[string]interface{}{"Name": "X-Custom", "Value": "val1"},
			map[string]interface{}{"Name": "X-Other", "Value": "val2"},
		},
	}
	result := extractPostmarkHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result for Postmark format")
	}
}

func TestExtractPostmarkHeaders_MissingMessageID(t *testing.T) {
	obj := map[string]interface{}{
		"Headers": []interface{}{},
	}
	result := extractPostmarkHeaders(obj)
	if result != "" {
		t.Error("expected empty when MessageID missing")
	}
}

func TestExtractSendGridHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"headers": map[string]interface{}{
			"X-Custom": "val1",
			"X-Other":  "val2",
		},
		"from": map[string]interface{}{
			"email": "sender@sendgrid.com",
			"name":  "Sender Name",
		},
		"subject": "Test Subject",
	}
	result := extractSendGridHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result for SendGrid format")
	}
}

func TestExtractSendGridHeaders_NoHeaders(t *testing.T) {
	result := extractSendGridHeaders(map[string]interface{}{})
	if result != "" {
		t.Error("expected empty when no headers key")
	}
}

func TestExtractSendGridHeaders_FromWithoutName(t *testing.T) {
	obj := map[string]interface{}{
		"headers": map[string]interface{}{
			"X-Custom": "val1",
			"X-Other":  "val2",
		},
		"from": map[string]interface{}{
			"email": "sender@sendgrid.com",
		},
		"subject": "Test Subject",
	}
	result := extractSendGridHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	if !strings.Contains(result, "From: sender@sendgrid.com") {
		t.Error("expected From header without name")
	}
}

func TestExtractMailgunHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"message-headers": []interface{}{
			[]interface{}{"From", "sender@mailgun.com"},
			[]interface{}{"To", "recipient@example.com"},
			[]interface{}{"Subject", "Test"},
		},
	}
	result := extractMailgunHeaders(obj)
	if result == "" {
		t.Fatal("expected non-empty result for Mailgun format")
	}
}

func TestExtractMailgunHeaders_NoMessageHeaders(t *testing.T) {
	result := extractMailgunHeaders(map[string]interface{}{})
	if result != "" {
		t.Error("expected empty when no message-headers")
	}
}

func TestExtractMailgunHeaders_ShortPairs(t *testing.T) {
	obj := map[string]interface{}{
		"message-headers": []interface{}{
			[]interface{}{"Only-One"},
			"not-an-array",
		},
	}
	result := extractMailgunHeaders(obj)
	if result != "" {
		t.Error("expected empty for invalid pairs")
	}
}

func TestExtractGenericJSONHeaders_StringHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"headers": "From: test@example.com\nTo: user@example.com\nSubject: Test",
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for string headers")
	}
}

func TestExtractGenericJSONHeaders_RawKey(t *testing.T) {
	obj := map[string]interface{}{
		"raw": "From: test@example.com\nTo: user@example.com\nSubject: Test",
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for raw key")
	}
}

func TestExtractGenericJSONHeaders_MapHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"headers": map[string]interface{}{
			"From": "test@example.com",
			"To":   "user@example.com",
		},
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for map headers")
	}
}

func TestExtractGenericJSONHeaders_ArrayHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"headers": []interface{}{
			map[string]interface{}{"name": "From", "value": "test@example.com"},
			map[string]interface{}{"name": "To", "value": "user@example.com"},
		},
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for array headers")
	}
}

func TestFirstString(t *testing.T) {
	m := map[string]interface{}{
		"name":  "test",
		"value": "val",
	}
	if got := firstString(m, "missing", "name"); got != "test" {
		t.Errorf("expected 'test', got %q", got)
	}
	if got := firstString(m, "missing1", "missing2"); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestIsMboxFormat(t *testing.T) {
	tests := []struct {
		name   string
		data   string
		expect bool
	}{
		{"valid mbox", "From sender@example.com Mon Jan  1 00:00:00 2024\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: test\nDate: Mon, 1 Jan 2024\nMessage-ID: <1@example.com>", true},
		{"not mbox", "Subject: Hello\nFrom: test@example.com", false},
		{"single line", "From sender@example.com", false},
		{"no header fields after From line", "From sender@example.com Mon Jan 1\nThis is just text", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isMboxFormat(tt.data)
			if got != tt.expect {
				t.Errorf("isMboxFormat() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestExtractFromMbox(t *testing.T) {
	data := "From sender@example.com Mon Jan 1 00:00:00 2024\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test"
	result := extractFromMbox(data)
	if result.Format != "mbox" {
		t.Errorf("expected format 'mbox', got %q", result.Format)
	}
	if result.Headers == "" {
		t.Error("expected non-empty headers")
	}
}

func TestExtractFromMbox_Empty(t *testing.T) {
	result := extractFromMbox("From sender@example.com")
	if result.Format != "mbox" {
		t.Errorf("expected format 'mbox', got %q", result.Format)
	}
	if result.Error == "" {
		t.Error("expected error for empty mbox")
	}
}

func TestExtractFromMbox_MultipleMessages(t *testing.T) {
	data := "From sender1@example.com Mon Jan 1 00:00:00 2024\nFrom: sender1@example.com\nSubject: First\n\nBody 1\n\nFrom sender2@example.com Mon Jan 2 00:00:00 2024\nFrom: sender2@example.com\nSubject: Second"
	result := extractFromMbox(data)
	if result.Format != "mbox" {
		t.Errorf("expected format 'mbox', got %q", result.Format)
	}
	if strings.Contains(result.Headers, "sender2") {
		t.Error("expected only first message headers")
	}
}

func TestDetectAndExtractHeaders_JSONObject(t *testing.T) {
	raw := `{"payload":{"headers":[{"name":"From","value":"a@b.com"},{"name":"To","value":"c@d.com"},{"name":"Subject","value":"Hi"}]}}`
	result := DetectAndExtractHeaders(raw, "test.json")
	if result.Format != "json-gmail-api" {
		t.Errorf("expected json-gmail-api, got %q", result.Format)
	}
}

func TestDetectAndExtractHeaders_JSONArray(t *testing.T) {
	raw := `[{"payload":{"headers":[{"name":"From","value":"a@b.com"},{"name":"To","value":"c@d.com"},{"name":"Subject","value":"Hi"}]}}]`
	result := DetectAndExtractHeaders(raw, "test.json")
	if result.Format != "json-gmail-api" {
		t.Errorf("expected json-gmail-api, got %q", result.Format)
	}
}

func TestDetectAndExtractHeaders_MboxFormat(t *testing.T) {
	raw := "From sender@example.com Mon Jan  1 00:00:00 2024\nFrom: sender@example.com\nTo: recipient@example.com\nSubject: Test\nDate: Mon, 1 Jan 2024\nMessage-ID: <1@example.com>"
	result := DetectAndExtractHeaders(raw, "mailbox.mbox")
	if result.Format != "mbox" {
		t.Errorf("expected format 'mbox', got %q", result.Format)
	}
}

func TestAppendPostmarkTopLevelFields(t *testing.T) {
	obj := map[string]interface{}{
		"From":      "sender@postmark.com",
		"To":        "recipient@example.com",
		"Subject":   "Test Subject",
		"MessageID": "msg-123",
	}
	lines := appendPostmarkTopLevelFields(nil, obj)
	if len(lines) != 4 {
		t.Errorf("expected 4 lines, got %d", len(lines))
	}
}

func TestTryExtractFromHeaderArray_SingleItem(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "From", "value": "test@example.com"},
	}
	result := tryExtractFromHeaderArray(arr)
	if result != "" {
		t.Error("expected empty for single header (need >= 2)")
	}
}

func TestTryExtractFromHeaderMap_SingleItem(t *testing.T) {
	m := map[string]interface{}{
		"From": "test@example.com",
	}
	result := tryExtractFromHeaderMap(m)
	if result != "" {
		t.Error("expected empty for single header (need >= 2)")
	}
}

func TestTryExtractGenericVal_String(t *testing.T) {
	result := tryExtractGenericVal("From: test@example.com\nTo: user@example.com")
	if result == "" {
		t.Error("expected non-empty for valid header string")
	}
}

func TestTryExtractGenericVal_StringNoHeaders(t *testing.T) {
	result := tryExtractGenericVal("just plain text")
	if result != "" {
		t.Error("expected empty for non-header string")
	}
}

func TestTryExtractGenericVal_Array(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "From", "value": "a@b.com"},
		map[string]interface{}{"name": "To", "value": "c@d.com"},
	}
	result := tryExtractGenericVal(arr)
	if result == "" {
		t.Error("expected non-empty for valid header array")
	}
}

func TestTryExtractGenericVal_Map(t *testing.T) {
	m := map[string]interface{}{
		"From": "a@b.com",
		"To":   "c@d.com",
	}
	result := tryExtractGenericVal(m)
	if result == "" {
		t.Error("expected non-empty for valid header map")
	}
}

func TestTryExtractGenericVal_NonHeaderType(t *testing.T) {
	result := tryExtractGenericVal(42)
	if result != "" {
		t.Error("expected empty for non-string/array/map type")
	}
}

func TestMatchJSONProvider_MicrosoftGraph(t *testing.T) {
	obj := map[string]interface{}{
		"internetMessageHeaders": []interface{}{
			map[string]interface{}{"name": "X-A", "value": "1"},
			map[string]interface{}{"name": "X-B", "value": "2"},
		},
	}
	result := matchJSONProvider(obj)
	if result.Format != "json-microsoft-graph" {
		t.Errorf("expected json-microsoft-graph, got %q", result.Format)
	}
}

func TestMatchJSONProvider_Unrecognized(t *testing.T) {
	obj := map[string]interface{}{
		"randomKey": "randomValue",
	}
	result := matchJSONProvider(obj)
	if result.Format != "json" {
		t.Errorf("expected json, got %q", result.Format)
	}
	if result.Error == "" {
		t.Error("expected error message for unrecognized JSON")
	}
}

func TestDetectAndExtractHeaders_WhitespaceOnly(t *testing.T) {
	result := DetectAndExtractHeaders("   \n\t  ", "test.eml")
	if result.Format != "raw" {
		t.Errorf("expected format 'raw', got %q", result.Format)
	}
}

func TestExtractSendGridHeaders_HeadersNotMap(t *testing.T) {
	obj := map[string]interface{}{
		"headers": "not-a-map",
	}
	result := extractSendGridHeaders(obj)
	if result != "" {
		t.Error("expected empty when headers is not a map")
	}
}

func TestExtractMicrosoftGraphHeaders_NotArray(t *testing.T) {
	obj := map[string]interface{}{
		"internetMessageHeaders": "not-an-array",
	}
	result := extractMicrosoftGraphHeaders(obj)
	if result != "" {
		t.Error("expected empty when internetMessageHeaders is not an array")
	}
}

func TestExtractPostmarkHeaders_HeadersNotArray(t *testing.T) {
	obj := map[string]interface{}{
		"MessageID": "msg-123",
		"Headers":   "not-an-array",
	}
	result := extractPostmarkHeaders(obj)
	if result != "" {
		t.Error("expected empty when Headers is not an array")
	}
}

func TestExtractMailgunHeaders_NotArray(t *testing.T) {
	obj := map[string]interface{}{
		"message-headers": "not-an-array",
	}
	result := extractMailgunHeaders(obj)
	if result != "" {
		t.Error("expected empty when message-headers is not an array")
	}
}

func TestExtractGenericJSONHeaders_EmailHeaders(t *testing.T) {
	obj := map[string]interface{}{
		"email_headers": "From: test@example.com\nTo: user@example.com\nSubject: Test",
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for email_headers key")
	}
}

func TestExtractGenericJSONHeaders_NoMatch(t *testing.T) {
	obj := map[string]interface{}{
		"unrelated_key": "unrelated_value",
	}
	result := extractGenericJSONHeaders(obj)
	if result != "" {
		t.Error("expected empty when no matching keys")
	}
}

func TestExtractGmailAPIHeaders_SingleHeader(t *testing.T) {
	obj := map[string]interface{}{
		"payload": map[string]interface{}{
			"headers": []interface{}{
				map[string]interface{}{"name": "From", "value": "sender@gmail.com"},
			},
		},
	}
	result := extractGmailAPIHeaders(obj)
	if result != "" {
		t.Error("expected empty for single header (need >= 2)")
	}
}

func TestExtractMailgunHeaders_SinglePair(t *testing.T) {
	obj := map[string]interface{}{
		"message-headers": []interface{}{
			[]interface{}{"From", "sender@mailgun.com"},
		},
	}
	result := extractMailgunHeaders(obj)
	if result != "" {
		t.Error("expected empty for single pair (need >= 2)")
	}
}

func TestUnmarshalJSONObject_ArrayOfNonObjects(t *testing.T) {
	obj := unmarshalJSONObject(`["string1", "string2"]`)
	if obj != nil {
		t.Error("expected nil for array of non-objects")
	}
}

func TestExtractMicrosoftGraphHeaders_SubjectPrepended(t *testing.T) {
	obj := map[string]interface{}{
		"subject": "Test Subject",
		"internetMessageHeaders": []interface{}{
			map[string]interface{}{"name": "X-Custom", "value": "val"},
		},
	}
	result := extractMicrosoftGraphHeaders(obj)
	if result == "" {
		t.Error("expected non-empty when subject is prepended to single header (total >= 2)")
	}
	if !strings.Contains(result, "Subject: Test Subject") {
		t.Error("expected Subject header to be prepended")
	}
}

func TestIsBinaryContent_ExactThreshold(t *testing.T) {
	data := make([]byte, 100)
	for i := range data {
		data[i] = 'A'
	}
	for i := 0; i < 4; i++ {
		data[i] = 0
	}
	got := isBinaryContent(string(data))
	if got {
		t.Error("expected false with exactly 4 null bytes (need > 4)")
	}

	data[4] = 0
	got = isBinaryContent(string(data))
	if !got {
		t.Error("expected true with 5 null bytes")
	}
}

func TestExtractPostmarkHeaders_WithMessageIDField(t *testing.T) {
	obj := map[string]interface{}{
		"MessageID": "msg-123",
		"Headers": []interface{}{
			map[string]interface{}{"Name": "X-Custom", "Value": "val1"},
		},
	}
	result := extractPostmarkHeaders(obj)
	if result == "" {
		t.Error("expected non-empty when MessageID is appended to header list")
	}
}

func TestExtractSendGridHeaders_SingleLine(t *testing.T) {
	obj := map[string]interface{}{
		"headers": map[string]interface{}{
			"X-Custom": "val1",
		},
	}
	result := extractSendGridHeaders(obj)
	if result != "" {
		t.Error("expected empty when total lines < 2")
	}
}

func TestExtractGenericJSONHeaders_RawUppercase(t *testing.T) {
	obj := map[string]interface{}{
		"Raw": "From: test@example.com\nTo: user@example.com\nSubject: Test",
	}
	result := extractGenericJSONHeaders(obj)
	if result == "" {
		t.Error("expected non-empty result for Raw key")
	}
}

func TestTryExtractFromHeaderArray_NonMapItems(t *testing.T) {
	arr := []interface{}{
		"not-a-map",
		42,
	}
	result := tryExtractFromHeaderArray(arr)
	if result != "" {
		t.Error("expected empty for non-map array items")
	}
}

func TestExtractHeaderArray_EmptyNames(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"name": "", "value": "val1"},
		map[string]interface{}{"name": "", "value": "val2"},
	}
	lines := extractHeaderArray(arr, "name", "value")
	if len(lines) != 0 {
		t.Errorf("expected 0 lines for empty names, got %d", len(lines))
	}
}
