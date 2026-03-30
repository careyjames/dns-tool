package templates

import (
        "html/template"
        "strings"
        "testing"
        "time"
)

func TestSafeEqCrossTypeNumeric(t *testing.T) {
        tests := []struct {
                name string
                a    interface{}
                b    interface{}
                want bool
        }{
                {"float64 vs int zero", float64(0), int(0), true},
                {"int vs float64 zero", int(0), float64(0), true},
                {"float64(2) vs int(2)", float64(2), int(2), true},
                {"float64(3) vs int(3)", float64(3), int(3), true},
                {"float64(2048) vs int(2048)", float64(2048), int(2048), true},
                {"float64(1) vs int(0)", float64(1), int(0), false},
                {"int(5) vs float64(10)", int(5), float64(10), false},
                {"float64(0) vs int(1)", float64(0), int(1), false},
                {"int32 vs float64", int32(42), float64(42), true},
                {"int64 vs float64", int64(100), float64(100), true},
                {"float32 vs int", float32(7), int(7), true},
                {"uint vs float64", uint(255), float64(255), true},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := safeEq(tt.a, tt.b)
                        if got != tt.want {
                                t.Errorf("safeEq(%v [%T], %v [%T]) = %v, want %v",
                                        tt.a, tt.a, tt.b, tt.b, got, tt.want)
                        }
                })
        }
}

func TestSafeEqVariadic(t *testing.T) {
        if !safeEq(float64(2), int(1), int(2), int(3)) {
                t.Error("safeEq(2.0, 1, 2, 3) should be true (matches 2)")
        }
        if safeEq(float64(5), int(1), int(2), int(3)) {
                t.Error("safeEq(5.0, 1, 2, 3) should be false (no match)")
        }
        if !safeEq("hello", "world", "hello") {
                t.Error("safeEq('hello', 'world', 'hello') should be true")
        }
}

func TestSafeEqStrings(t *testing.T) {
        tests := []struct {
                name string
                a, b interface{}
                want bool
        }{
                {"equal strings", "success", "success", true},
                {"different strings", "success", "error", false},
                {"empty strings", "", "", true},
                {"empty vs non-empty", "", "hello", false},
        }
        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        got := safeEq(tt.a, tt.b)
                        if got != tt.want {
                                t.Errorf("safeEq(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
                        }
                })
        }
}

func TestSafeEqNil(t *testing.T) {
        if !safeEq(nil, nil) {
                t.Error("safeEq(nil, nil) should be true")
        }
        if safeEq(nil, int(0)) {
                t.Error("safeEq(nil, 0) should be false")
        }
        if safeEq("hello", nil) {
                t.Error("safeEq('hello', nil) should be false")
        }
}

func TestSafeNeCrossTypeNumeric(t *testing.T) {
        if safeNe(float64(0), int(0)) {
                t.Error("safeNe(0.0, 0) should be false")
        }
        if !safeNe(float64(1), int(0)) {
                t.Error("safeNe(1.0, 0) should be true")
        }
        if safeNe(float64(2048), int(2048)) {
                t.Error("safeNe(2048.0, 2048) should be false")
        }
}

func TestGtCmpCrossType(t *testing.T) {
        if !gtCmp(float64(10), int(5)) {
                t.Error("gtCmp(10.0, 5) should be true")
        }
        if gtCmp(float64(0), int(0)) {
                t.Error("gtCmp(0.0, 0) should be false")
        }
        if gtCmp(int(3), float64(5)) {
                t.Error("gtCmp(3, 5.0) should be false")
        }
}

func TestLtCmpCrossType(t *testing.T) {
        if !ltCmp(int(5), float64(10)) {
                t.Error("ltCmp(5, 10.0) should be true")
        }
        if ltCmp(float64(10), int(5)) {
                t.Error("ltCmp(10.0, 5) should be false")
        }
}

func TestGeCmpCrossType(t *testing.T) {
        if !geCmp(float64(10), int(10)) {
                t.Error("geCmp(10.0, 10) should be true")
        }
        if !geCmp(float64(11), int(10)) {
                t.Error("geCmp(11.0, 10) should be true")
        }
        if geCmp(float64(9), int(10)) {
                t.Error("geCmp(9.0, 10) should be false")
        }
}

func TestLeCmpCrossType(t *testing.T) {
        if !leCmp(float64(10), int(10)) {
                t.Error("leCmp(10.0, 10) should be true")
        }
        if !leCmp(float64(9), int(10)) {
                t.Error("leCmp(9.0, 10) should be true")
        }
        if leCmp(float64(11), int(10)) {
                t.Error("leCmp(11.0, 10) should be false")
        }
}

func TestTemplateRenderMixedTypes(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .floatVal 0}}ZERO{{else}}NONZERO{{end}}|` +
                        `{{if ne .floatVal 1}}NOT_ONE{{else}}IS_ONE{{end}}|` +
                        `{{if gt .floatVal 5}}GT5{{else}}LTE5{{end}}|` +
                        `{{if lt .intVal 100.0}}LT100{{else}}GTE100{{end}}`,
        ))

        tests := []struct {
                name     string
                data     map[string]interface{}
                expected string
        }{
                {
                        "float64 zero vs int literals",
                        map[string]interface{}{"floatVal": float64(0), "intVal": int(50)},
                        "ZERO|NOT_ONE|LTE5|LT100",
                },
                {
                        "float64 nonzero vs int literals",
                        map[string]interface{}{"floatVal": float64(10), "intVal": int(200)},
                        "NONZERO|NOT_ONE|GT5|GTE100",
                },
                {
                        "float64 one vs int literals",
                        map[string]interface{}{"floatVal": float64(1), "intVal": int(99)},
                        "NONZERO|IS_ONE|LTE5|LT100",
                },
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, tt.data)
                        if err != nil {
                                t.Fatalf("template execution failed: %v", err)
                        }
                        if buf.String() != tt.expected {
                                t.Errorf("got %q, want %q", buf.String(), tt.expected)
                        }
                })
        }
}

func TestTemplateRenderVariadicEq(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .val 2 3}}MATCH{{else}}NO_MATCH{{end}}`,
        ))

        tests := []struct {
                name     string
                val      interface{}
                expected string
        }{
                {"float64(2) matches int 2", float64(2), "MATCH"},
                {"float64(3) matches int 3", float64(3), "MATCH"},
                {"float64(1) no match", float64(1), "NO_MATCH"},
                {"int(2) matches", int(2), "MATCH"},
        }

        for _, tt := range tests {
                t.Run(tt.name, func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, map[string]interface{}{"val": tt.val})
                        if err != nil {
                                t.Fatalf("template execution failed: %v", err)
                        }
                        if buf.String() != tt.expected {
                                t.Errorf("got %q, want %q", buf.String(), tt.expected)
                        }
                })
        }
}

func TestTemplateRenderNoPanic(t *testing.T) {
        tmpl := template.Must(template.New("test").Funcs(FuncMap()).Parse(
                `{{if eq .f 0}}Z{{end}}{{if ne .f 1}}N{{end}}` +
                        `{{if gt .f 0}}G{{end}}{{if lt .f 100}}L{{end}}` +
                        `{{if ge .f 0}}GE{{end}}{{if le .f 100}}LE{{end}}`,
        ))

        vals := []interface{}{
                float64(0), float64(50), float64(100),
                int(0), int(50), int(100),
                int32(0), int64(50), float32(100),
                uint(0), uint(50),
        }

        for _, v := range vals {
                t.Run("", func(t *testing.T) {
                        var buf strings.Builder
                        err := tmpl.Execute(&buf, map[string]interface{}{"f": v})
                        if err != nil {
                                t.Fatalf("template panicked with %T(%v): %v", v, v, err)
                        }
                })
        }
}

func TestToFloat64(t *testing.T) {
        tests := []struct {
                input interface{}
                want  float64
        }{
                {int(42), 42},
                {int32(42), 42},
                {int64(42), 42},
                {float32(42.5), 42.5},
                {float64(42.5), 42.5},
                {uint(42), 42},
                {"42", 42},
                {"3.14", 3.14},
                {"0", 0},
                {nil, 0},
                {"not a number", 0},
                {int8(10), 10},
                {int16(10), 10},
                {uint8(10), 10},
                {uint16(10), 10},
                {uint32(10), 10},
                {uint64(10), 10},
        }
        for _, tt := range tests {
                got := toFloat64(tt.input)
                if got != tt.want {
                        t.Errorf("toFloat64(%v [%T]) = %v, want %v", tt.input, tt.input, got, tt.want)
                }
        }
}

func TestFormatDate(t *testing.T) {
        ts := time.Date(2026, 2, 15, 14, 30, 0, 0, time.UTC)
        got := formatDate(ts)
        if got != "Feb 15, 2026 14:30 UTC" {
                t.Errorf("formatDate(time.Time) = %q, want %q", got, "Feb 15, 2026 14:30 UTC")
        }
        got = formatDate("already formatted")
        if got != "already formatted" {
                t.Errorf("formatDate(string) = %q, want %q", got, "already formatted")
        }
        got = formatDate(12345)
        if got != "12345" {
                t.Errorf("formatDate(int) = %q, want %q", got, "12345")
        }
}

func TestFormatDateShort(t *testing.T) {
        ts := time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)
        got := formatDateShort(ts)
        if got != "2026-02-15" {
                t.Errorf("formatDateShort = %q, want %q", got, "2026-02-15")
        }
        if formatDateShort(42) != "" {
                t.Error("formatDateShort(int) should return empty")
        }
}

func TestFormatTime(t *testing.T) {
        ts := time.Date(2026, 1, 1, 15, 4, 5, 0, time.UTC)
        got := formatTime(ts)
        if got != "15:04:05" {
                t.Errorf("formatTime = %q", got)
        }
}

func TestFormatDateTime(t *testing.T) {
        ts := time.Date(2026, 2, 15, 14, 30, 45, 0, time.UTC)
        got := formatDateTime(ts)
        if got != "2026-02-15 14:30:45" {
                t.Errorf("formatDateTime = %q", got)
        }
}

func TestFormatDateMonthDay(t *testing.T) {
        ts := time.Date(2026, 3, 5, 0, 0, 0, 0, time.UTC)
        got := formatDateMonthDay(ts)
        if got != "03/05" {
                t.Errorf("formatDateMonthDay = %q", got)
        }
}

func TestFormatDuration(t *testing.T) {
        tests := []struct {
                input interface{}
                want  string
        }{
                {float64(0.5), "500ms"},
                {float64(0.001), "1ms"},
                {float64(2.5), "2.5s"},
                {float64(1.0), "1.0s"},
                {float32(3.5), "3.5s"},
                {"unknown", "unknown"},
        }
        for _, tt := range tests {
                got := formatDuration(tt.input)
                if got != tt.want {
                        t.Errorf("formatDuration(%v) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestFormatFloat(t *testing.T) {
        tests := []struct {
                prec  int
                input interface{}
                want  string
        }{
                {2, float64(3.14159), "3.14"},
                {0, float64(3.7), "4"},
                {1, float32(2.55), "2.5"},
                {0, int(42), "42"},
                {2, int64(100), "100.00"},
                {2, "hello", "hello"},
        }
        for _, tt := range tests {
                got := formatFloat(tt.prec, tt.input)
                if got != tt.want {
                        t.Errorf("formatFloat(%d, %v) = %q, want %q", tt.prec, tt.input, got, tt.want)
                }
        }
}

func TestSuccessRate(t *testing.T) {
        tests := []struct {
                s, total interface{}
                want     string
        }{
                {80, 100, "80.0"},
                {0, 0, "0"},
                {1, 2, "50.0"},
                {float64(3), float64(4), "75.0"},
        }
        for _, tt := range tests {
                got := successRate(tt.s, tt.total)
                if got != tt.want {
                        t.Errorf("successRate(%v, %v) = %q, want %q", tt.s, tt.total, got, tt.want)
                }
        }
}

func TestPercent(t *testing.T) {
        got := percent(1, 4)
        if got != 25.0 {
                t.Errorf("percent(1,4) = %v, want 25.0", got)
        }
        if percent(0, 0) != 0 {
                t.Error("percent(0,0) should be 0")
        }
}

func TestArithmeticFuncs(t *testing.T) {
        if addInt(3, 4) != 7 {
                t.Error("addInt")
        }
        if subInt(10, 3) != 7 {
                t.Error("subInt")
        }
        if mulInt(3, 4) != 12 {
                t.Error("mulInt")
        }
        if maxInt(3, 7) != 7 {
                t.Error("maxInt")
        }
        if maxInt(7, 3) != 7 {
                t.Error("maxInt reverse")
        }
        if minInt(3, 7) != 3 {
                t.Error("minInt")
        }
        if minInt(7, 3) != 3 {
                t.Error("minInt reverse")
        }
        if divFloat(10, 4) != 2.5 {
                t.Error("divFloat")
        }
        if divFloat(10, 0) != 0 {
                t.Error("divFloat by zero")
        }
        if modInt(10, 3) != 1 {
                t.Error("modInt")
        }
        if modInt(10, 0) != 0 {
                t.Error("modInt by zero")
        }
}

func TestIntDiv(t *testing.T) {
        if intDiv(10, 3) != 3 {
                t.Error("intDiv(10,3)")
        }
        if intDiv(10, 0) != 0 {
                t.Error("intDiv by zero")
        }
        if intDiv(float64(9), int(3)) != 3 {
                t.Error("intDiv cross-type")
        }
}

func TestMaxIntIface(t *testing.T) {
        if maxIntIface(3, 7) != 7 {
                t.Error("maxIntIface(3,7)")
        }
        if maxIntIface(float64(10), int(5)) != 10 {
                t.Error("maxIntIface cross-type")
        }
}

func TestTruncateStr(t *testing.T) {
        if truncateStr(5, "hello world") != "hello..." {
                t.Errorf("truncateStr = %q", truncateStr(5, "hello world"))
        }
        if truncateStr(20, "short") != "short" {
                t.Error("truncateStr short string")
        }
}

func TestSubstrStr(t *testing.T) {
        if substrStr(0, 5, "hello world") != "hello" {
                t.Error("substrStr basic")
        }
        if substrStr(6, 5, "hello world") != "world" {
                t.Error("substrStr offset")
        }
        if substrStr(100, 5, "hello") != "" {
                t.Error("substrStr past end")
        }
        if substrStr(3, 100, "hello") != "lo" {
                t.Error("substrStr clamp end")
        }
}

func TestReplaceStr(t *testing.T) {
        got := replaceStr("world", "Go", "hello world")
        if got != "hello Go" {
                t.Errorf("replaceStr = %q", got)
        }
}

func TestUrlEncode(t *testing.T) {
        got := urlEncode("hello world&foo=bar")
        if !strings.Contains(got, "+") || !strings.Contains(got, "%26") {
                t.Errorf("urlEncode = %q", got)
        }
}

func TestBimiProxyURL(t *testing.T) {
        got := string(bimiProxyURL("https://example.com/logo.svg"))
        if !strings.HasPrefix(got, "/proxy/bimi-logo?url=") {
                t.Errorf("bimiProxyURL = %q", got)
        }
}

func TestMapGet(t *testing.T) {
        m := map[string]interface{}{"key": "value"}
        if mapGet("key", m) != "value" {
                t.Error("mapGet existing key")
        }
        if mapGet("missing", m) != nil {
                t.Error("mapGet missing key")
        }
        if mapGet("key", nil) != nil {
                t.Error("mapGet nil map")
        }
}

func TestMapGetStr(t *testing.T) {
        m := map[string]interface{}{"s": "hello", "n": 42, "nil": nil}
        if mapGetStr("s", m) != "hello" {
                t.Error("mapGetStr string")
        }
        if mapGetStr("n", m) != "42" {
                t.Error("mapGetStr non-string")
        }
        if mapGetStr("nil", m) != "" {
                t.Error("mapGetStr nil value")
        }
        if mapGetStr("missing", m) != "" {
                t.Error("mapGetStr missing")
        }
        if mapGetStr("key", nil) != "" {
                t.Error("mapGetStr nil map")
        }
}

func TestMapGetInt(t *testing.T) {
        m := map[string]interface{}{
                "i":   42,
                "i64": int64(100),
                "f":   float64(3.9),
                "s":   "hello",
                "nil": nil,
        }
        if mapGetInt("i", m) != 42 {
                t.Error("mapGetInt int")
        }
        if mapGetInt("i64", m) != 100 {
                t.Error("mapGetInt int64")
        }
        if mapGetInt("f", m) != 3 {
                t.Error("mapGetInt float64")
        }
        if mapGetInt("s", m) != 0 {
                t.Error("mapGetInt string")
        }
        if mapGetInt("nil", m) != 0 {
                t.Error("mapGetInt nil")
        }
        if mapGetInt("missing", m) != 0 {
                t.Error("mapGetInt missing")
        }
        if mapGetInt("k", nil) != 0 {
                t.Error("mapGetInt nil map")
        }
}

func TestMapGetFloat(t *testing.T) {
        m := map[string]interface{}{"f": float64(3.14)}
        if mapGetFloat("f", m) != 3.14 {
                t.Error("mapGetFloat")
        }
        if mapGetFloat("k", nil) != 0 {
                t.Error("mapGetFloat nil map")
        }
}

func TestMapGetBool(t *testing.T) {
        m := map[string]interface{}{"t": true, "f": false, "s": "yes", "nil": nil}
        if !mapGetBool("t", m) {
                t.Error("mapGetBool true")
        }
        if mapGetBool("f", m) {
                t.Error("mapGetBool false")
        }
        if mapGetBool("s", m) {
                t.Error("mapGetBool non-bool")
        }
        if mapGetBool("nil", m) {
                t.Error("mapGetBool nil value")
        }
        if mapGetBool("missing", m) {
                t.Error("mapGetBool missing")
        }
        if mapGetBool("k", nil) {
                t.Error("mapGetBool nil map")
        }
}

func TestMapGetMap(t *testing.T) {
        sub := map[string]interface{}{"nested": true}
        m := map[string]interface{}{"sub": sub, "str": "hello", "nil": nil}
        got := mapGetMap("sub", m)
        if got == nil || got["nested"] != true {
                t.Error("mapGetMap existing")
        }
        if mapGetMap("str", m) != nil {
                t.Error("mapGetMap non-map")
        }
        if mapGetMap("nil", m) != nil {
                t.Error("mapGetMap nil value")
        }
        if mapGetMap("missing", m) != nil {
                t.Error("mapGetMap missing")
        }
        if mapGetMap("k", nil) != nil {
                t.Error("mapGetMap nil map")
        }
}

func TestMapGetSlice(t *testing.T) {
        m := map[string]interface{}{
                "iface": []interface{}{"a", "b"},
                "str":   []string{"x", "y"},
                "maps":  []map[string]interface{}{{"k": "v"}},
                "int":   42,
                "nil":   nil,
        }
        got := mapGetSlice("iface", m)
        if len(got) != 2 {
                t.Error("mapGetSlice iface")
        }
        got = mapGetSlice("str", m)
        if len(got) != 2 {
                t.Error("mapGetSlice str")
        }
        got = mapGetSlice("maps", m)
        if len(got) != 1 {
                t.Error("mapGetSlice maps")
        }
        if mapGetSlice("int", m) != nil {
                t.Error("mapGetSlice non-slice")
        }
        if mapGetSlice("nil", m) != nil {
                t.Error("mapGetSlice nil value")
        }
        if mapGetSlice("missing", m) != nil {
                t.Error("mapGetSlice missing")
        }
        if mapGetSlice("k", nil) != nil {
                t.Error("mapGetSlice nil map")
        }
}

func TestMapKeys(t *testing.T) {
        m := map[string]interface{}{"a": 1, "b": 2}
        keys := mapKeys(m)
        if len(keys) != 2 {
                t.Errorf("mapKeys len = %d", len(keys))
        }
        if mapKeys(nil) != nil {
                t.Error("mapKeys nil")
        }
}

func TestDict(t *testing.T) {
        d := dict("a", 1, "b", "two")
        if d["a"] != 1 || d["b"] != "two" {
                t.Error("dict basic")
        }
        if dict("a") != nil {
                t.Error("dict odd args")
        }
        d = dict(42, "val")
        if len(d) != 0 {
                t.Error("dict non-string key should be skipped")
        }
}

func TestIsMap(t *testing.T) {
        if !isMap(map[string]interface{}{}) {
                t.Error("isMap true")
        }
        if isMap("string") {
                t.Error("isMap false")
        }
}

func TestToMap(t *testing.T) {
        m := map[string]interface{}{"k": "v"}
        if toMap(m) == nil {
                t.Error("toMap valid")
        }
        if toMap(nil) != nil {
                t.Error("toMap nil")
        }
        if toMap("string") != nil {
                t.Error("toMap non-map")
        }
}

func TestListSlice(t *testing.T) {
        got := listSlice(1, "two", 3.0)
        if len(got) != 3 {
                t.Error("listSlice")
        }
}

func TestSeq(t *testing.T) {
        got := seq(1, 5)
        if len(got) != 5 || got[0] != 1 || got[4] != 5 {
                t.Errorf("seq = %v", got)
        }
}

func TestIsSlice(t *testing.T) {
        if !isSlice([]interface{}{}) {
                t.Error("isSlice []interface{}")
        }
        if !isSlice([]string{}) {
                t.Error("isSlice []string")
        }
        if !isSlice([]int{}) {
                t.Error("isSlice []int")
        }
        if !isSlice([]float64{}) {
                t.Error("isSlice []float64")
        }
        if isSlice("string") {
                t.Error("isSlice string")
        }
}

func TestSliceFrom(t *testing.T) {
        s := []interface{}{1, 2, 3, 4}
        got := sliceFrom(2, s)
        if len(got) != 2 || got[0] != 3 {
                t.Error("sliceFrom")
        }
        if sliceFrom(10, s) != nil {
                t.Error("sliceFrom past end")
        }
}

func TestSliceIndex(t *testing.T) {
        s := []interface{}{"a", "b", "c"}
        if sliceIndex(1, s) != "b" {
                t.Error("sliceIndex valid")
        }
        if sliceIndex(-1, s) != nil {
                t.Error("sliceIndex negative")
        }
        if sliceIndex(10, s) != nil {
                t.Error("sliceIndex past end")
        }
}

func TestToInt(t *testing.T) {
        tests := []struct {
                input interface{}
                want  int
        }{
                {int(42), 42},
                {int32(42), 42},
                {int64(42), 42},
                {float64(3.9), 3},
                {float32(2.1), 2},
                {"hello", 0},
        }
        for _, tt := range tests {
                got := toInt(tt.input)
                if got != tt.want {
                        t.Errorf("toInt(%v) = %d, want %d", tt.input, got, tt.want)
                }
        }
}

func TestToStringSlice(t *testing.T) {
        got := toStringSlice([]string{"a", "b"})
        if len(got) != 2 {
                t.Error("toStringSlice []string")
        }
        got = toStringSlice([]interface{}{"x", "y", 42})
        if len(got) != 2 {
                t.Error("toStringSlice []interface{}")
        }
        if toStringSlice(nil) != nil {
                t.Error("toStringSlice nil")
        }
        if toStringSlice(42) != nil {
                t.Error("toStringSlice int")
        }
}

func TestToMapSlice(t *testing.T) {
        ms := []map[string]interface{}{{"a": 1}}
        got := toMapSlice(ms)
        if len(got) != 1 {
                t.Error("toMapSlice direct")
        }
        iface := []interface{}{map[string]interface{}{"b": 2}, "skip"}
        got = toMapSlice(iface)
        if len(got) != 1 {
                t.Error("toMapSlice []interface{}")
        }
        if toMapSlice(nil) != nil {
                t.Error("toMapSlice nil")
        }
        if toMapSlice(42) != nil {
                t.Error("toMapSlice int")
        }
}

func TestIsNumeric(t *testing.T) {
        numerics := []interface{}{int(1), int8(1), int16(1), int32(1), int64(1), uint(1), uint8(1), uint16(1), uint32(1), uint64(1), float32(1), float64(1)}
        for _, v := range numerics {
                if !isNumeric(v) {
                        t.Errorf("isNumeric(%T) should be true", v)
                }
        }
        if isNumeric("string") {
                t.Error("isNumeric(string) should be false")
        }
        if isNumeric(nil) {
                t.Error("isNumeric(nil) should be false")
        }
}

func TestGteCmp(t *testing.T) {
        if !gteCmp(float64(10), int(10)) {
                t.Error("gteCmp equal")
        }
        if !gteCmp(float64(11), int(10)) {
                t.Error("gteCmp greater")
        }
        if gteCmp(float64(9), int(10)) {
                t.Error("gteCmp less")
        }
}

func TestLteCmp(t *testing.T) {
        if !lteCmp(float64(10), int(10)) {
                t.Error("lteCmp equal")
        }
        if !lteCmp(float64(9), int(10)) {
                t.Error("lteCmp less")
        }
        if lteCmp(float64(11), int(10)) {
                t.Error("lteCmp greater")
        }
}

func TestIsNilNotNil(t *testing.T) {
        if !isNil(nil) {
                t.Error("isNil(nil)")
        }
        if isNil(42) {
                t.Error("isNil(42)")
        }
        if !notNil(42) {
                t.Error("notNil(42)")
        }
        if notNil(nil) {
                t.Error("notNil(nil)")
        }
}

func TestDefaultVal(t *testing.T) {
        if defaultVal("fallback", nil) != "fallback" {
                t.Error("defaultVal nil")
        }
        if defaultVal("fallback", "") != "fallback" {
                t.Error("defaultVal empty string")
        }
        if defaultVal("fallback", "actual") != "actual" {
                t.Error("defaultVal with value")
        }
        if defaultVal("fallback", 42) != 42 {
                t.Error("defaultVal with int")
        }
}

func TestCoalesce(t *testing.T) {
        if coalesce(nil, "", "hello", "world") != "hello" {
                t.Error("coalesce")
        }
        if coalesce(nil, nil) != nil {
                t.Error("coalesce all nil")
        }
        if coalesce(42) != 42 {
                t.Error("coalesce first non-nil")
        }
}

func TestStatusBadgeClass(t *testing.T) {
        tests := []struct {
                input, want string
        }{
                {"success", "bg-success"},
                {"warning", "bg-warning"},
                {"info", "bg-info"},
                {"danger", "bg-danger"},
                {"error", "bg-danger"},
                {"critical", "bg-danger"},
                {"unknown", "bg-secondary"},
                {"SUCCESS", "bg-success"},
        }
        for _, tt := range tests {
                got := statusBadgeClass(tt.input)
                if got != tt.want {
                        t.Errorf("statusBadgeClass(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestStatusColor(t *testing.T) {
        tests := []struct {
                input, want string
        }{
                {"success", "success"},
                {"warning", "warning"},
                {"partial", "warning"},
                {"error", "danger"},
                {"danger", "danger"},
                {"critical", "danger"},
                {"info", "info"},
                {"unknown", "secondary"},
        }
        for _, tt := range tests {
                got := statusColor(tt.input)
                if got != tt.want {
                        t.Errorf("statusColor(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestSectionStatusCSS(t *testing.T) {
        tests := []struct {
                input, want string
        }{
                {"beta", "u-status-beta"},
                {"active development", "u-status-active"},
                {"maintenance", "u-status-maintenance"},
                {"experimental", "u-status-experimental"},
                {"deprecated", "u-status-deprecated"},
                {"accuracy tuning", "u-section-tuning"},
                {"unknown", "u-section-tuning"},
                {"BETA", "u-status-beta"},
        }
        for _, tt := range tests {
                got := sectionStatusCSS(tt.input)
                if got != tt.want {
                        t.Errorf("sectionStatusCSS(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestSectionStatusIcon(t *testing.T) {
        tests := []struct {
                input, want string
        }{
                {"beta", "flask"},
                {"active development", "code"},
                {"maintenance", "wrench"},
                {"experimental", "microscope"},
                {"deprecated", "archive"},
                {"accuracy tuning", "wrench"},
                {"unknown", "wrench"},
        }
        for _, tt := range tests {
                got := sectionStatusIcon(tt.input)
                if got != tt.want {
                        t.Errorf("sectionStatusIcon(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestCountryFlag(t *testing.T) {
        got := countryFlag("US")
        if got == "" {
                t.Error("countryFlag US should not be empty")
        }
        if countryFlag("X") != "" {
                t.Error("countryFlag single char should be empty")
        }
        if countryFlag("USA") != "" {
                t.Error("countryFlag 3 chars should be empty")
        }
        got2 := countryFlag("us")
        if got2 != got {
                t.Error("countryFlag should uppercase")
        }
}

func TestStaticURL(t *testing.T) {
        got := staticURL("css/style.css")
        if got != "/static/css/style.css" {
                t.Errorf("staticURL = %q", got)
        }
}

func TestStaticVersionURL(t *testing.T) {
        got := staticVersionURL("js/app.js", "1.0")
        if got != "/static/js/app.js?v=1.0" {
                t.Errorf("staticVersionURL = %q", got)
        }
}

func TestToJSON(t *testing.T) {
        got := toJSON(map[string]int{"a": 1})
        if !strings.Contains(got, `"a":1`) {
                t.Errorf("toJSON = %q", got)
        }
        got = toJSON(make(chan int))
        if got != "{}" {
                t.Errorf("toJSON unmarshalable = %q", got)
        }
}

func TestToStr(t *testing.T) {
        if toStr(nil) != "" {
                t.Error("toStr nil")
        }
        if toStr("hello") != "hello" {
                t.Error("toStr string")
        }
        if toStr(42) != "42" {
                t.Error("toStr int")
        }
}

func TestPluralize(t *testing.T) {
        if pluralize(1, "item", "items") != "item" {
                t.Error("pluralize singular")
        }
        if pluralize(2, "item", "items") != "items" {
                t.Error("pluralize plural")
        }
        if pluralize(0, "item", "items") != "items" {
                t.Error("pluralize zero")
        }
}

func TestHtmlComment(t *testing.T) {
        got := string(htmlComment("hello -- world"))
        if !strings.HasPrefix(got, "<!--") || !strings.HasSuffix(got, "-->") {
                t.Errorf("htmlComment = %q", got)
        }
        if strings.Contains(got, "--") && !strings.Contains(got, "<!--") {
                t.Error("htmlComment should replace --")
        }
}

func TestMergeFuncs(t *testing.T) {
        dst := template.FuncMap{"a": func() {}}
        src := template.FuncMap{"b": func() {}}
        mergeFuncs(dst, src)
        if _, ok := dst["b"]; !ok {
                t.Error("mergeFuncs should copy keys")
        }
}

func TestFuncMapHasExpectedKeys(t *testing.T) {
        fm := FuncMap()
        expected := []string{"eq", "ne", "gt", "lt", "ge", "le", "formatDate", "add", "sub",
                "upper", "lower", "mapGet", "dict", "list", "seq", "statusBadgeClass", "toJSON", "pluralize"}
        for _, k := range expected {
                if _, ok := fm[k]; !ok {
                        t.Errorf("FuncMap missing key %q", k)
                }
        }
}

func TestTitleFunc(t *testing.T) {
        fm := stringFuncs()
        titleFn, ok := fm["title"]
        if !ok {
                t.Fatal("missing title function in stringFuncs")
        }
        fn := titleFn.(func(string) string)

        tests := []struct {
                input string
                want  string
        }{
                {"hello", "Hello"},
                {"hello world", "Hello World"},
                {"dns tool", "Dns Tool"},
                {"", ""},
                {"ALREADY UPPER", "Already Upper"},
        }
        for _, tt := range tests {
                got := fn(tt.input)
                if got != tt.want {
                        t.Errorf("title(%q) = %q, want %q", tt.input, got, tt.want)
                }
        }
}

func TestSafeFuncs(t *testing.T) {
        fm := safeFuncs()
        if _, ok := fm["safeHTML"]; !ok {
                t.Error("missing safeHTML")
        }
        if _, ok := fm["safeURL"]; !ok {
                t.Error("missing safeURL")
        }
        if _, ok := fm["safeAttr"]; !ok {
                t.Error("missing safeAttr")
        }
        if _, ok := fm["safeJS"]; !ok {
                t.Error("missing safeJS")
        }
}
