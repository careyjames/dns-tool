# DNS Tool — Coding Conventions

## Go Conventions
- **File naming**: `snake_case.go`, stubs `*_oss.go`, tests `*_test.go`
- **Bridge tests**: `*_bridge_test.go` (mock vs golden fixture validation)
- **Pure tests**: `*_pure_test.go` (unit tests without external dependencies)
- **License header**: Every file starts with BUSL-1.1 copyright header
- **Build tags**: `//go:build !intel` for OSS stubs, `//go:build intel` for proprietary
- **Constants**: `mapKeySomething` for JSON map keys, `errExpectedGot` for test formatting
- **Error format**: `t.Errorf("expected %v, got %v", expected, actual)`

## Template Conventions
- All user-facing headings use NIST/Chicago title case
- No inline `onclick`/`onchange`/`style=""` — use `addEventListener` in nonce'd `<script>` blocks
- CSP nonces via `{{.Nonce}}` template variable
- SRI integrity via `{{staticSRI "path"}}` template function
- Version-stamped URLs via `{{staticVersionURL "path" .AppVersion}}`
- Print-only elements: `display: none !important` in screen stylesheet

## CSS Conventions
- Four-layer token system: Background → Text → Status → Accents
- CSS custom properties: `--bg-primary`, `--text-primary`, `--accent-gold`, etc.
- Brand colors: Emblem Gold (#C8A878), Accent Red (#C42A2A)
- Scientific status colors validated by `scripts/validate-scientific-colors.js`
- Glass effects validated by `scripts/audit-css-cohesion.js`
- All changes verified at 375px width minimum

## JavaScript Conventions
- Source: `static/js/main.js`, minified: `static/js/main.min.js`
- Minification: `npx terser static/js/main.js -o static/js/main.min.js --compress --mangle`
- No `location.href` for scan navigation (WebKit kills JS on navigation)
- Use `fetch()` + `document.write()` + `history.replaceState()` pattern
- `showOverlay()` with double-rAF animation restart

### Bootstrap Shim Contract (`foundation.js`)
DNS Tool uses a lightweight custom Bootstrap shim (`static/js/foundation.js`) instead of
the full Bootstrap JS bundle. Any code in `main.js` or templates that uses Bootstrap
APIs must only use methods/events that `foundation.js` actually implements.

**Supported Components & API:**

| Component | Constructor | Methods | Lifecycle Events |
|-----------|------------|---------|-----------------|
| Modal | `new bootstrap.Modal(el)` | `show()`, `hide()` | `show/shown/hide/hidden.bs.modal` |
| Collapse | (delegated click) | `toggleCollapse(el)` | `show/shown/hide/hidden.bs.collapse` |
| Dropdown | `new bootstrap.Dropdown(el)` | `show()`, `hide()`, `toggle()` | None |
| Tooltip | `new bootstrap.Tooltip(el)` | `show()`, `hide()`, `dispose()` | None |
| Alert | `Alert.getOrCreateInstance(el)` | `close()` | None |

**Rules:**
1. If `main.js` or a template listens for a Bootstrap event, that event MUST be dispatched by `foundation.js`
2. If a template calls a method on a Bootstrap instance (e.g., `tooltip.hide()`), that method MUST exist on the shim's prototype
3. The `inert` HTML attribute on modals is managed by `foundation.js` Modal lifecycle — do NOT rely on external event listeners to remove it
4. When adding new Bootstrap-dependent behavior, update `foundation.js` FIRST, then `main.js`
5. After any change to `foundation.js`, re-minify: `npx terser static/js/foundation.js -o static/js/foundation.min.js --compress --mangle`

## Testing Conventions
- **Go tests**: Standard `testing` package, no third-party assertion libraries
- **Golden fixtures**: `tests/golden_fixtures/*.json` — real domain analysis snapshots
- **Confidence Bridge**: `confidence_bridge_test.go` validates mocks against golden fixtures
- **Quality gates**: R009 (CSS), R010 (colors), R011 (features) — run before every release
- **E2E**: Playwright with TypeScript in `tests/e2e/`

## Version Management
- Single source of truth: `go-server/internal/config/config.go` → `Version = "X.Y.Z"`
- `build.sh` reads version automatically
- Must also update: `sonar-project.properties`, `CITATION.cff`, `codemeta.json`
- Service worker cache version auto-updates from binary

## Static Asset Serving
- **MIME types**: Registered via `mime.AddExtensionType()` in `init()` of `main.go` — never rely on OS `/etc/mime.types`
- **Rationale**: Nix production images have a broken `mailcap` mime.types file (I/O error), causing Go's `mime.TypeByExtension()` to panic or return empty Content-Type. Videos won't play, CSS/JS may fail.
- **Rule**: When adding a new static file type, add its MIME mapping to the `init()` function in `go-server/cmd/server/main.go`
- **Cache**: `isStaticAsset()` must include all served file extensions for cache-control headers

## Security Conventions
- SRI SHA-384 on all CSS/JS assets (computed at startup by `InitSRI()`)
- CSP: `default-src 'none'`, script/style-src with nonce
- CSRF: Double-submit cookie pattern
- HSTS: `max-age=63072000; includeSubDomains; preload`
- Cookies: `HttpOnly; Secure; SameSite=Strict`
