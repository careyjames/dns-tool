#!/usr/bin/env node
/**
 * DNS Tool — Feature Regression Inventory (R011)
 * Scans the codebase to verify that known features still exist and are wired up.
 * Run: node scripts/feature-inventory.js
 *
 * Checks:
 * 1. Go stub functions return real data (not hardcoded "Unknown")
 * 2. Template variables are populated
 * 3. CSS classes referenced in templates exist in stylesheets
 * 4. Covert mode overrides exist for semantic elements
 * 5. Key routes are registered
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
let errors = 0;
let warnings = 0;
let pass = 0;

function read(relPath) {
  const full = path.join(ROOT, relPath);
  if (!fs.existsSync(full)) return null;
  return fs.readFileSync(full, 'utf8');
}

function check(label, condition, detail) {
  if (condition) {
    pass++;
  } else {
    errors++;
    console.log(`  ✗ [REGRESSION] ${label}`);
    if (detail) console.log(`    ${detail}`);
  }
}

function warn(label, detail) {
  warnings++;
  console.log(`  ⚠ [WARNING] ${label}`);
  if (detail) console.log(`    ${detail}`);
}

console.log('═══════════════════════════════════════════════════════════════');
console.log('  DNS Tool — Feature Regression Inventory');
console.log(`  Date: ${new Date().toISOString().slice(0, 10)}`);
console.log('═══════════════════════════════════════════════════════════════\n');

// ── 1. Hosting Detection ──────────────────────────────────────
console.log('── Hosting Detection (R007) ─────────────────────────────────');
const infraOSS = read('go-server/internal/analyzer/infrastructure_oss.go');
if (infraOSS) {
  const getHostingFn = infraOSS.match(/func \(a \*Analyzer\) GetHostingInfo[\s\S]*?^}/m);
  if (getHostingFn) {
    const fnBody = getHostingFn[0];
    check('GetHostingInfo uses provider data',
      fnBody.includes('identifyWebHostingOSS') || fnBody.includes('identifyWebHosting'),
      'GetHostingInfo should call provider matching, not return hardcoded "Unknown"');
    check('GetHostingInfo returns DNS hosting',
      fnBody.includes('identifyDNSProviderOSS') || fnBody.includes('identifyDNSProvider'),
      'DNS hosting should use NS record matching');
    check('GetHostingInfo returns email hosting',
      fnBody.includes('identifyEmailProviderOSS') || fnBody.includes('identifyEmailProvider'),
      'Email hosting should use MX record matching');
  } else {
    check('GetHostingInfo function exists', false, 'Function not found in infrastructure_oss.go');
  }
} else {
  check('infrastructure_oss.go exists', false, 'File not found');
}

// ── 2. Provider Data ──────────────────────────────────────────
console.log('\n── Provider Data ────────────────────────────────────────────');
const providersGo = read('go-server/internal/providers/providers.go');
if (providersGo) {
  check('CNAMEProviderMap has entries',
    (providersGo.match(/CNAMEProviderMap.*=.*map/s) && providersGo.includes('shopify.com')),
    'CNAME provider map should contain known providers');
  check('DANEMXCapability has entries',
    providersGo.includes('DANEMXCapability') && providersGo.includes('outlook.com'),
    'DANE MX capability map should contain known email providers');
  check('knownDNSProviders exists',
    read('go-server/internal/analyzer/ns_delegation.go')?.includes('knownDNSProviders'),
    'DNS provider patterns should exist in ns_delegation.go');
} else {
  check('providers.go exists', false, 'File not found');
}

// ── 3. Glass Treatment CSS ────────────────────────────────────
console.log('\n── Glass Treatment CSS ──────────────────────────────────────');
const css = read('static/css/custom.css');
if (css) {
  const glassElements = [
    { name: 'ICAE badge dot', pattern: /\.icae-badge-verified\s+\.icae-dot\s*\{[^}]*rgba/ },
    { name: 'ICuAE badge dot', pattern: /\.icuae-badge-adequate\s+\.icuae-dot\s*\{[^}]*rgba/ },
    { name: 'Analyze button glass bg', pattern: /\.btn-analyze\s*\{[^}]*rgba\(201,\s*163,\s*102/ },
    { name: 'ICAE dot verified', pattern: /\.icae-dot-color-verified\s*\{[^}]*rgba/ },
    { name: 'Hero maturity dot', pattern: /\.icae-hero-maturity[^:]*::before\s*\{[^}]*rgba/ },
  ];
  for (const el of glassElements) {
    check(`Glass: ${el.name}`, el.pattern.test(css), `Missing glass treatment for ${el.name}`);
  }

  const covertElements = [
    { name: 'Covert ICAE badge', pattern: /covert-mode\s+\.icae-badge\s/ },
    { name: 'Covert ICuAE badge', pattern: /covert-mode\s+\.icuae-badge\s/ },
    { name: 'Covert ICAE dot verified', pattern: /covert-mode\s+\.icae-dot-color-verified/ },
    { name: 'Covert ICuAE dot', pattern: /covert-mode\s+\.icuae-badge\s+\.icuae-dot/ },
    { name: 'Covert hero maturity', pattern: /covert-mode\s+\.icae-hero-maturity\s*\{/ },
    { name: 'Covert hero maturity dot', pattern: /covert-mode\s+\.icae-hero-maturity::before/ },
    { name: 'Covert Analyze button', pattern: /covert-mode\s+\.btn-analyze\s*\{/ },
    { name: 'Covert icae-level-verified', pattern: /covert-mode\s+\.icae-level-verified/ },
    { name: 'Covert icae-level-consistent', pattern: /covert-mode\s+\.icae-level-consistent/ },
    { name: 'Covert icae-level-gold', pattern: /covert-mode\s+\.icae-level-gold\s/ },
    { name: 'Covert icae-level-gold-master', pattern: /covert-mode\s+\.icae-level-gold-master/ },
  ];
  for (const el of covertElements) {
    check(`Covert: ${el.name}`, el.pattern.test(css), `Missing covert mode override for ${el.name}`);
  }
} else {
  check('custom.css exists', false, 'File not found');
}

// ── 4. Template Variables ─────────────────────────────────────
console.log('\n── Template Variables ───────────────────────────────────────');
const resultsHTML = read('go-server/templates/results.html');
if (resultsHTML) {
  check('Template renders hosting_summary', resultsHTML.includes('hosting_summary'),
    'results.html should reference hosting_summary');
  check('Template renders email_hosting', resultsHTML.includes('email_hosting'),
    'results.html should reference email_hosting');
  check('Template renders dns_hosting', resultsHTML.includes('dns_hosting'),
    'results.html should reference dns_hosting');
  check('Template renders ICAE maturity', resultsHTML.includes('OverallMaturity'),
    'results.html should reference OverallMaturity');
}
const indexHTML = read('go-server/templates/index.html');
if (indexHTML) {
  check('Homepage renders ICAE hero', indexHTML.includes('icae-hero-maturity'),
    'index.html should have ICAE hero maturity badge');
  check('Homepage renders ICuAE badge', indexHTML.includes('icuae-badge'),
    'index.html should have ICuAE badge');
  check('Homepage renders btn-analyze', indexHTML.includes('btn-analyze'),
    'index.html should have btn-analyze class on analyze button');
}

// ── 5. Key Routes ─────────────────────────────────────────────
console.log('\n── Key Routes ──────────────────────────────────────────────');
const routesFiles = [
  'go-server/internal/handlers/routes.go',
  'go-server/internal/handlers/handlers.go',
  'go-server/cmd/server/main.go',
];
let routesContent = '';
for (const f of routesFiles) {
  const c = read(f);
  if (c) routesContent += c;
}
if (routesContent) {
  const requiredRoutes = ['/healthz', '/analyze', '/confidence', '/architecture'];
  for (const route of requiredRoutes) {
    check(`Route registered: ${route}`,
      routesContent.includes(route),
      `Route ${route} should be registered in handlers`);
  }
}

// ── 6. Build System ───────────────────────────────────────────
console.log('\n── Build System ────────────────────────────────────────────');
const buildSh = read('build.sh');
if (buildSh) {
  check('Build uses CGO_ENABLED=0', buildSh.includes('CGO_ENABLED=0'),
    'Static binary requires CGO_ENABLED=0');
  check('Build uses -ldflags', buildSh.includes('-ldflags'),
    'Version stamping requires -ldflags');
}
const configGo = read('go-server/internal/config/config.go');
if (configGo) {
  const versionMatch = configGo.match(/Version\s*=\s*"([^"]+)"/);
  if (versionMatch) {
    console.log(`  ℹ Current version: ${versionMatch[1]}`);
  }
}

// ── 7. TLD Toast & Provenance ────────────────────────────────
console.log('\n── TLD Toast & Provenance ──────────────────────────────────');
const mainJs = read('static/js/main.js');
if (mainJs) {
  check('TLD detection helper exists', mainJs.includes('isBareTopLevelDomain'),
    'main.js must define isBareTopLevelDomain()');
  check('Covert TLD toast exists', mainJs.includes('showCovertTLDToast'),
    'main.js must define showCovertTLDToast()');
  check('Toast fires in covert mode only', mainJs.includes('covert-mode') && mainJs.includes('isBareTopLevelDomain'),
    'Toast must be gated by covert-mode class check');
}
const analysisHandler = read('go-server/internal/handlers/analysis.go');
if (analysisHandler) {
  check('SHA3 sidecar includes analysis ID', analysisHandler.includes('Analysis ID:'),
    'Checksum .sha3 file must include analysis ID');
  check('SHA3 sidecar includes report URL', analysisHandler.includes('Report URL:'),
    'Checksum .sha3 file must include permalink back to report');
  check('Unified mode handler exists', analysisHandler.includes('viewAnalysisWithMode'),
    'Handler must dispatch E/C/B via viewAnalysisWithMode');
  check('Mode resolver function exists', analysisHandler.includes('resolveReportMode'),
    'Route mode param resolver must exist');
  check('ReportMode passed to template', analysisHandler.includes('"ReportMode"'),
    'Template data must include ReportMode for URL canonicalization');
}
const mainGoServer = read('go-server/cmd/server/main.go');
if (mainGoServer) {
  check('Mode-aware route registered', mainGoServer.includes('/analysis/:id/view/:mode'),
    'Router must register /analysis/:id/view/:mode');
}
if (mainJs) {
  check('URL canonicalization uses x-report-mode', mainJs.includes('x-report-mode'),
    'JS must read meta[name=x-report-mode] for replaceState');
}

// ── 8. Question Branding (R004) ─────────────────────────────
console.log('\n── Question Branding (R004) ────────────────────────────────');
check('.dt-question base class in CSS', css.includes('.dt-question {'),
  'Base question class must exist');
check('.dt-question--section modifier', css.includes('.dt-question--section'),
  'Section-level modifier must exist');
check('.dt-question--protocol modifier', css.includes('.dt-question--protocol'),
  'Protocol-level modifier must exist');
check('Covert .dt-question override', css.includes('body.covert-mode .dt-question'),
  'Single covert override for all question text');
check('--dt-question-border token', css.includes('--dt-question-border:'),
  'Protocol container border must be tokenized');
check('--dt-question-bg token', css.includes('--dt-question-bg:'),
  'Protocol container background must be tokenized');
check('.protocol-question uses border token', css.includes('var(--dt-question-border)'),
  'Protocol question container must reference border token');
check('.protocol-question uses bg token', css.includes('var(--dt-question-bg)'),
  'Protocol question container must reference bg token');
check('.section-question uses composition', !css.match(/\.section-question\s*\{[^}]*font-weight/),
  '.section-question must not duplicate font-weight (composed via .dt-question)');
check('.protocol-question-text uses composition', !css.match(/\.protocol-question-text\s*\{[^}]*font-weight/),
  '.protocol-question-text must not duplicate font-weight (composed via .dt-question)');
const resultsHtml = read('go-server/templates/results.html');
if (resultsHtml) {
  check('Protocol questions have dt-question class', resultsHtml.includes('protocol-question-text dt-question dt-question--protocol'),
    'Protocol question spans must compose .dt-question');
}

// ── 9. Math Display System ───────────────────────────────────
console.log('\n── Math Display System ─────────────────────────────────────');
check('.math-display class in CSS', css.includes('.math-display'),
  'KaTeX chalkboard treatment must be defined');
check('.math-copy-btn in CSS', css.includes('.math-copy-btn'),
  'Copy button styling for math blocks');
check('.math-copy-btn--copied in CSS', css.includes('.math-copy-btn--copied'),
  'Copy success state styling');
check('Covert mode .math-display', css.includes('body.covert-mode .math-display'),
  'Red accent border in covert mode');
const mathCopyPartial = read('go-server/templates/_math_copy.html');
check('_math_copy.html partial exists', !!mathCopyPartial,
  'Shared math copy-button script template');
const archHtml = read('go-server/templates/architecture.html');
if (archHtml) {
  check('Architecture page has math-display blocks', archHtml.includes('class="math-display"'),
    'Architecture dual-engine section needs KaTeX display formulas');
  check('Architecture page loads math_copy_script', archHtml.includes('math_copy_script'),
    'Architecture page should wire up copy buttons');
}
const confHtml = read('go-server/templates/confidence.html');
if (confHtml) {
  check('Confidence page has math-display blocks', confHtml.includes('class="math-display"'),
    'Confidence page needs KaTeX display formulas');
  check('Confidence page loads math_copy_script', confHtml.includes('math_copy_script'),
    'Confidence page should wire up copy buttons');
}

// ── 10. CSS Minification ─────────────────────────────────────
console.log('\n── CSS Minification ────────────────────────────────────────');
const cssPath = path.join(ROOT, 'static/css/custom.css');
const minPath = path.join(ROOT, 'static/css/custom.min.css');
if (fs.existsSync(cssPath) && fs.existsSync(minPath)) {
  const cssStat = fs.statSync(cssPath);
  const minStat = fs.statSync(minPath);
  check('Minified CSS is up to date',
    minStat.mtimeMs >= cssStat.mtimeMs,
    `custom.min.css (${new Date(minStat.mtimeMs).toISOString()}) is older than custom.css (${new Date(cssStat.mtimeMs).toISOString()}) — run npx csso`);
}

// ── 11. JS Minification ──────────────────────────────────────
console.log('\n── JS Minification ─────────────────────────────────────────');
const jsFiles = ['main'];
jsFiles.forEach(name => {
  const srcPath = path.join(ROOT, `static/js/${name}.js`);
  const minJsPath = path.join(ROOT, `static/js/${name}.min.js`);
  if (fs.existsSync(srcPath) && fs.existsSync(minJsPath)) {
    const srcStat = fs.statSync(srcPath);
    const minJsStat = fs.statSync(minJsPath);
    check(`Minified ${name}.min.js is up to date`,
      minJsStat.mtimeMs >= srcStat.mtimeMs,
      `${name}.min.js (${new Date(minJsStat.mtimeMs).toISOString()}) is older than ${name}.js (${new Date(srcStat.mtimeMs).toISOString()}) — run npx terser`);
  }
});

// ── 12. Phase 2: Scanner Profile ─────────────────────────────
console.log('\n── Phase 2: Scanner Profile ─────────────────────────────────');
const scannerProfile = read('go-server/internal/icuae/scanner_profile.go');
if (scannerProfile) {
  check('ScannerProfile struct exists', scannerProfile.includes('type ScannerProfile struct'));
  check('ProfileSuggestion struct exists', scannerProfile.includes('type ProfileSuggestion struct'));
  check('GenerateSuggestedConfig function exists', scannerProfile.includes('func GenerateSuggestedConfig'));
  check('BuildRollingStats function exists', scannerProfile.includes('func BuildRollingStats'));
  check('DefaultProfile defined', scannerProfile.includes('var DefaultProfile'));
  check('NIST SP 800-53 SI-7 cited', scannerProfile.includes('NIST SP 800-53 SI-7'));
  check('RFC 8767 cited', scannerProfile.includes('RFC 8767'));
}
const resultsHtml2 = read('go-server/templates/results.html');
if (resultsHtml2) {
  check('SuggestedConfig template block exists', resultsHtml2.includes('SuggestedConfig'));
  check('suggestedConfigPanel collapse ID exists', resultsHtml2.includes('suggestedConfigPanel'));
}

// ── Summary ──────────────────────────────────────────────────
console.log('\n═══════════════════════════════════════════════════════════════');
console.log(`  Passed:   ${pass}`);
console.log(`  Failed:   ${errors}`);
console.log(`  Warnings: ${warnings}`);
console.log(`  Result:   ${errors === 0 ? 'PASS' : 'FAIL'}`);
console.log('═══════════════════════════════════════════════════════════════');

process.exit(errors > 0 ? 1 : 0);
