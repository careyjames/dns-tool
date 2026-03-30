#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const CSS_FILE = path.join(__dirname, '..', 'static', 'css', 'custom.css');

const GLASS_FORMULA = {
  bgOpacityRange: [0.08, 0.40],
  borderOpacityRange: [0.25, 0.80],
  glowOpacityRange: [0.15, 0.50],
};

const SEMANTIC_COLORS = {
  success: { r: [40, 100], g: [150, 220], b: [50, 120] },
  warning: { r: [200, 240], g: [160, 200], b: [40, 100] },
  danger:  { r: [200, 255], g: [50, 120],  b: [50, 120] },
  info:    { r: [60, 120],  g: [150, 230], b: [220, 255] },
  neutral: { r: [70, 160],  g: [80, 170],  b: [90, 180] },
  violet:  { r: [90, 130],  g: [70, 110],  b: [200, 240] },
  gold:    { r: [190, 245], g: [150, 225], b: [60, 180] },
  covertRed: { r: [100, 220], g: [20, 100], b: [20, 100] },
};

const SUPPRESSIONS = [
  { id: 'COVERT_RED', pattern: /body\.covert-mode/, reason: 'Covert mode uses red spectrum by design' },
  { id: 'PRINT_ONLY', pattern: /@media\s+print/, reason: 'Print styles have different color rules' },
  { id: 'VENDOR', pattern: /vendor|mermaid|katex|bootstrap/, reason: 'Vendor CSS not under our control' },
];

class CSSCohesionAuditor {
  constructor(cssContent, filePath) {
    this.css = cssContent;
    this.filePath = filePath;
    this.lines = cssContent.split('\n');
    this.findings = [];
    this.stats = {
      totalRules: 0,
      totalColors: 0,
      solidDots: 0,
      glassDots: 0,
      hardcodedColors: 0,
      varColors: 0,
      modesCovered: { dark: false, light: false, covert: false },
    };
  }

  audit() {
    this.checkGlassConsistency();
    this.checkHardcodedColors();
    this.checkModeGaps();
    this.checkOpacityFormula();
    this.checkBoxShadowConsistency();
    this.checkSemanticColorLeaks();
    this.checkMissingCovertOverrides();
    return this.report();
  }

  addFinding(severity, category, message, line, context, suppressionId) {
    if (suppressionId) {
      const suppression = SUPPRESSIONS.find(s => s.id === suppressionId);
      if (suppression) {
        this.findings.push({
          severity: 'suppressed',
          category,
          message: `[SUPPRESSED: ${suppression.reason}] ${message}`,
          line,
          context,
        });
        return;
      }
    }
    this.findings.push({ severity, category, message, line, context });
  }

  getLineNumber(charIndex) {
    let count = 0;
    for (let i = 0; i < this.lines.length; i++) {
      count += this.lines[i].length + 1;
      if (count > charIndex) return i + 1;
    }
    return this.lines.length;
  }

  checkGlassConsistency() {
    const dotPattern = /([.#\w\-[\]:()>+~ ]+)::before\s*\{([^}]+)\}/g;
    let match;
    while ((match = dotPattern.exec(this.css)) !== null) {
      const selector = match[1].trim();
      const props = match[2];
      const line = this.getLineNumber(match.index);

      if (!selector.includes('dot') && !selector.includes('level-') && !selector.includes('maturity')) continue;

      const hasBorder = /border:\s*1px\s+solid/.test(props);
      const hasTranslucentBg = /background:\s*rgba\(/.test(props) || /background:\s*linear-gradient\(.+rgba\(/.test(props);
      const hasGlow = /box-shadow/.test(props);
      const hasSolidBg = /background:\s*#[0-9a-fA-F]/.test(props);

      if (hasSolidBg && !hasTranslucentBg) {
        this.stats.solidDots++;
        const isSuppressed = SUPPRESSIONS.some(s => s.pattern.test(this.getContext(line, 5)));
        this.addFinding(
          'warn',
          'GLASS_CONSISTENCY',
          `Solid fill dot found — should be translucent glass: ${selector}`,
          line,
          this.lines[line - 1]?.trim(),
          isSuppressed ? 'COVERT_RED' : null
        );
      } else if (hasTranslucentBg) {
        this.stats.glassDots++;
        if (!hasBorder) {
          this.addFinding(
            'info',
            'GLASS_FORMULA',
            `Glass dot missing border: ${selector}`,
            line,
            this.lines[line - 1]?.trim()
          );
        }
        if (!hasGlow) {
          this.addFinding(
            'info',
            'GLASS_FORMULA',
            `Glass dot missing box-shadow glow: ${selector}`,
            line,
            this.lines[line - 1]?.trim()
          );
        }
      }
    }
  }

  checkHardcodedColors() {
    const hexPattern = /([\w\-.#[\]:()>+~ ]+)\s*\{([^}]+)\}/g;
    let match;
    while ((match = hexPattern.exec(this.css)) !== null) {
      const selector = match[1].trim();
      const props = match[2];
      const line = this.getLineNumber(match.index);

      if (SUPPRESSIONS.some(s => s.pattern.test(selector))) continue;

      const colorProps = props.match(/(?:color|background(?:-color)?|border(?:-color)?)\s*:\s*#[0-9a-fA-F]{3,8}/g);
      if (colorProps) {
        colorProps.forEach(cp => {
          this.stats.hardcodedColors++;
          const hexMatch = cp.match(/#([0-9a-fA-F]{3,8})/);
          if (hexMatch) {
            const hex = hexMatch[1];
            if (hex.length === 3 || hex.length === 6) {
              const isWhiteOrBlack = /^(fff|000|ffffff|000000)$/i.test(hex);
              if (!isWhiteOrBlack) {
                const isInCovertBlock = this.getContext(line, 10).includes('covert-mode');
                if (!isInCovertBlock) {
                  this.stats.totalColors++;
                }
              }
            }
          }
        });
      }

      const varProps = props.match(/var\(--[a-z\-]+\)/g);
      if (varProps) {
        this.stats.varColors += varProps.length;
      }
    }
  }

  checkModeGaps() {
    const classPattern = /\.(icae-badge|icuae-badge|btn-analyze|section-answer|verdict-badge|icae-hero|icae-dot|icuae-dot|icae-level)/g;
    const classesUsed = new Set();
    let match;
    while ((match = classPattern.exec(this.css)) !== null) {
      classesUsed.add(match[1]);
    }

    const covertSection = this.css.match(/body\.covert-mode[\s\S]*?(?=\n\/\*|$)/g) || [];
    const covertText = covertSection.join(' ');

    classesUsed.forEach(cls => {
      const hasCovertOverride = covertText.includes(cls);
      if (!hasCovertOverride && !['icae-dot', 'icuae-dot'].includes(cls)) {
        this.addFinding(
          'info',
          'MODE_COVERAGE',
          `Class ".${cls}" has no covert-mode override — verify intentional`,
          null,
          `Used in default theme but no body.covert-mode .${cls} found`
        );
      }
    });

    this.stats.modesCovered.dark = true;
    this.stats.modesCovered.covert = /body\.covert-mode/.test(this.css);
    this.stats.modesCovered.light = /body\.light-mode|prefers-color-scheme:\s*light/.test(this.css);
  }

  checkOpacityFormula() {
    const rgbaPattern = /rgba\(\s*(\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)/g;
    let match;
    const opacityBuckets = { background: [], border: [], shadow: [] };

    const structuralPatterns = [
      /overlay/, /modal/, /backdrop/, /radial-gradient.*ellipse/,
      /table.*stripe/, /hover.*row/, /zebra/, /nav-version/,
      /tooltip/, /dropdown/, /popover/, /offcanvas/,
      /protocol-card/, /section-card/, /card-body/,
    ];

    const lines = this.css.split('\n');
    lines.forEach((line, idx) => {
      const context5 = lines.slice(Math.max(0, idx - 5), idx + 1).join('\n');
      const isStructural = structuralPatterns.some(p => p.test(context5));
      if (isStructural) return;

      const isGlassElement = /badge|dot|btn-|level-|maturity|verdict|pill|chip/.test(context5);
      if (!isGlassElement) return;

      const isCovertMode = /covert-mode/.test(context5);
      if (isCovertMode) return;

      let m;
      while ((m = rgbaPattern.exec(line)) !== null) {
        const opacity = parseFloat(m[4]);
        const prop = line.trim();

        if (prop.startsWith('background') || prop.includes('--bs-btn-bg')) {
          opacityBuckets.background.push({ opacity, line: idx + 1, prop: prop.substring(0, 80) });
        } else if (prop.startsWith('border') || prop.includes('border-color')) {
          opacityBuckets.border.push({ opacity, line: idx + 1, prop: prop.substring(0, 80) });
        } else if (prop.includes('box-shadow')) {
          opacityBuckets.shadow.push({ opacity, line: idx + 1, prop: prop.substring(0, 80) });
        }
      }
    });

    const bgOutliers = opacityBuckets.background.filter(
      b => (b.opacity > 0 && b.opacity < GLASS_FORMULA.bgOpacityRange[0]) ||
           (b.opacity > GLASS_FORMULA.bgOpacityRange[1] && b.opacity < 0.8)
    );

    bgOutliers.forEach(o => {
      this.addFinding(
        'info',
        'OPACITY_FORMULA',
        `Glass element background opacity ${o.opacity} outside formula range [${GLASS_FORMULA.bgOpacityRange}]`,
        o.line,
        o.prop
      );
    });
  }

  checkBoxShadowConsistency() {
    const glowPattern = /box-shadow:\s*0\s+0\s+(\d+)px\s+rgba\(([^)]+)\)/g;
    const glowSizes = [];
    let match;
    while ((match = glowPattern.exec(this.css)) !== null) {
      const size = parseInt(match[1]);
      const line = this.getLineNumber(match.index);
      glowSizes.push({ size, line });
    }

    if (glowSizes.length > 0) {
      const sizes = glowSizes.map(g => g.size);
      const avg = sizes.reduce((a, b) => a + b, 0) / sizes.length;
      const outliers = glowSizes.filter(g => Math.abs(g.size - avg) > avg * 1.5);
      outliers.forEach(o => {
        this.addFinding(
          'info',
          'GLOW_CONSISTENCY',
          `Glow size ${o.size}px is an outlier (avg: ${avg.toFixed(1)}px)`,
          o.line,
          this.lines[o.line - 1]?.trim()
        );
      });
    }
  }

  checkSemanticColorLeaks() {
    const lines = this.css.split('\n');
    lines.forEach((line, idx) => {
      if (line.includes('covert-mode')) return;
      if (line.trim().startsWith('/*') || line.trim().startsWith('*')) return;

      const greenInDanger = /danger.*#3fb950|danger.*rgba\(\s*63,\s*185,\s*80/.test(line);
      const redInSuccess = /success.*#f85149|success.*rgba\(\s*248,\s*81,\s*73/.test(line);

      if (greenInDanger) {
        this.addFinding('error', 'SEMANTIC_LEAK', 'Green color in danger context', idx + 1, line.trim());
      }
      if (redInSuccess) {
        this.addFinding('error', 'SEMANTIC_LEAK', 'Red color in success context', idx + 1, line.trim());
      }
    });
  }

  checkMissingCovertOverrides() {
    const semanticClasses = [
      'status-success', 'status-warning', 'status-danger', 'status-info',
      'text-success', 'text-warning', 'text-danger', 'text-info',
      'badge-success', 'badge-warning', 'badge-danger', 'badge-info',
    ];

    const covertBlock = this.css.match(/body\.covert-mode[\s\S]*?(?=\n\/\*[^/]|\n\n\n)/g) || [];
    const covertText = covertBlock.join('\n');

    semanticClasses.forEach(cls => {
      const usedInDefault = new RegExp(`\\.${cls}[^a-z]`).test(this.css);
      const hasCovertOverride = new RegExp(`covert-mode.*\\.${cls}|covert-mode[\\s\\S]{0,200}\\.${cls}`).test(covertText);

      if (usedInDefault && !hasCovertOverride) {
        this.addFinding(
          'info',
          'COVERT_COVERAGE',
          `Semantic class ".${cls}" may need covert-mode override for red spectrum`,
          null,
          'No covert-mode selector found for this class'
        );
      }
    });
  }

  getContext(line, radius) {
    const start = Math.max(0, line - radius - 1);
    const end = Math.min(this.lines.length, line + radius);
    return this.lines.slice(start, end).join('\n');
  }

  report() {
    const errors = this.findings.filter(f => f.severity === 'error');
    const warnings = this.findings.filter(f => f.severity === 'warn');
    const infos = this.findings.filter(f => f.severity === 'info');
    const suppressed = this.findings.filter(f => f.severity === 'suppressed');

    let output = '';
    output += '═══════════════════════════════════════════════════════════════\n';
    output += '  DNS Tool — CSS Cohesion Audit Report\n';
    output += `  File: ${this.filePath}\n`;
    output += `  Date: ${new Date().toISOString().split('T')[0]}\n`;
    output += '═══════════════════════════════════════════════════════════════\n\n';

    output += '── SUMMARY ──────────────────────────────────────────────────\n';
    output += `  Glass dots:        ${this.stats.glassDots}\n`;
    output += `  Solid dots:        ${this.stats.solidDots}\n`;
    output += `  Hardcoded colors:  ${this.stats.hardcodedColors}\n`;
    output += `  CSS var() colors:  ${this.stats.varColors}\n`;
    output += `  Mode coverage:     Dark: ✓  Covert: ${this.stats.modesCovered.covert ? '✓' : '✗'}  Light: ${this.stats.modesCovered.light ? '✓' : '○ (not implemented)'}\n\n`;

    output += `  Errors:     ${errors.length}\n`;
    output += `  Warnings:   ${warnings.length}\n`;
    output += `  Info:       ${infos.length}\n`;
    output += `  Suppressed: ${suppressed.length}\n\n`;

    if (errors.length > 0) {
      output += '── ERRORS (semantic violations) ─────────────────────────────\n';
      errors.forEach(f => {
        output += `  ✗ [${f.category}] ${f.message}\n`;
        if (f.line) output += `    Line ${f.line}: ${f.context}\n`;
        output += '\n';
      });
    }

    if (warnings.length > 0) {
      output += '── WARNINGS (cohesion issues) ───────────────────────────────\n';
      warnings.forEach(f => {
        output += `  ⚠ [${f.category}] ${f.message}\n`;
        if (f.line) output += `    Line ${f.line}: ${f.context}\n`;
        output += '\n';
      });
    }

    if (infos.length > 0) {
      output += '── INFO (suggestions) ──────────────────────────────────────\n';
      infos.forEach(f => {
        output += `  ○ [${f.category}] ${f.message}\n`;
        if (f.line) output += `    Line ${f.line}: ${f.context}\n`;
        output += '\n';
      });
    }

    if (suppressed.length > 0) {
      output += '── SUPPRESSED (reviewed, intentional) ──────────────────────\n';
      suppressed.forEach(f => {
        output += `  ~ ${f.message}\n`;
        if (f.line) output += `    Line ${f.line}\n`;
        output += '\n';
      });
    }

    const exitCode = errors.length > 0 ? 2 : (warnings.length > 0 ? 1 : 0);
    output += '═══════════════════════════════════════════════════════════════\n';
    output += `  Result: ${exitCode === 0 ? 'PASS' : exitCode === 1 ? 'WARNINGS' : 'FAIL'}\n`;
    output += '═══════════════════════════════════════════════════════════════\n';

    return { output, exitCode, stats: this.stats, findings: this.findings };
  }
}

const cssContent = fs.readFileSync(CSS_FILE, 'utf-8');
const auditor = new CSSCohesionAuditor(cssContent, 'static/css/custom.css');
const result = auditor.audit();
console.log(result.output);
process.exit(result.exitCode);
