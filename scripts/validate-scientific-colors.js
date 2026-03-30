#!/usr/bin/env node
const fs = require('fs');
const path = require('path');

const CSS_FILE = path.join(__dirname, '..', 'static', 'css', 'custom.css');

const MATURITY_SPECTRUM = {
  'dev':          { name: 'Development',  family: 'gray',     r: [60, 110],  g: [70, 110],  b: [85, 120]  },
  'verified':     { name: 'Verified',     family: 'blue',     r: [80, 130],  g: [150, 200], b: [230, 255] },
  'consistent':   { name: 'Consistent',   family: 'green',    r: [50, 110],  g: [170, 225], b: [60, 125]  },
  'gold':         { name: 'Gold',         family: 'gold',     r: [195, 240], g: [155, 200], b: [60, 110]  },
  'gold-master':  { name: 'Gold Master',  family: 'platinum', r: [220, 255], g: [200, 250], b: [150, 240] },
};

const ICUAE_SPECTRUM = {
  'excellent': { name: 'Excellent', family: 'green',   r: [50, 120],  g: [170, 230], b: [60, 130]  },
  'good':      { name: 'Good',     family: 'green',   r: [40, 100],  g: [150, 220], b: [50, 120]  },
  'adequate':  { name: 'Adequate', family: 'cyan',    r: [60, 130],  g: [190, 255], b: [220, 255] },
  'degraded':  { name: 'Degraded', family: 'gold',    r: [195, 240], g: [155, 200], b: [60, 120]  },
  'stale':     { name: 'Stale',    family: 'red',     r: [200, 255], g: [70, 140],  b: [70, 140]  },
};

const STATUS_TOKENS = {
  'status-success': { family: 'green',  hex: '#3fb950' },
  'status-warning': { family: 'amber',  hex: '#e3b341' },
  'status-danger':  { family: 'red',    hex: '#f85149' },
  'status-info':    { family: 'warm',   hex: '#c8956a' },
  'status-neutral': { family: 'gray',   hex: '#8b949e' },
};

const ACCENT_TOKENS = {
  'accent-steel':  { hex: '#9a8f82' },
  'accent-deep':   { hex: '#3d2e1f' },
  'accent-violet': { hex: '#c8956a' },
  'accent-cyan':   { hex: '#d4a853' },
  'accent-cobalt': { hex: '#b8a089' },
  'accent-gold':   { hex: '#d4a853' },
  'accent-gold-muted': { hex: '#c9a84c' },
  'accent-amber':  { hex: '#e8b54a' },
};

const DT_QUESTION_TOKENS = [
  'dt-question-color',
  'dt-question-color-covert',
  'dt-question-size-section',
  'dt-question-size-protocol',
  'dt-question-weight',
  'dt-question-spacing',
  'dt-question-border',
  'dt-question-border-covert',
  'dt-question-bg',
  'dt-question-bg-covert',
];

const DT_QUESTION_EXPECTED_VALUES = {
  'dt-question-color':        { type: 'rgba', r: [200,220], g: [158,178], b: [73,93], a: [0.85,0.95], family: 'gold' },
  'dt-question-color-covert': { type: 'rgba', r: [190,200], g: [55,65], b: [55,65], a: [0.80,0.90], family: 'red' },
  'dt-question-weight':       { type: 'literal', value: '600' },
  'dt-question-spacing':      { type: 'literal', value: '0.015em' },
  'dt-question-size-section': { type: 'literal', value: '1.0em' },
  'dt-question-size-protocol':{ type: 'literal', value: '0.85em' },
  'dt-question-border':       { type: 'rgba', r: [200,220], g: [158,178], b: [73,93], a: [0.30,0.40], family: 'gold' },
  'dt-question-border-covert':{ type: 'rgba', r: [135,145], g: [35,45], b: [35,45], a: [0.30,0.40], family: 'red' },
  'dt-question-bg':           { type: 'rgba', r: [200,220], g: [158,178], b: [73,93], a: [0.02,0.08], family: 'gold' },
  'dt-question-bg-covert':    { type: 'rgba', r: [135,145], g: [35,45], b: [35,45], a: [0.02,0.08], family: 'red' },
};

const QUESTION_CONTAINERS = [
  { cls: 'protocol-question', desc: 'Protocol question container' },
  { cls: 'dri-question-block', desc: 'Homepage DRI question block' },
  { cls: 'exec-inline-question', desc: 'Executive inline question', template: true },
];

class ScientificColorValidator {
  constructor(cssContent) {
    this.css = cssContent;
    this.lines = cssContent.split('\n');
    this.findings = [];
    this.stats = {
      tokensValidated: 0,
      maturityLevels: 0,
      icuaeGrades: 0,
      covertOverrides: 0,
      dtQuestionTokens: 0,
      verdictBadges: 0,
      semanticChecks: 0,
    };
  }

  validate() {
    this.validateStatusTokensDefined();
    this.validateAccentTokensDefined();
    this.validateMaturitySpectrum();
    this.validateICuAESpectrum();
    this.validateSemanticIntegrity();
    this.validateCovertRedShift();
    this.validateDTQuestionSystem();
    this.validateVerdictBadges();
    this.validateGlassOpacityRanges();
    this.validateMathDisplay();
    this.validateCrossModeCoverage();
    return this.report();
  }

  addFinding(severity, category, message, line, context) {
    this.findings.push({ severity, category, message, line, context });
  }

  hexToRgb(hex) {
    hex = hex.replace('#', '');
    if (hex.length === 3) hex = hex[0]+hex[0]+hex[1]+hex[1]+hex[2]+hex[2];
    return {
      r: parseInt(hex.substring(0, 2), 16),
      g: parseInt(hex.substring(2, 4), 16),
      b: parseInt(hex.substring(4, 6), 16),
    };
  }

  inRange(val, range) {
    return val >= range[0] && val <= range[1];
  }

  findLineNumber(pattern) {
    for (let i = 0; i < this.lines.length; i++) {
      if (pattern.test(this.lines[i])) return i + 1;
    }
    return null;
  }

  validateStatusTokensDefined() {
    Object.entries(STATUS_TOKENS).forEach(([token, spec]) => {
      const pattern = new RegExp(`--${token}:\\s*${spec.hex.replace('#', '#')}`, 'i');
      const found = pattern.test(this.css);
      const line = this.findLineNumber(new RegExp(`--${token}:`));
      this.stats.tokensValidated++;

      if (!found) {
        this.addFinding('error', 'TOKEN_DEFINITION',
          `Status token --${token} not found with expected value ${spec.hex}`,
          line, `Expected: --${token}: ${spec.hex}`);
      }
    });
  }

  validateAccentTokensDefined() {
    Object.entries(ACCENT_TOKENS).forEach(([token, spec]) => {
      const pattern = new RegExp(`--${token}:\\s*${spec.hex.replace('#', '#')}`, 'i');
      const found = pattern.test(this.css);
      const line = this.findLineNumber(new RegExp(`--${token}:`));
      this.stats.tokensValidated++;

      if (!found) {
        this.addFinding('error', 'TOKEN_DEFINITION',
          `Accent token --${token} not found with expected value ${spec.hex}`,
          line, `Expected: --${token}: ${spec.hex}`);
      }
    });
  }

  validateMaturitySpectrum() {
    Object.entries(MATURITY_SPECTRUM).forEach(([level, spec]) => {
      const escapedLevel = level.replace('-', '\\-');
      const dotPattern = new RegExp(
        `icae-level-${escapedLevel}(?![\\w-])[^{]*::before\\s*\\{([^}]+)\\}`, 'g'
      );
      let match;
      let found = false;

      while ((match = dotPattern.exec(this.css)) !== null) {
        found = true;
        this.stats.maturityLevels++;
        const props = match[1];

        const rgbaMatch = props.match(/background:\s*(?:linear-gradient\([^,]+,\s*)?rgba\(\s*(\d+),\s*(\d+),\s*(\d+)/);
        if (rgbaMatch) {
          const r = parseInt(rgbaMatch[1]);
          const g = parseInt(rgbaMatch[2]);
          const b = parseInt(rgbaMatch[3]);

          if (!this.inRange(r, spec.r) || !this.inRange(g, spec.g) || !this.inRange(b, spec.b)) {
            const line = this.findLineNumber(new RegExp(`icae-level-${escapedLevel}(?![\\w-])[^{]*::before`));
            this.addFinding('error', 'MATURITY_SPECTRUM',
              `ICAE ${spec.name} dot color rgb(${r},${g},${b}) outside ${spec.family} family range`,
              line, `Expected R:${spec.r} G:${spec.g} B:${spec.b}`);
          }
        }
      }

      if (!found) {
        this.addFinding('warn', 'MATURITY_SPECTRUM',
          `No ::before dot found for ICAE level "${level}" (${spec.name})`,
          null, 'Missing glass dot definition');
      }
    });
  }

  validateICuAESpectrum() {
    Object.entries(ICUAE_SPECTRUM).forEach(([grade, spec]) => {
      const dotPattern = new RegExp(
        `icuae-badge-${grade}\\s+\\.icuae-dot\\s*\\{([^}]+)\\}`, 'g'
      );
      let match;
      let found = false;

      while ((match = dotPattern.exec(this.css)) !== null) {
        found = true;
        this.stats.icuaeGrades++;
        const props = match[1];

        const rgbaMatch = props.match(/background:\s*rgba\(\s*(\d+),\s*(\d+),\s*(\d+)/);
        if (rgbaMatch) {
          const r = parseInt(rgbaMatch[1]);
          const g = parseInt(rgbaMatch[2]);
          const b = parseInt(rgbaMatch[3]);

          if (!this.inRange(r, spec.r) || !this.inRange(g, spec.g) || !this.inRange(b, spec.b)) {
            const line = this.findLineNumber(new RegExp(`icuae-badge-${grade}\\s+\\.icuae-dot`));
            this.addFinding('error', 'ICUAE_SPECTRUM',
              `ICuAE ${spec.name} dot color rgb(${r},${g},${b}) outside ${spec.family} family range`,
              line, `Expected R:${spec.r} G:${spec.g} B:${spec.b}`);
          }
        }
      }

      if (!found) {
        this.addFinding('warn', 'ICUAE_SPECTRUM',
          `No .icuae-dot found for ICuAE grade "${grade}" (${spec.name})`,
          null, 'Missing glass dot definition');
      }
    });
  }

  validateSemanticIntegrity() {
    const semanticPairs = [
      { context: 'success', wrongFamily: 'red',   wrongRange: { r: [200,255], g: [40,120], b: [40,120] } },
      { context: 'danger',  wrongFamily: 'green', wrongRange: { r: [40,100],  g: [150,220], b: [50,120] } },
      { context: 'warning', wrongFamily: 'blue',  wrongRange: { r: [60,120],  g: [150,230], b: [220,255] } },
      { context: 'info',    wrongFamily: 'red',   wrongRange: { r: [200,255], g: [40,120], b: [40,120] } },
    ];

    this.lines.forEach((line, idx) => {
      if (line.trim().startsWith('/*') || line.trim().startsWith('*')) return;
      if (/covert-mode/.test(line)) return;

      semanticPairs.forEach(pair => {
        if (!line.includes(pair.context)) return;

        const rgbaMatches = line.matchAll(/rgba\(\s*(\d+),\s*(\d+),\s*(\d+)/g);
        for (const m of rgbaMatches) {
          const r = parseInt(m[1]), g = parseInt(m[2]), b = parseInt(m[3]);
          if (this.inRange(r, pair.wrongRange.r) &&
              this.inRange(g, pair.wrongRange.g) &&
              this.inRange(b, pair.wrongRange.b)) {
            this.stats.semanticChecks++;
            this.addFinding('error', 'SEMANTIC_INTEGRITY',
              `${pair.wrongFamily} color in "${pair.context}" context — semantic inversion`,
              idx + 1, line.trim().substring(0, 100));
          }
        }
      });
    });

    this.stats.semanticChecks += this.lines.length;
  }

  validateCovertRedShift() {
    const covertPatterns = [
      /body\.covert-mode\s+\.icae-level-[\w-]+\s*\{([^}]+)\}/g,
      /body\.covert-mode\s+\.icuae-badge[\w-]*\s+\.icuae-dot\s*\{([^}]+)\}/g,
      /body\.covert-mode\s+\.icae-level-[\w-]+::before\s*\{([^}]+)\}/g,
    ];

    covertPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(this.css)) !== null) {
        this.stats.covertOverrides++;
        const props = match[1];

        const rgbaMatches = [...props.matchAll(/rgba\(\s*(\d+),\s*(\d+),\s*(\d+)/g)];
        rgbaMatches.forEach(rm => {
          const r = parseInt(rm[1]);
          const g = parseInt(rm[2]);
          const b = parseInt(rm[3]);

          if (r < 30 && g < 30 && b < 30) return;

          const isRedShifted = r >= g && r >= b;
          if (!isRedShifted) {
            const line = this.findLineNumber(new RegExp(
              match[0].substring(0, 40).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            ));
            this.addFinding('error', 'COVERT_RED_SHIFT',
              `Covert element NOT red-shifted: rgb(${r},${g},${b}) — red channel should dominate`,
              line, 'Scotopic vision requires red spectrum dominance');
          }
        });
      }
    });

    const covertDTQuestion = /body\.covert-mode\s+\.dt-question/.test(this.css);
    if (!covertDTQuestion) {
      this.addFinding('warn', 'COVERT_RED_SHIFT',
        '.dt-question missing covert-mode palette swap',
        null, 'Questions should shift to muted palette in covert mode');
    }
  }

  validateDTQuestionSystem() {
    DT_QUESTION_TOKENS.forEach(token => {
      const pattern = new RegExp(`--${token}:`);
      const found = pattern.test(this.css);
      const line = this.findLineNumber(pattern);
      this.stats.dtQuestionTokens++;

      if (!found) {
        this.addFinding('error', 'DT_QUESTION',
          `Question token --${token} not defined in :root`,
          null, 'R004/R006 requires complete token set');
      } else {
        this.stats.tokensValidated++;
      }
    });

    const hasBase = /\.dt-question\s*\{/.test(this.css);
    const hasSection = /\.dt-question--section\s*\{/.test(this.css);
    const hasProtocol = /\.dt-question--protocol\s*\{/.test(this.css);

    if (!hasBase) this.addFinding('error', 'DT_QUESTION', '.dt-question base class not defined', null, null);
    if (!hasSection) this.addFinding('error', 'DT_QUESTION', '.dt-question--section modifier not defined', null, null);
    if (!hasProtocol) this.addFinding('error', 'DT_QUESTION', '.dt-question--protocol modifier not defined', null, null);

    this.validateDTQuestionTokenValues();
    this.validateQuestionContainerCoverage();
  }

  validateDTQuestionTokenValues() {
    Object.entries(DT_QUESTION_EXPECTED_VALUES).forEach(([token, spec]) => {
      const valPattern = new RegExp(`--${token}:\\s*([^;]+);`);
      const match = valPattern.exec(this.css);
      if (!match) return;

      const rawValue = match[1].trim();
      const line = this.findLineNumber(new RegExp(`--${token}:`));

      if (spec.type === 'literal') {
        if (rawValue !== spec.value) {
          this.addFinding('error', 'DT_QUESTION_VALUE',
            `--${token} expected "${spec.value}" but found "${rawValue}"`,
            line, `Token value mismatch`);
        }
      } else if (spec.type === 'rgba') {
        const rgbaMatch = rawValue.match(/rgba\(\s*(\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\s*\)/);
        if (!rgbaMatch) {
          this.addFinding('warn', 'DT_QUESTION_VALUE',
            `--${token} expected rgba() format but found "${rawValue}"`,
            line, `Cannot validate non-rgba value`);
          return;
        }
        const r = parseInt(rgbaMatch[1]), g = parseInt(rgbaMatch[2]);
        const b = parseInt(rgbaMatch[3]), a = parseFloat(rgbaMatch[4]);

        let issues = [];
        if (!this.inRange(r, spec.r)) issues.push(`R=${r} outside [${spec.r}]`);
        if (!this.inRange(g, spec.g)) issues.push(`G=${g} outside [${spec.g}]`);
        if (!this.inRange(b, spec.b)) issues.push(`B=${b} outside [${spec.b}]`);
        if (!this.inRange(a, spec.a)) issues.push(`A=${a} outside [${spec.a}]`);

        if (issues.length > 0) {
          this.addFinding('error', 'DT_QUESTION_VALUE',
            `--${token} (${spec.family}) value rgba(${r},${g},${b},${a}) out of range`,
            line, issues.join('; '));
        }
      }

      this.stats.tokensValidated++;
    });
  }

  validateQuestionContainerCoverage() {
    QUESTION_CONTAINERS.forEach(({ cls, desc, template }) => {
      if (template) return;

      const standardExists = new RegExp(`\\.${cls}[^{]*\\{`).test(this.css);
      const covertExists = new RegExp(`body\\.covert-mode\\s+\\.${cls}|body\\.covert-mode\\s[\\s\\S]{0,200}\\.${cls}`).test(this.css);

      if (standardExists && !covertExists) {
        this.addFinding('warn', 'DT_QUESTION_CONTAINER',
          `${desc} (.${cls}) defined in standard mode but no covert override`,
          null, 'R006 requires covert palette swap for all question containers');
      }

      if (standardExists) {
        const rule = this.css.match(new RegExp(`\\.${cls}\\s*\\{([^}]+)\\}`));
        if (rule) {
          const usesTokenBorder = /var\(--dt-question-border(?:-covert)?\)/.test(rule[1]);
          const usesTokenBg = /var\(--dt-question-bg(?:-covert)?\)/.test(rule[1]);
          const hasBorderProp = /border(?:-left)?(?:-color)?:/.test(rule[1]);
          const hasBgProp = /background:/.test(rule[1]);
          if (hasBorderProp && !usesTokenBorder) {
            this.addFinding('info', 'DT_QUESTION_CONTAINER',
              `${desc} (.${cls}) uses hardcoded border color instead of --dt-question-border token`,
              null, 'Consider migrating to dt-question token');
          }
          if (hasBgProp && !usesTokenBg) {
            this.addFinding('info', 'DT_QUESTION_CONTAINER',
              `${desc} (.${cls}) uses hardcoded background instead of --dt-question-bg token`,
              null, 'Consider migrating to dt-question token');
          }
        }
      }
    });
  }

  validateVerdictBadges() {
    const verdictMap = {
      'verdict-success': { family: 'green',  rMin: 20, gMin: 100, bMax: 100 },
      'verdict-info':    { family: 'blue',   rMax: 120, gMin: 130, bMin: 200 },
      'verdict-warning': { family: 'amber',  rMin: 200, gMin: 150, bMax: 80  },
      'verdict-danger':  { family: 'red',    rMin: 180, gMax: 100, bMax: 100 },
      'verdict-secondary': { family: 'gray' },
    };

    Object.entries(verdictMap).forEach(([cls, spec]) => {
      const pattern = new RegExp(`\\.intel-verdict-answer\\.${cls}\\s*\\{([^}]+)\\}`);
      const match = pattern.exec(this.css);
      if (!match) {
        this.addFinding('warn', 'VERDICT_BADGE',
          `Verdict badge ".${cls}" not found`, null, 'Expected in intel-verdict system');
        return;
      }
      this.stats.tokensValidated++;
      this.stats.verdictBadges++;

      const colorMatch = match[1].match(/color:\s*#([0-9a-fA-F]{6})/);
      if (colorMatch && spec.family !== 'gray') {
        const { r, g, b } = this.hexToRgb(colorMatch[1]);
        let valid = true;
        if (spec.rMin !== undefined && r < spec.rMin) valid = false;
        if (spec.rMax !== undefined && r > spec.rMax) valid = false;
        if (spec.gMin !== undefined && g < spec.gMin) valid = false;
        if (spec.gMax !== undefined && g > spec.gMax) valid = false;
        if (spec.bMin !== undefined && b < spec.bMin) valid = false;
        if (spec.bMax !== undefined && b > spec.bMax) valid = false;
        if (!valid) {
          const line = this.findLineNumber(new RegExp(`\\.intel-verdict-answer\\.${cls}`));
          this.addFinding('error', 'VERDICT_BADGE',
            `${cls} text color #${colorMatch[1]} doesn't match ${spec.family} family`,
            line, `rgb(${r},${g},${b})`);
        }
      }
    });
  }

  validateGlassOpacityRanges() {
    const glassPatterns = [
      { name: 'ICAE dot',    pattern: /icae-level-[\w-]+::before\s*\{([^}]+)\}/g },
      { name: 'ICuAE dot',   pattern: /icuae-badge-[\w-]+\s+\.icuae-dot\s*\{([^}]+)\}/g },
      { name: 'Answer badge', pattern: /section-answer[\w-]*\s*\{([^}]+)\}/g },
    ];

    glassPatterns.forEach(({ name, pattern }) => {
      let match;
      while ((match = pattern.exec(this.css)) !== null) {
        const props = match[1];
        if (/covert-mode/.test(this.css.substring(Math.max(0, match.index - 80), match.index))) continue;

        const bgLine = props.match(/background:\s*[^;]+/);
        if (bgLine) {
          const bgAlphas = [...bgLine[0].matchAll(/rgba\(\s*\d+,\s*\d+,\s*\d+,\s*([\d.]+)\s*\)/g)];
          bgAlphas.forEach(om => {
            const alpha = parseFloat(om[1]);
            if (alpha > 0.65) {
              const line = this.findLineNumber(new RegExp(
                match[0].substring(0, 30).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
              ));
              this.addFinding('warn', 'GLASS_OPACITY',
                `${name} background rgba alpha ${alpha} > 0.65 — may not appear glass-like`,
                line, 'Glass treatment requires translucency (alpha ≤ 0.65)');
            }
          });
        }
      }
    });
  }

  validateMathDisplay() {
    const hasMathDisplay = /\.math-display\s*\{/.test(this.css);
    if (!hasMathDisplay) {
      this.addFinding('error', 'MATH_DISPLAY',
        '.math-display chalkboard treatment not defined', null,
        'KaTeX display blocks require gradient bg + cobalt border');
    }

    const hasMathCopyBtn = /\.math-copy-btn\s*\{/.test(this.css);
    if (!hasMathCopyBtn) {
      this.addFinding('error', 'MATH_DISPLAY',
        '.math-copy-btn not defined', null,
        'Copy-to-clipboard button for math formulas');
    }

    const hasCovertMathDisplay = /body\.covert-mode\s+\.math-display/.test(this.css);
    if (!hasCovertMathDisplay) {
      this.addFinding('error', 'MATH_DISPLAY',
        'Covert mode .math-display override not found', null,
        'Math display blocks need red accent border in covert mode');
    }

    const hasPrintMathDisplay = /@media\s+print[\s\S]*?\.math-display/.test(this.css);
    if (!hasPrintMathDisplay) {
      this.addFinding('warn', 'MATH_DISPLAY',
        'No @media print rule found for .math-display', null,
        'Print stylesheet should use light background');
    }

    this.stats.tokensValidated += 4;
  }

  validateCrossModeCoverage() {
    const glassElements = [
      'icae-hero-maturity-badge',
      'icae-hero-maturity',
      'section-answer',
      'btn-analyze',
    ];

    glassElements.forEach(cls => {
      const darkExists = new RegExp(`\\.${cls}[^{]*\\{`).test(this.css);
      const covertExists = new RegExp(`body\\.covert-mode\\s+\\.${cls}|body\\.covert-mode\\s[\\s\\S]{0,200}\\.${cls}`).test(this.css);

      if (darkExists && !covertExists) {
        this.addFinding('info', 'CROSS_MODE',
          `Glass element ".${cls}" defined in dark mode but no covert override found`,
          null, 'Consider whether covert red-shift is needed');
      }
    });
  }

  report() {
    const errors = this.findings.filter(f => f.severity === 'error');
    const warnings = this.findings.filter(f => f.severity === 'warn');
    const infos = this.findings.filter(f => f.severity === 'info');

    let output = '';
    output += '═══════════════════════════════════════════════════════════════\n';
    output += '  DNS Tool — Scientific Color Validation Report (R010)\n';
    output += `  File: static/css/custom.css\n`;
    output += `  Date: ${new Date().toISOString().split('T')[0]}\n`;
    output += '═══════════════════════════════════════════════════════════════\n\n';

    output += '── TOKEN INVENTORY ─────────────────────────────────────────\n';
    output += `  Status tokens:       ${Object.keys(STATUS_TOKENS).length} defined\n`;
    output += `  Accent tokens:       ${Object.keys(ACCENT_TOKENS).length} defined\n`;
    output += `  DT-Question tokens:  ${this.stats.dtQuestionTokens} checked\n`;
    output += `  Tokens validated:    ${this.stats.tokensValidated}\n\n`;

    output += '── SPECTRUM VALIDATION ─────────────────────────────────────\n';
    output += `  ICAE maturity dots:  ${this.stats.maturityLevels} validated\n`;
    output += `  ICuAE grade dots:    ${this.stats.icuaeGrades} validated\n`;
    output += `  Verdict badges:      ${this.stats.verdictBadges} validated\n`;
    output += `  Covert overrides:    ${this.stats.covertOverrides} red-shift checked\n`;
    output += `  Semantic line scans: ${this.stats.semanticChecks}\n`;
    output += `  Question containers: ${QUESTION_CONTAINERS.length} checked\n\n`;

    output += `  Errors:   ${errors.length}\n`;
    output += `  Warnings: ${warnings.length}\n`;
    output += `  Info:     ${infos.length}\n\n`;

    if (errors.length > 0) {
      output += '── ERRORS (color mapping violations) ───────────────────────\n';
      errors.forEach(f => {
        output += `  ✗ [${f.category}] ${f.message}\n`;
        if (f.line) output += `    Line ${f.line}: ${f.context}\n`;
        if (f.context && !f.line) output += `    ${f.context}\n`;
        output += '\n';
      });
    }

    if (warnings.length > 0) {
      output += '── WARNINGS (missing coverage) ─────────────────────────────\n';
      warnings.forEach(f => {
        output += `  ⚠ [${f.category}] ${f.message}\n`;
        if (f.context) output += `    ${f.context}\n`;
        output += '\n';
      });
    }

    if (infos.length > 0) {
      output += '── INFO (suggestions) ──────────────────────────────────────\n';
      infos.forEach(f => {
        output += `  ○ [${f.category}] ${f.message}\n`;
        if (f.context) output += `    ${f.context}\n`;
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
const validator = new ScientificColorValidator(cssContent);
const result = validator.validate();
console.log(result.output);
process.exit(result.exitCode);
