#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync, readdirSync, statSync } from 'fs';
import { join, basename } from 'path';

const CONFIG_PATH = 'scripts/pipeline-config.json';
const VERSION_RE = /Version\s*=\s*"([^"]+)"/;

function getVersion() {
  try {
    const src = readFileSync('go-server/internal/config/config.go', 'utf8');
    const m = src.match(VERSION_RE);
    return m ? m[1] : 'unknown';
  } catch { return 'unknown'; }
}

function loadConfig() {
  return JSON.parse(readFileSync(CONFIG_PATH, 'utf8'));
}

function ensureDir(dir) {
  mkdirSync(dir, { recursive: true });
}

function main() {
  const config = loadConfig();
  const version = getVersion();
  const bundleDir = config.export.bundle_dir;
  const diagramsDir = join(bundleDir, 'diagrams');
  const metaDir = join(bundleDir, 'meta');

  console.log(`\n  Figma Asset Bundle Generator`);
  console.log(`  Version: ${version}`);
  console.log(`${'='.repeat(55)}\n`);

  ensureDir(diagramsDir);
  ensureDir(metaDir);

  const diagrams = config.miro.diagrams;
  const bundled = [];
  let copied = 0;
  let missing = 0;

  for (const [name, info] of Object.entries(diagrams)) {
    const svgPath = info.svg_output;
    const destPath = join(diagramsDir, `${name}.svg`);

    if (existsSync(svgPath)) {
      copyFileSync(svgPath, destPath);
      const stat = statSync(svgPath);
      bundled.push({
        name,
        title: info.miro_title,
        mermaid_source: info.mermaid_source,
        svg_file: `diagrams/${name}.svg`,
        size_bytes: stat.size,
        miro_widget_id: info.miro_widget_id
      });
      copied++;
      console.log(`  [OK] ${name}.svg (${(stat.size / 1024).toFixed(1)} KB)`);
    } else {
      missing++;
      console.log(`  [MISSING] ${svgPath}`);
    }
  }

  const manifest = {
    generated_at: new Date().toISOString(),
    app_version: version,
    diagram_count: copied,
    figma_target: {
      file_key: config.figma.file_key,
      page_name: config.figma.page_name
    },
    miro_board: {
      board_id: config.miro.board_id,
      board_url: config.miro.board_url
    },
    diagrams: bundled,
    instructions: [
      'Open your Figma file (or create one)',
      'Create a page named "Architecture Diagrams"',
      'Drag the SVG files from the diagrams/ folder onto the canvas',
      'Arrange them in a grid layout matching the architecture page',
      'Each diagram name and Miro widget ID is in the manifest for traceability'
    ]
  };

  writeFileSync(config.export.manifest_file, JSON.stringify(manifest, null, 2));
  console.log(`\n  Manifest written: ${config.export.manifest_file}`);

  const readmePath = join(bundleDir, 'README.txt');
  const readme = [
    `DNS Tool — Figma Asset Bundle`,
    `Generated: ${manifest.generated_at}`,
    `App Version: ${version}`,
    ``,
    `This bundle contains ${copied} SVG diagrams ready for Figma import.`,
    ``,
    `INSTRUCTIONS:`,
    ...manifest.instructions.map((s, i) => `  ${i + 1}. ${s}`),
    ``,
    `DIAGRAMS:`,
    ...bundled.map(d => `  - ${d.name}: ${d.title}`),
    ``,
    `SOURCE OF TRUTH:`,
    `  Mermaid files: docs/diagrams/*.mmd`,
    `  Miro board: ${config.miro.board_url}`,
    `  Pipeline config: ${CONFIG_PATH}`,
    ``
  ].join('\n');
  writeFileSync(readmePath, readme);

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Result: ${copied} diagrams bundled, ${missing} missing`);
  console.log(`  Bundle: ${bundleDir}/`);
  console.log(`${'='.repeat(55)}\n`);

  process.exit(missing > 0 ? 1 : 0);
}

main();
