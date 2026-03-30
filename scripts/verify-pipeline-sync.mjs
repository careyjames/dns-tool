#!/usr/bin/env node
import { readFileSync, statSync, existsSync } from 'fs';
import { createHash } from 'crypto';

const CONFIG_PATH = 'scripts/pipeline-config.json';
const VERSION_RE = /Version\s*=\s*"([^"]+)"/;

let errors = 0;
let warnings = 0;
let passed = 0;

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

function sha256(filePath) {
  const data = readFileSync(filePath);
  return createHash('sha256').update(data).digest('hex').slice(0, 12);
}

function fileMtime(filePath) {
  return statSync(filePath).mtime;
}

function pass(msg) { passed++; console.log(`  \x1b[32m✓\x1b[0m ${msg}`); }
function warn(msg) { warnings++; console.log(`  \x1b[33m⚠\x1b[0m ${msg}`); }
function fail(msg) { errors++; console.log(`  \x1b[31m✗\x1b[0m ${msg}`); }
function info(msg) { console.log(`  \x1b[36mℹ\x1b[0m ${msg}`); }
function heading(msg) { console.log(`\n\x1b[1m${msg}\x1b[0m`); }

function verifyMermaidLayer(config) {
  heading('Layer 1: Mermaid Sources (Engineering Truth)');

  const diagrams = config.miro.diagrams;
  for (const [key, diag] of Object.entries(diagrams)) {
    const src = diag.mermaid_source;
    if (!existsSync(src)) {
      fail(`${key}: Mermaid source missing — ${src}`);
      continue;
    }

    const content = readFileSync(src, 'utf8');
    const lines = content.split('\n').filter(l => l.trim()).length;
    const hash = sha256(src);
    pass(`${key}: ${src} (${lines} lines, sha256:${hash})`);
  }
}

function verifySvgLayer(config) {
  heading('Layer 1→2: SVG Renders (Mermaid → Static Assets)');

  const diagrams = config.miro.diagrams;
  for (const [key, diag] of Object.entries(diagrams)) {
    const src = diag.mermaid_source;
    const svg = diag.svg_output;

    if (!existsSync(svg)) {
      fail(`${key}: SVG output missing — ${svg}`);
      continue;
    }

    const svgHash = sha256(svg);
    const svgSize = statSync(svg).size;

    if (existsSync(src)) {
      const srcMtime = fileMtime(src);
      const svgMtime = fileMtime(svg);
      if (srcMtime > svgMtime) {
        fail(`${key}: Mermaid source newer than SVG (drift detected — re-render needed)`);
        info(`  Source: ${srcMtime.toISOString()}`);
        info(`  SVG:    ${svgMtime.toISOString()}`);
      } else {
        pass(`${key}: SVG up to date (${(svgSize / 1024).toFixed(1)}KB, sha256:${svgHash})`);
      }
    } else {
      pass(`${key}: SVG exists (${(svgSize / 1024).toFixed(1)}KB, sha256:${svgHash})`);
    }
  }
}

async function miroGet(path, token) {
  const resp = await fetch(`https://api.miro.com/v2${path}`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  if (!resp.ok) throw new Error(`Miro API ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

async function verifyMiroLayer(config) {
  heading('Layer 2: Miro Board (Collaborative Workspace)');

  const miroToken = process.env.MIRO_API_TOKEN;
  const boardId = config.miro.board_id;

  if (!miroToken) {
    info('MIRO_API_TOKEN not set — config-only verification (no live drift detection)');

    const diagrams = config.miro.diagrams;
    for (const [key, diag] of Object.entries(diagrams)) {
      if (!diag.miro_widget_id) {
        warn(`${key}: No Miro widget ID configured`);
      } else {
        pass(`${key}: Miro widget mapped → ${diag.miro_widget_id} ("${diag.miro_title}")`);
      }
    }
  } else {
    info('MIRO_API_TOKEN set — live API verification');

    const diagrams = config.miro.diagrams;
    for (const [key, diag] of Object.entries(diagrams)) {
      if (!diag.miro_widget_id) {
        warn(`${key}: No Miro widget ID configured`);
        continue;
      }
      try {
        const item = await miroGet(`/boards/${boardId}/items/${diag.miro_widget_id}`, miroToken);
        const liveTitle = item.data?.content || item.data?.title || '(untitled)';
        const modified = item.modifiedAt || item.data?.modifiedAt || 'unknown';
        if (liveTitle.includes(diag.miro_title) || diag.miro_title.includes(liveTitle)) {
          pass(`${key}: Miro live ✓ title matches ("${liveTitle.slice(0, 60)}")`);
        } else {
          warn(`${key}: Miro title drift — config: "${diag.miro_title}" vs live: "${liveTitle.slice(0, 60)}"`);
        }
        info(`  Last modified: ${modified}`);
      } catch (err) {
        warn(`${key}: Miro API check failed — ${err.message}`);
      }
    }
  }

  const additional = config.miro.additional_diagrams || {};
  for (const [key, diag] of Object.entries(additional)) {
    if (diag.miro_widget_id) {
      pass(`${key}: Miro-native diagram → ${diag.miro_widget_id} ("${diag.miro_title}")`);
    }
  }

  const docs = config.miro.documents || {};
  pass(`Documents: ${Object.keys(docs).length} registered`);

  const tables = config.miro.tables || {};
  pass(`Tables: ${Object.keys(tables).length} registered`);
}

async function figmaGet(path, token) {
  const resp = await fetch(`https://api.figma.com/v1${path}`, {
    headers: { 'X-Figma-Token': token }
  });
  if (!resp.ok) throw new Error(`Figma API ${resp.status}: ${resp.statusText}`);
  return resp.json();
}

async function verifyFigmaLayer(config) {
  heading('Layer 3: Figma (Presentation Polish)');

  const figma = config.figma;
  if (!figma.file_key) {
    info('Figma file_key not configured — Figma layer not yet active');
    return;
  }

  const figmaToken = process.env.FIGMA_PAT;
  if (!figmaToken) {
    info('FIGMA_PAT not set — config-only verification (no live drift detection)');
  } else {
    info('FIGMA_PAT set — live API verification');
    try {
      const file = await figmaGet(`/files/${figma.file_key}?depth=1`, figmaToken);
      pass(`Figma file: "${file.name}" (last modified: ${file.lastModified})`);

      const targetPage = figma.page_name;
      const pages = file.document?.children || [];
      const found = pages.find(p => p.name === targetPage);
      if (found) {
        pass(`Target page "${targetPage}" exists in Figma file`);
      } else {
        warn(`Target page "${targetPage}" not found — available: ${pages.map(p => p.name).join(', ')}`);
      }
    } catch (err) {
      warn(`Figma API check failed — ${err.message}`);
    }
  }

  const bundleDir = config.export?.bundle_dir;
  if (bundleDir && existsSync(bundleDir)) {
    const manifest = config.export?.manifest_file;
    if (manifest && existsSync(manifest)) {
      const manifestData = JSON.parse(readFileSync(manifest, 'utf8'));
      pass(`Figma bundle manifest exists (${Object.keys(manifestData).length} entries)`);
    } else {
      warn('Figma bundle directory exists but no manifest.json');
    }
  } else {
    info('Figma bundle not yet generated');
  }
}

function verifyMinifiedAssets() {
  heading('Asset Freshness (Minified Files)');

  const pairs = [
    ['static/css/custom.css', 'static/css/custom.min.css'],
    ['static/js/main.js', 'static/js/main.min.js'],
    ['static/js/foundation.js', 'static/js/foundation.min.js'],
  ];

  for (const [src, min] of pairs) {
    if (!existsSync(src)) { warn(`Source missing: ${src}`); continue; }
    if (!existsSync(min)) { fail(`Minified missing: ${min}`); continue; }

    const srcMtime = fileMtime(src);
    const minMtime = fileMtime(min);

    if (srcMtime > minMtime) {
      fail(`STALE: ${min} older than ${src} — re-minify needed`);
      info(`  Source:   ${srcMtime.toISOString()}`);
      info(`  Minified: ${minMtime.toISOString()}`);
    } else {
      const ratio = ((statSync(min).size / statSync(src).size) * 100).toFixed(0);
      pass(`${min} up to date (${ratio}% of source)`);
    }
  }
}

function verifyPipelineConfig(config) {
  heading('Pipeline Configuration Integrity');

  if (!config.version) {
    warn('pipeline-config.json missing version field');
  } else {
    pass(`Config version: ${config.version}`);
  }

  if (!config.miro?.board_id) {
    fail('Missing miro.board_id');
  } else {
    pass(`Miro board: ${config.miro.board_id}`);
  }

  const diagramCount = Object.keys(config.miro?.diagrams || {}).length;
  const additionalCount = Object.keys(config.miro?.additional_diagrams || {}).length;
  pass(`Diagrams: ${diagramCount} Mermaid-sourced + ${additionalCount} Miro-native = ${diagramCount + additionalCount} total`);
}

async function main() {
  const version = getVersion();

  console.log(`${'═'.repeat(55)}`);
  console.log(`  Three-Layer Pipeline Sync Verification`);
  console.log(`  Version: ${version}`);
  console.log(`  Time:    ${new Date().toISOString()}`);
  console.log(`${'═'.repeat(55)}`);

  if (!existsSync(CONFIG_PATH)) {
    fail(`Pipeline config missing: ${CONFIG_PATH}`);
    process.exit(1);
  }

  const config = loadConfig();

  verifyPipelineConfig(config);
  verifyMermaidLayer(config);
  verifySvgLayer(config);
  await verifyMiroLayer(config);
  await verifyFigmaLayer(config);
  verifyMinifiedAssets();

  heading('Summary');
  console.log(`  Passed:   ${passed}`);
  console.log(`  Warnings: ${warnings}`);
  console.log(`  Errors:   ${errors}`);
  console.log();

  if (errors > 0) {
    console.log(`  \x1b[31mFAIL\x1b[0m — ${errors} error(s) detected`);
    process.exit(1);
  } else if (warnings > 0) {
    console.log(`  \x1b[33mWARN\x1b[0m — ${warnings} warning(s), no errors`);
    process.exit(0);
  } else {
    console.log(`  \x1b[32mPASS\x1b[0m — All layers in sync`);
    process.exit(0);
  }
}

main();
