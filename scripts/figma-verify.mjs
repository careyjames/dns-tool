#!/usr/bin/env node
import { readFileSync, statSync, existsSync } from 'fs';

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

async function figmaGet(path, token) {
  const resp = await fetch(`https://api.figma.com/v1${path}`, {
    headers: { 'X-Figma-Token': token }
  });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Figma API ${resp.status}: ${resp.statusText} — ${body}`);
  }
  return resp.json();
}

function collectNodeNames(node, depth = 0, results = []) {
  if (node.name) {
    results.push({ name: node.name, type: node.type, id: node.id, depth });
  }
  if (node.children) {
    for (const child of node.children) {
      collectNodeNames(child, depth + 1, results);
    }
  }
  return results;
}

async function main() {
  const config = loadConfig();
  const version = getVersion();
  const token = process.env.FIGMA_PAT;

  console.log(`\n  Figma Verification Script`);
  console.log(`  Version: ${version}`);
  console.log(`${'='.repeat(55)}\n`);

  if (!token) {
    console.log('  [ERROR] FIGMA_PAT environment variable not set');
    process.exit(1);
  }

  const fileKey = config.figma.file_key;
  if (!fileKey) {
    console.log('  [INFO] No Figma file_key configured in pipeline-config.json');
    console.log('  [INFO] To enable verification:');
    console.log('    1. Create a Figma file and note its key from the URL');
    console.log('       (https://figma.com/file/FILE_KEY/...)');
    console.log('    2. Set "file_key" in scripts/pipeline-config.json');
    console.log('');
    console.log('  Verifying FIGMA_PAT access instead...\n');

    try {
      const me = await figmaGet('/me', token);
      console.log(`  [OK] Figma token valid — user: ${me.handle} (${me.email})`);
      console.log(`  [OK] Token has access to Figma API\n`);
    } catch (err) {
      console.log(`  [FAIL] Figma token invalid: ${err.message}\n`);
      process.exit(1);
    }

    console.log('  Checking local asset bundle...\n');
    checkLocalAssets(config);
    return;
  }

  try {
    console.log(`  Checking Figma file: ${fileKey}\n`);
    const file = await figmaGet(`/files/${fileKey}?depth=2`, token);
    console.log(`  [OK] File: "${file.name}"`);
    console.log(`  [OK] Last modified: ${file.lastModified}`);
    console.log(`  [OK] Version: ${file.version}\n`);

    const targetPage = config.figma.page_name;
    const pages = file.document.children || [];
    const archPage = pages.find(p => p.name === targetPage);

    if (archPage) {
      console.log(`  [OK] Page "${targetPage}" found`);
      const nodes = collectNodeNames(archPage);
      console.log(`  [OK] ${nodes.length} nodes on page\n`);

      const diagrams = config.miro.diagrams;
      let matched = 0;
      let unmatched = 0;

      for (const [name, info] of Object.entries(diagrams)) {
        const found = nodes.find(n =>
          n.name.toLowerCase().includes(name.replace(/-/g, ' ')) ||
          n.name.toLowerCase().includes(name.replace(/-/g, '-'))
        );
        if (found) {
          console.log(`  [MATCH] ${name} → "${found.name}" (${found.type})`);
          matched++;
        } else {
          console.log(`  [DRIFT] ${name} — not found in Figma`);
          unmatched++;
        }
      }

      console.log(`\n  Figma sync: ${matched} matched, ${unmatched} drifted`);
    } else {
      console.log(`  [DRIFT] Page "${targetPage}" not found in Figma file`);
      console.log(`  Available pages: ${pages.map(p => p.name).join(', ')}`);
    }
  } catch (err) {
    console.log(`  [ERROR] ${err.message}`);
    process.exit(1);
  }

  console.log('');
  checkLocalAssets(config);
}

function checkLocalAssets(config) {
  const diagrams = config.miro.diagrams;
  let ok = 0;
  let stale = 0;

  console.log('  Local SVG freshness check:\n');

  for (const [name, info] of Object.entries(diagrams)) {
    const mmdPath = info.mermaid_source;
    const svgPath = info.svg_output;

    if (!existsSync(svgPath)) {
      console.log(`  [MISSING] ${svgPath}`);
      stale++;
      continue;
    }
    if (!existsSync(mmdPath)) {
      console.log(`  [MISSING] ${mmdPath}`);
      stale++;
      continue;
    }

    const mmdTime = statSync(mmdPath).mtimeMs;
    const svgTime = statSync(svgPath).mtimeMs;

    if (mmdTime > svgTime) {
      console.log(`  [STALE] ${name} — .mmd newer than .svg (needs re-render)`);
      stale++;
    } else {
      const age = Math.round((Date.now() - svgTime) / 86400000);
      console.log(`  [OK] ${name} — SVG current (${age}d old)`);
      ok++;
    }
  }

  const bundlePath = config.export.manifest_file;
  if (existsSync(bundlePath)) {
    const manifest = JSON.parse(readFileSync(bundlePath, 'utf8'));
    const bundleAge = Math.round((Date.now() - new Date(manifest.generated_at).getTime()) / 86400000);
    if (manifest.app_version !== getVersion()) {
      console.log(`\n  [DRIFT] Asset bundle version (${manifest.app_version}) != app version (${getVersion()})`);
      stale++;
    } else {
      console.log(`\n  [OK] Asset bundle matches app version (${bundleAge}d old)`);
    }
  } else {
    console.log(`\n  [INFO] No asset bundle found — run: node scripts/figma-asset-bundle.mjs`);
  }

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Result: ${ok} current, ${stale} stale/missing`);
  console.log(`${'='.repeat(55)}\n`);

  process.exit(stale > 0 ? 1 : 0);
}

main();
