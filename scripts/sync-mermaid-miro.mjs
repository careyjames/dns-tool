#!/usr/bin/env node
import { readFileSync, writeFileSync, existsSync } from 'fs';

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

function saveConfig(config) {
  writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n', 'utf8');
}

function getToken() {
  const token = process.env.MIRO_API_TOKEN;
  if (!token) {
    console.error('\n  [ERROR] MIRO_API_TOKEN secret not set.');
    console.error('  Generate one at: https://miro.com/app/settings/user-profile/apps');
    console.error('  Then add it as a Replit secret.\n');
    process.exit(1);
  }
  return token;
}

async function miroApi(path, options = {}) {
  const token = getToken();
  const url = `https://api.miro.com/v2${path}`;
  const headers = {
    'Authorization': `Bearer ${token}`,
    'Accept': 'application/json',
    ...options.headers,
  };
  const resp = await fetch(url, { ...options, headers });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw new Error(`Miro API ${resp.status}: ${resp.statusText} — ${body}`);
  }
  if (options.method === 'DELETE') return null;
  return resp.json();
}

async function deleteWidget(boardId, widgetId) {
  await miroApi(`/boards/${boardId}/images/${widgetId}`, { method: 'DELETE' });
}

async function uploadSvgToBoard(boardId, svgPath, title, position) {
  const token = getToken();
  const url = `https://api.miro.com/v2/boards/${boardId}/images`;

  const svgContent = readFileSync(svgPath);
  const boundary = '----MiroUpload' + Date.now();
  const metadata = JSON.stringify({
    title: title,
    position: { x: position.x, y: position.y, origin: 'center' },
  });

  const parts = [];
  parts.push(`--${boundary}\r\n`);
  parts.push(`Content-Disposition: form-data; name="resource"; filename="${title.replace(/[^a-zA-Z0-9._-]/g, '_')}.svg"\r\n`);
  parts.push(`Content-Type: image/svg+xml\r\n\r\n`);
  parts.push(svgContent);
  parts.push(`\r\n--${boundary}\r\n`);
  parts.push(`Content-Disposition: form-data; name="data"\r\n`);
  parts.push(`Content-Type: application/json\r\n\r\n`);
  parts.push(metadata);
  parts.push(`\r\n--${boundary}--\r\n`);

  const body = Buffer.concat(parts.map(p => typeof p === 'string' ? Buffer.from(p) : p));

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`,
      'Accept': 'application/json',
    },
    body: body,
  });

  if (!resp.ok) {
    const respBody = await resp.text().catch(() => '');
    throw new Error(`Miro image upload ${resp.status}: ${resp.statusText} — ${respBody}`);
  }

  return resp.json();
}

async function getWidgetPosition(boardId, widgetId) {
  try {
    const widget = await miroApi(`/boards/${boardId}/images/${widgetId}`);
    return { x: widget.position.x, y: widget.position.y };
  } catch {
    return null;
  }
}

async function listAllBoardImages(boardId) {
  const items = [];
  let cursor = null;
  do {
    const qs = cursor ? `?cursor=${cursor}&type=image&limit=50` : '?type=image&limit=50';
    const resp = await miroApi(`/boards/${boardId}/items${qs}`);
    items.push(...(resp.data || []));
    cursor = resp.cursor || null;
  } while (cursor);
  return items;
}

async function cleanOrphans(config) {
  const boardId = config.miro.board_id;
  console.log(`\n  Orphan Cleanup Mode`);
  console.log(`  Board: ${boardId}`);
  console.log(`${'='.repeat(55)}\n`);

  const knownIds = new Set();
  for (const info of Object.values(config.miro.diagrams)) {
    if (info.miro_widget_id) knownIds.add(info.miro_widget_id);
  }
  for (const info of Object.values(config.miro.additional_diagrams || {})) {
    if (info.miro_widget_id) knownIds.add(info.miro_widget_id);
  }

  const allImages = await listAllBoardImages(boardId);
  let removed = 0;

  for (const img of allImages) {
    if (!knownIds.has(img.id)) {
      try {
        await deleteWidget(boardId, img.id);
        console.log(`  [CLEAN] Removed orphan image ${img.id} (${img.data?.title || 'untitled'})`);
        removed++;
      } catch (err) {
        console.log(`  [FAIL] Could not remove ${img.id}: ${err.message}`);
      }
    }
  }

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Cleanup: ${removed} orphan(s) removed, ${allImages.length - removed} tracked images kept`);
  console.log(`${'='.repeat(55)}\n`);
}

async function main() {
  const args = process.argv.slice(2);
  const cleanMode = args.includes('--clean');

  const config = loadConfig();
  const version = getVersion();
  const boardId = config.miro.board_id;

  if (cleanMode) {
    await cleanOrphans(config);
    return;
  }

  console.log(`\n  Mermaid → Miro Sync (idempotent)`);
  console.log(`  Version: ${version}`);
  console.log(`  Board: ${boardId}`);
  console.log(`${'='.repeat(55)}\n`);

  const diagrams = config.miro.diagrams;
  let synced = 0;
  let failed = 0;
  let defaultYOffset = 0;

  for (const [name, info] of Object.entries(diagrams)) {
    const svgPath = info.svg_output;

    if (!existsSync(svgPath)) {
      console.log(`  [SKIP] ${name} — SVG not found at ${svgPath}`);
      console.log(`         Run: bash scripts/render-diagrams.sh`);
      failed++;
      continue;
    }

    try {
      let position = { x: 5000, y: defaultYOffset };

      if (info.miro_widget_id) {
        const existingPos = await getWidgetPosition(boardId, info.miro_widget_id);
        if (existingPos) {
          position = existingPos;
          console.log(`  [DEL] ${name} — removing old widget ${info.miro_widget_id}`);
          await deleteWidget(boardId, info.miro_widget_id);
        } else {
          console.log(`  [INFO] ${name} — old widget ${info.miro_widget_id} not found, creating fresh`);
        }
      }

      const result = await uploadSvgToBoard(boardId, svgPath, `${info.miro_title} (v${version})`, position);

      config.miro.diagrams[name].miro_widget_id = result.id;
      console.log(`  [OK] ${name} → Miro image ${result.id}`);
      synced++;
      defaultYOffset += 800;
    } catch (err) {
      console.log(`  [FAIL] ${name}: ${err.message}`);
      failed++;
    }
  }

  saveConfig(config);
  console.log(`  [SAVED] pipeline-config.json updated with new widget IDs`);

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Result: ${synced} synced, ${failed} failed`);
  console.log(`${'='.repeat(55)}\n`);

  process.exit(failed > 0 ? 1 : 0);
}

main();
