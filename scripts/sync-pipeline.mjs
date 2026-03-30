#!/usr/bin/env node
import { execFileSync, execSync } from 'child_process';
import { readFileSync } from 'fs';

function hasMmdc() {
  try { execSync('command -v mmdc', { stdio: 'pipe' }); return true; }
  catch { return false; }
}

const VERSION_RE = /Version\s*=\s*"([^"]+)"/;

function getVersion() {
  try {
    const src = readFileSync('go-server/internal/config/config.go', 'utf8');
    const m = src.match(VERSION_RE);
    return m ? m[1] : 'unknown';
  } catch { return 'unknown'; }
}

function runStep(label, cmd, args) {
  const display = [cmd, ...args].join(' ');
  console.log(`\n  [${'='.repeat(45)}]`);
  console.log(`  Step: ${label}`);
  console.log(`  Command: ${display}`);
  console.log(`  [${'='.repeat(45)}]\n`);

  try {
    execFileSync(cmd, args, { stdio: 'inherit', timeout: 60000 });
    console.log(`\n  [OK] ${label} completed`);
    return true;
  } catch (err) {
    console.log(`\n  [FAIL] ${label} failed (exit ${err.status})`);
    return false;
  }
}

function main() {
  const version = getVersion();
  const startTime = Date.now();

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Three-Layer Pipeline Sync`);
  console.log(`  Version: ${version}`);
  console.log(`  Started: ${new Date().toISOString()}`);
  console.log(`${'='.repeat(55)}`);

  const steps = [
    { label: 'Render Mermaid Diagrams', cmd: 'bash', args: [hasMmdc() ? 'scripts/render-diagrams.sh' : 'scripts/render-diagrams-remote.sh'] },
    { label: 'CSS Minification', cmd: 'npx', args: ['csso', 'static/css/custom.css', '-o', 'static/css/custom.min.css'] },
    { label: 'Figma Asset Bundle', cmd: 'node', args: ['scripts/figma-asset-bundle.mjs'] },
    { label: 'Figma Verification', cmd: 'node', args: ['scripts/figma-verify.mjs'] },
  ];

  if (process.env.MIRO_API_TOKEN) {
    steps.splice(1, 0, { label: 'Sync to Miro Board', cmd: 'node', args: ['scripts/sync-mermaid-miro.mjs'] });
  } else {
    console.log('\n  [INFO] MIRO_API_TOKEN not set — skipping Miro sync');
  }

  const results = [];
  let allPassed = true;

  for (const step of steps) {
    const ok = runStep(step.label, step.cmd, step.args);
    results.push({ ...step, ok });
    if (!ok) {
      allPassed = false;
      console.log(`\n  [ABORT] Pipeline stopped at "${step.label}"`);
      break;
    }
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log(`\n${'='.repeat(55)}`);
  console.log(`  Pipeline Summary (${elapsed}s)`);
  console.log(`${'='.repeat(55)}`);
  for (const r of results) {
    console.log(`  ${r.ok ? '[OK]  ' : '[FAIL]'} ${r.label}`);
  }
  console.log(`${'='.repeat(55)}`);
  console.log(`  Result: ${allPassed ? 'ALL PASSED' : 'FAILED'}`);
  console.log(`${'='.repeat(55)}\n`);

  process.exit(allPassed ? 0 : 1);
}

main();
