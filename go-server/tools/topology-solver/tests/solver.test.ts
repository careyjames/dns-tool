import { readFileSync } from 'node:fs';
import { solveLayout } from '../src/layoutSolver.js';
import type { LayoutSpec, MetricsReport } from '../src/types.js';
import { computeNodeBox, estimateTextWidth } from '../src/nodeMetrics.js';

const FIXTURE_PATH = 'fixtures/dns-topology-production.json';

function loadSpec(): LayoutSpec {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf-8'));
}

interface TestCase {
  name: string;
  fn: () => void;
}

const tests: TestCase[] = [];
let passed = 0;
let failed = 0;

function test(name: string, fn: () => void) {
  tests.push({ name, fn });
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function assertEqual<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) throw new Error(`${message}: expected ${expected}, got ${actual}`);
}

test('solver produces valid output for production fixture', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'desktop' });

  assert(result.nodeCenters !== undefined, 'nodeCenters must exist');
  assert(result.routedEdges !== undefined, 'routedEdges must exist');
  assert(result.metrics !== undefined, 'metrics must exist');

  const nodeIds = spec.nodes.map((n) => n.id).sort((a, b) => a.localeCompare(b));
  const resultIds = Object.keys(result.nodeCenters).sort((a, b) => a.localeCompare(b));
  assertEqual(resultIds.length, nodeIds.length, 'all nodes must have positions');

  for (const id of nodeIds) {
    assert(result.nodeCenters[id] !== undefined, `missing position for node ${id}`);
    assert(typeof result.nodeCenters[id].x === 'number', `x must be number for ${id}`);
    assert(typeof result.nodeCenters[id].y === 'number', `y must be number for ${id}`);
    assert(!Number.isNaN(result.nodeCenters[id].x), `x must not be NaN for ${id}`);
    assert(!Number.isNaN(result.nodeCenters[id].y), `y must not be NaN for ${id}`);
  }

  assertEqual(result.routedEdges.length, spec.edges.length, 'all edges must be routed');
});

test('output is deterministic (run twice, compare)', () => {
  const spec = loadSpec();
  const result1 = solveLayout(spec, { profileId: 'desktop' });
  const result2 = solveLayout(spec, { profileId: 'desktop' });

  const ids = Object.keys(result1.nodeCenters).sort((a, b) => a.localeCompare(b));
  for (const id of ids) {
    assertEqual(result1.nodeCenters[id].x, result2.nodeCenters[id].x, `x mismatch for ${id}`);
    assertEqual(result1.nodeCenters[id].y, result2.nodeCenters[id].y, `y mismatch for ${id}`);
  }

  for (let i = 0; i < result1.routedEdges.length; i++) {
    const e1 = result1.routedEdges[i];
    const e2 = result2.routedEdges[i];
    assertEqual(e1.edgeId, e2.edgeId, `edge id mismatch at index ${i}`);
    assertEqual(e1.points.length, e2.points.length, `points length mismatch for ${e1.edgeId}`);
  }
});

test('zero node overlaps', () => {
  const spec = loadSpec();
  for (const profileId of ['desktop', 'tablet', 'mobile']) {
    const result = solveLayout(spec, { profileId });
    assertEqual(result.metrics.nodeOverlaps, 0, `node overlaps must be zero on ${profileId}`);
  }
});

test('flow x-monotonicity violations tracked on desktop', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'desktop' });
  assert(typeof result.metrics.flowMonotonicityViolations === 'number', 'flowMonotonicityViolations must be a number');
  const v = result.metrics.flowMonotonicityViolations;
  if (v > 0) {
    console.log(`    ⚠ ${v} flow monotonicity violations (quality target: 0)`);
  }
  assert(v <= 10, `flow monotonicity violations exceed quality threshold: ${v} > 10`);
});

test('all nodes have positions within their zone bounds', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'desktop' });
  const profile = spec.viewportProfiles['desktop'];

  for (const node of spec.nodes) {
    const template = profile.zoneTemplates[node.zoneId];
    if (!template) continue;

    const pos = result.nodeCenters[node.id];
    let halfW: number;
    let halfH: number;
    if (node.radius) {
      const box = computeNodeBox(
        { shape: node.shape as any, radius: node.radius, label: node.label, sub: node.sub, scale: 1, fontLabel: 14, fontSub: 10 },
        estimateTextWidth,
      );
      halfW = box.halfW;
      halfH = box.halfH;
    } else {
      halfW = node.width / 2;
      halfH = node.height / 2;
    }
    const padding = template.padding ?? 8;

    const minX = template.x1 + padding + halfW;
    const maxX = template.x2 - padding - halfW;
    const minY = template.y1 + padding + halfH;
    const maxY = template.y2 - padding - halfH;

    assert(
      pos.x >= minX - 1 && pos.x <= maxX + 1,
      `node ${node.id} x=${pos.x.toFixed(1)} outside zone bounds [${minX.toFixed(1)}, ${maxX.toFixed(1)}]`,
    );
    assert(
      pos.y >= minY - 1 && pos.y <= maxY + 1,
      `node ${node.id} y=${pos.y.toFixed(1)} outside zone bounds [${minY.toFixed(1)}, ${maxY.toFixed(1)}]`,
    );
  }
});

test('metrics report has all required fields', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'desktop' });
  const m = result.metrics;

  const requiredFields: Array<keyof MetricsReport> = [
    'nodeOverlaps',
    'labelOverlaps',
    'flowCrossings',
    'totalCrossings',
    'edgeNodeIntersections',
    'flowMonotonicityViolations',
    'bendsTotal',
    'averageAngularResolution',
    'area',
    'stress',
  ];

  for (const field of requiredFields) {
    assert(field in m, `missing metrics field: ${field}`);
    assert(typeof m[field] === 'number', `metrics.${field} must be a number, got ${typeof m[field]}`);
  }
});

test('solver works for tablet profile', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'tablet' });
  assert(Object.keys(result.nodeCenters).length === spec.nodes.length, 'all nodes placed for tablet');
});

test('solver works for mobile profile', () => {
  const spec = loadSpec();
  const result = solveLayout(spec, { profileId: 'mobile' });
  assert(Object.keys(result.nodeCenters).length === spec.nodes.length, 'all nodes placed for mobile');
});

async function runTests() {
  console.log(`Running ${tests.length} tests...\n`);

  for (const t of tests) {
    try {
      t.fn();
      passed++;
      console.log(`  ✓ ${t.name}`);
    } catch (err: unknown) {
      failed++;
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ✗ ${t.name}`);
      console.log(`    ${msg}`);
    }
  }

  console.log(`\n${passed} passed, ${failed} failed, ${tests.length} total`);
  if (failed > 0) process.exit(1);
}

await runTests();
