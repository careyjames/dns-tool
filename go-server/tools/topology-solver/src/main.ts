import { readFileSync } from 'node:fs';
import { solveLayout } from './layoutSolver.js';
import type { LayoutSpec } from './types.js';

function usage(): never {
  console.error('Usage: tsx src/main.ts [--profile <id>] [--pretty] <spec.json>');
  console.error('  --profile   Viewport profile ID (default: desktop)');
  console.error('  --pretty    Pretty-print JSON output');
  process.exit(1);
}

function main() {
  const args = process.argv.slice(2);
  let profileId = 'desktop';
  let pretty = false;
  let specPath: string | undefined;

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--profile') {
      profileId = args[++i];
    } else if (args[i] === '--pretty') {
      pretty = true;
    } else if (args[i] === '--help' || args[i] === '-h') {
      usage();
    } else {
      specPath = args[i];
    }
  }

  if (specPath) {
    const raw = readFileSync(specPath, 'utf-8');
    const spec: LayoutSpec = JSON.parse(raw);
    run(spec, profileId, pretty);
  } else {
    try {
      const stdin = readFileSync(0, 'utf-8');
      const spec: LayoutSpec = JSON.parse(stdin);
      run(spec, profileId, pretty);
    } catch {
      usage();
    }
  }
}

function run(spec: LayoutSpec, profileId: string, pretty: boolean) {
  const t0 = performance.now();
  const result = solveLayout(spec, { profileId });
  const elapsed = performance.now() - t0;

  const output = pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result);
  process.stdout.write(output + '\n');

  console.error(`[solver] profile=${profileId} nodes=${spec.nodes.length} edges=${spec.edges.length}`);
  console.error(`[solver] iterations=${(result.debug as any)?.stressHistory?.length ?? '?'} stress=${result.metrics.stress.toFixed(1)}`);
  console.error(`[solver] overlaps=${result.metrics.nodeOverlaps} flow-violations=${result.metrics.flowMonotonicityViolations} crossings=${result.metrics.totalCrossings}`);
  console.error(`[solver] elapsed=${elapsed.toFixed(1)}ms`);
}

main();
