import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { solveLayout } from './layoutSolver.js';
import { applyPerturbation, getViewportSequence } from './perturbations.js';
import { generateCsvSummary, generateMarkdownReport } from './report.js';
import type { LayoutSpec, MetricsReport } from './types.js';
import type { PerturbationDef } from './perturbations.js';

interface ManifestFixture {
  id: string;
  source: string;
  required: boolean;
}

interface ManifestSolver {
  id: string;
  label: string;
  deterministic: boolean;
  seeds?: number[];
  adapter?: string;
}

interface ManifestViewport {
  id: string;
  width: number;
  height: number;
}

interface Manifest {
  study: { name: string; date: string; purpose: string };
  fixtures: ManifestFixture[];
  solvers: ManifestSolver[];
  viewports: ManifestViewport[];
  perturbations: PerturbationDef[];
  metrics: Array<{ id: string; target: string; accept?: number }>;
  reporting: Record<string, unknown>;
}

interface BenchmarkRun {
  solverId: string;
  fixtureId: string;
  viewportId: string;
  perturbationId: string;
  seed: number | null;
  metrics: MetricsReport;
  elapsedMs: number;
}

function loadFixture(fixtureId: string): LayoutSpec | null {
  const paths: Record<string, string> = {
    'dns-topology-prod': 'fixtures/dns-topology-production.json',
    'dns-topology-reconstructed': 'fixtures/dns-topology-production.json',
  };
  const p = paths[fixtureId];
  if (!p) return null;
  try {
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return null;
  }
}

function mapViewportToProfile(viewportId: string): string {
  const vw: Record<string, string> = {
    phone_small: 'mobile',
    phone_large: 'mobile',
    tablet_portrait: 'tablet',
    laptop: 'desktop',
    desktop: 'desktop',
    wall: 'desktop',
  };
  return vw[viewportId] ?? 'desktop';
}

function runSolver(spec: LayoutSpec, profileId: string): { metrics: MetricsReport; elapsedMs: number } {
  const t0 = performance.now();
  const result = solveLayout(spec, { profileId });
  const elapsed = performance.now() - t0;
  return { metrics: result.metrics, elapsedMs: elapsed };
}

function runHybridSolver(
  solver: ManifestSolver,
  spec: LayoutSpec,
  viewportId: string,
  perturbation: PerturbationDef,
): BenchmarkRun[] {
  const runs: BenchmarkRun[] = [];
  const profileId = mapViewportToProfile(viewportId);

  const viewportSequence = getViewportSequence(perturbation);
  if (viewportSequence) {
    for (const vp of viewportSequence) {
      const prof = mapViewportToProfile(vp);
      if (!spec.viewportProfiles[prof]) continue;
      const { metrics, elapsedMs } = runSolver(spec, prof);
      runs.push({
        solverId: solver.id,
        fixtureId: 'dns-topology-prod',
        viewportId: vp,
        perturbationId: perturbation.id,
        seed: null,
        metrics,
        elapsedMs,
      });
    }
    return runs;
  }

  if (!spec.viewportProfiles[profileId]) return runs;
  const { metrics, elapsedMs } = runSolver(spec, profileId);
  runs.push({
    solverId: solver.id,
    fixtureId: 'dns-topology-prod',
    viewportId,
    perturbationId: perturbation.id,
    seed: null,
    metrics,
    elapsedMs,
  });
  return runs;
}

function runFRBaseline(
  solver: ManifestSolver,
  spec: LayoutSpec,
  viewportId: string,
  perturbation: PerturbationDef,
): BenchmarkRun[] {
  const runs: BenchmarkRun[] = [];
  const profileId = mapViewportToProfile(viewportId);
  if (!spec.viewportProfiles[profileId]) return runs;

  const seeds = solver.seeds ?? [1];
  for (const seed of seeds) {
    const seeded = structuredClone(spec);
    seeded.metadata.seed = seed;
    const { metrics, elapsedMs } = runSolver(seeded, profileId);
    runs.push({
      solverId: solver.id,
      fixtureId: 'dns-topology-prod',
      viewportId,
      perturbationId: perturbation.id,
      seed,
      metrics,
      elapsedMs,
    });
  }
  return runs;
}

function runSolverForViewport(
  solver: ManifestSolver,
  spec: LayoutSpec,
  viewportId: string,
  perturbation: PerturbationDef,
): BenchmarkRun[] {
  if (solver.deterministic || !solver.seeds) {
    return runHybridSolver(solver, spec, viewportId, perturbation);
  }
  return runFRBaseline(solver, spec, viewportId, perturbation);
}

function main() {
  const manifestPath = process.argv[2] ?? 'benchmark.manifest.json';
  const manifest: Manifest = JSON.parse(readFileSync(manifestPath, 'utf-8'));
  const allRuns: BenchmarkRun[] = [];

  const baseSpec = loadFixture('dns-topology-prod');
  if (!baseSpec) {
    console.error('ERROR: Cannot load production fixture');
    process.exit(1);
  }

  const activeSolvers = manifest.solvers.filter(
    (s) => !s.adapter || s.adapter !== 'elkjs',
  );

  const activeViewports = ['desktop', 'tablet_portrait', 'phone_large'];

  for (const solver of activeSolvers) {
    for (const perturbation of manifest.perturbations) {
      let spec: LayoutSpec;
      try {
        spec = applyPerturbation(baseSpec, perturbation);
      } catch (err) {
        console.error(`SKIP perturbation ${perturbation.id}: ${err}`);
        continue;
      }

      for (const viewportId of activeViewports) {
        try {
          allRuns.push(...runSolverForViewport(solver, spec, viewportId, perturbation));
        } catch (err) {
          console.error(`ERROR: solver=${solver.id} viewport=${viewportId} perturbation=${perturbation.id}: ${err}`);
        }
      }
    }
  }

  mkdirSync('results', { recursive: true });

  const rawJson = JSON.stringify(allRuns, null, 2);
  writeFileSync('results/benchmark-raw.json', rawJson);
  console.error(`[benchmark] ${allRuns.length} runs completed`);

  const csv = generateCsvSummary(allRuns);
  writeFileSync('results/benchmark-summary.csv', csv);
  console.error('[benchmark] CSV summary written to results/benchmark-summary.csv');

  const md = generateMarkdownReport(allRuns, manifest.metrics);
  writeFileSync('results/benchmark-report.md', md);
  console.error('[benchmark] Markdown report written to results/benchmark-report.md');

  process.stdout.write(rawJson + '\n');
}

main();
