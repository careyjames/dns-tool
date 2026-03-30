import type { MetricsReport } from './types.js';

interface BenchmarkRun {
  solverId: string;
  fixtureId: string;
  viewportId: string;
  perturbationId: string;
  seed: number | null;
  metrics: MetricsReport;
  elapsedMs: number;
}

interface MetricDef {
  id: string;
  target: string;
  accept?: number;
}

const METRIC_KEYS: Array<keyof MetricsReport> = [
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

export function generateCsvSummary(runs: BenchmarkRun[]): string {
  const header = [
    'solver',
    'fixture',
    'viewport',
    'perturbation',
    'seed',
    ...METRIC_KEYS,
    'elapsed_ms',
  ].join(',');

  const rows = runs.map((r) => {
    const vals = METRIC_KEYS.map((k) => r.metrics[k] ?? '');
    return [
      r.solverId,
      r.fixtureId,
      r.viewportId,
      r.perturbationId,
      r.seed ?? '',
      ...vals,
      r.elapsedMs.toFixed(1),
    ].join(',');
  });

  return [header, ...rows].join('\n') + '\n';
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

function iqr(values: number[]): number {
  if (values.length < 4) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const q1Idx = Math.floor(sorted.length * 0.25);
  const q3Idx = Math.floor(sorted.length * 0.75);
  return sorted[q3Idx] - sorted[q1Idx];
}

interface AggregatedMetrics {
  solverId: string;
  viewportId: string;
  perturbationId: string;
  count: number;
  metrics: Record<string, { median: number; iqr: number; min: number; max: number }>;
}

function aggregateRuns(runs: BenchmarkRun[]): AggregatedMetrics[] {
  const groups = new Map<string, BenchmarkRun[]>();
  for (const r of runs) {
    const key = `${r.solverId}|${r.viewportId}|${r.perturbationId}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key)!.push(r);
  }

  const results: AggregatedMetrics[] = [];
  for (const [, group] of [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))) {
    const first = group[0];
    const agg: AggregatedMetrics = {
      solverId: first.solverId,
      viewportId: first.viewportId,
      perturbationId: first.perturbationId,
      count: group.length,
      metrics: {},
    };

    for (const key of METRIC_KEYS) {
      const values = group.map((r) => (r.metrics[key] as number) ?? 0);
      agg.metrics[key] = {
        median: median(values),
        iqr: iqr(values),
        min: Math.min(...values),
        max: Math.max(...values),
      };
    }

    results.push(agg);
  }

  return results;
}

function findPerMetricWinners(runs: BenchmarkRun[], metricDefs: MetricDef[], solverIds: string[]): string[] {
  const winnerLines: string[] = [];
  for (const md of metricDefs) {
    const metricKey = mapMetricId(md.id);
    if (!metricKey) continue;

    let bestSolver = '';
    let bestVal = md.target === 'max' ? -Infinity : Infinity;
    for (const solverId of solverIds) {
      const solverRuns = runs.filter((r) => r.solverId === solverId);
      const values = solverRuns.map((r) => (r.metrics[metricKey as keyof MetricsReport] as number) ?? 0);
      const med = median(values);

      if ((md.target === 'max' && med > bestVal) || (md.target === 'min' && med < bestVal) || md.target === 'mid') {
        bestVal = med;
        bestSolver = solverId;
      }
    }
    winnerLines.push(`- **${md.id}**: winner = ${bestSolver || 'N/A'} (median = ${typeof bestVal === 'number' ? bestVal.toFixed(2) : bestVal})`);
  }
  return winnerLines;
}

function formatFailureCases(runs: BenchmarkRun[]): string[] {
  const failures = runs.filter(
    (r) => r.metrics.nodeOverlaps > 0 || r.metrics.flowMonotonicityViolations > 0,
  );
  if (failures.length === 0) {
    return ['No critical failures detected.'];
  }
  const failureLines = [
    `${failures.length} runs with critical metric failures:`,
    '',
    ...failures.slice(0, 20).map((f) =>
      `- solver=${f.solverId} viewport=${f.viewportId} perturbation=${f.perturbationId}: overlaps=${f.metrics.nodeOverlaps} flow_violations=${f.metrics.flowMonotonicityViolations}`
    ),
  ];
  if (failures.length > 20) {
    failureLines.push(`- ... and ${failures.length - 20} more`);
  }
  return failureLines;
}

export function generateMarkdownReport(runs: BenchmarkRun[], metricDefs: MetricDef[]): string {
  const aggregated = aggregateRuns(runs);
  const solverIds = [...new Set(runs.map((r) => r.solverId))].sort((a, b) => a.localeCompare(b));

  const solverSummaryRows = solverIds.map((solverId) => {
    const solverRuns = runs.filter((r) => r.solverId === solverId);
    const overlaps = median(solverRuns.map((r) => r.metrics.nodeOverlaps));
    const stress = median(solverRuns.map((r) => r.metrics.stress));
    const crossings = median(solverRuns.map((r) => r.metrics.totalCrossings));
    const flowViol = median(solverRuns.map((r) => r.metrics.flowMonotonicityViolations));
    return `| ${solverId} | ${solverRuns.length} | ${overlaps} | ${stress.toFixed(1)} | ${crossings} | ${flowViol} |`;
  });

  const detailRows = aggregated.map((a) => {
    const ov = a.metrics['nodeOverlaps'];
    const st = a.metrics['stress'];
    const cr = a.metrics['totalCrossings'];
    return `| ${a.solverId} | ${a.viewportId} | ${a.perturbationId} | ${a.count} | ${ov?.median ?? '-'} | ${st?.median?.toFixed(1) ?? '-'} | ${cr?.median ?? '-'} |`;
  });

  const lines: string[] = [
    '# Topology Solver Benchmark Report',
    '',
    `Generated: ${new Date().toISOString()}`,
    `Total runs: ${runs.length}`,
    '',
    '## Summary by Solver',
    '',
    '| Solver | Runs | Median Overlaps | Median Stress | Median Crossings | Median Flow Violations |',
    '|--------|------|----------------|---------------|-----------------|----------------------|',
    ...solverSummaryRows,
    '',
    '## Per-Metric Winners',
    '',
    ...findPerMetricWinners(runs, metricDefs, solverIds),
    '',
    '## Failure Cases',
    '',
    ...formatFailureCases(runs),
    '',
    '## Detailed Aggregation',
    '',
    '| Solver | Viewport | Perturbation | N | Overlaps (med) | Stress (med) | Crossings (med) |',
    '|--------|----------|-------------|---|---------------|-------------|----------------|',
    ...detailRows,
    '',
  ];

  return lines.join('\n');
}

function mapMetricId(id: string): string | null {
  const mapping: Record<string, string> = {
    node_overlap_ratio: 'nodeOverlaps',
    label_overlap_ratio: 'labelOverlaps',
    edge_crossings_total: 'totalCrossings',
    edge_crossings_flow_flow: 'flowCrossings',
    edge_node_intersections: 'edgeNodeIntersections',
    flow_x_monotonicity_violations: 'flowMonotonicityViolations',
    flow_stress: 'stress',
    bend_count_total: 'bendsTotal',
    angular_resolution_min: 'averageAngularResolution',
    layout_bbox_area_ratio: 'area',
  };
  return mapping[id] ?? null;
}
