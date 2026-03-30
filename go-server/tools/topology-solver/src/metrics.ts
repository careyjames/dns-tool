import {
  CompiledProblem,
  LayoutSpec,
  LayoutState,
  MetricsReport,
  RoutedEdge,
} from './types.js';

export function evaluateMetrics(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
  routedEdges: RoutedEdge[],
): MetricsReport {
  return {
    nodeOverlaps: countNodeOverlaps(spec, compiled, state),
    labelOverlaps: countLabelOverlaps(routedEdges),
    flowCrossings: countCrossings(routedEdges.filter((e) => {
      const edge = spec.edges.find((x) => x.id === e.edgeId);
      return edge?.kind === 'flow';
    })),
    totalCrossings: countCrossings(routedEdges),
    edgeNodeIntersections: countEdgeNodeIntersections(spec, compiled, state, routedEdges),
    flowMonotonicityViolations: countFlowMonotonicityViolations(spec, routedEdges),
    bendsTotal: routedEdges.reduce((sum, e) => sum + Math.max(0, e.points.length - 2), 0),
    averageAngularResolution: 0,
    area: estimateArea(spec, state),
    stress: computeEdgeLengthStress(spec, state),
    medianResizeDrift: undefined,
  };
}

function countNodeOverlaps(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
): number {
  const ids = spec.nodes.map((n) => n.id).sort((a, b) => a.localeCompare(b));
  let overlaps = 0;

  for (let i = 0; i < ids.length; i += 1) {
    for (let j = i + 1; j < ids.length; j += 1) {
      const a = ids[i];
      const b = ids[j];
      const boxA = compiled.nodeBoxes[a];
      const boxB = compiled.nodeBoxes[b];
      const dx = Math.abs(state.x[a] - state.x[b]);
      const dy = Math.abs(state.y[a] - state.y[b]);
      if (dx < boxA.halfW + boxB.halfW && dy < boxA.halfH + boxB.halfH) overlaps += 1;
    }
  }

  return overlaps;
}

function countLabelOverlaps(edges: RoutedEdge[]): number {
  let overlaps = 0;
  for (let i = 0; i < edges.length; i += 1) {
    const a = edges[i].labelBox;
    if (!a) continue;
    for (let j = i + 1; j < edges.length; j += 1) {
      const b = edges[j].labelBox;
      if (!b) continue;
      if (
        Math.abs(a.x - b.x) * 2 < a.width + b.width &&
        Math.abs(a.y - b.y) * 2 < a.height + b.height
      ) {
        overlaps += 1;
      }
    }
  }
  return overlaps;
}

function countCrossings(edges: RoutedEdge[]): number {
  let crossings = 0;
  for (let i = 0; i < edges.length; i += 1) {
    for (let j = i + 1; j < edges.length; j += 1) {
      const aSegs = segments(edges[i]);
      const bSegs = segments(edges[j]);
      for (const as of aSegs) {
        for (const bs of bSegs) {
          if (segmentsIntersect(as[0], as[1], bs[0], bs[1])) crossings += 1;
        }
      }
    }
  }
  return crossings;
}

function countEdgeNodeIntersections(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
  edges: RoutedEdge[],
): number {
  let count = 0;
  for (const e of edges) {
    const srcEdge = spec.edges.find((x) => x.id === e.edgeId);
    if (!srcEdge) continue;
    for (const node of spec.nodes) {
      if (node.id === srcEdge.source || node.id === srcEdge.target) continue;
      const box = compiled.nodeBoxes[node.id];
      const rect = {
        x1: state.x[node.id] - box.halfW,
        y1: state.y[node.id] - box.halfH,
        x2: state.x[node.id] + box.halfW,
        y2: state.y[node.id] + box.halfH,
      };
      for (const [p, q] of segments(e)) {
        if (segmentIntersectsRect(p, q, rect)) count += 1;
      }
    }
  }
  return count;
}

function countFlowMonotonicityViolations(
  spec: LayoutSpec,
  edges: RoutedEdge[],
): number {
  let count = 0;
  for (const e of edges) {
    const src = spec.edges.find((x) => x.id === e.edgeId);
    if (src?.kind !== 'flow') continue;
    for (let i = 1; i < e.points.length; i += 1) {
      if (e.points[i].x + 1e-6 < e.points[i - 1].x) count += 1;
    }
  }
  return count;
}

function estimateArea(spec: LayoutSpec, state: LayoutState): number {
  const xs = spec.nodes.map((n) => state.x[n.id]);
  const ys = spec.nodes.map((n) => state.y[n.id]);
  const width = Math.max(...xs) - Math.min(...xs);
  const height = Math.max(...ys) - Math.min(...ys);
  return width * height;
}

function computeEdgeLengthStress(spec: LayoutSpec, state: LayoutState): number {
  let total = 0;
  for (const e of spec.edges) {
    const dx = state.x[e.target] - state.x[e.source];
    const dy = state.y[e.target] - state.y[e.source];
    const dist = Math.hypot(dx, dy) || 1;
    const desired = 120 * (e.minLen ?? 1);
    const err = dist - desired;
    total += err * err;
  }
  return total;
}

function segments(edge: RoutedEdge) {
  const out: Array<[typeof edge.points[number], typeof edge.points[number]]> = [];
  for (let i = 1; i < edge.points.length; i += 1) {
    out.push([edge.points[i - 1], edge.points[i]]);
  }
  return out;
}

function segmentsIntersect(a: { x: number; y: number }, b: { x: number; y: number }, c: { x: number; y: number }, d: { x: number; y: number }): boolean {
  const o1 = orient(a, b, c);
  const o2 = orient(a, b, d);
  const o3 = orient(c, d, a);
  const o4 = orient(c, d, b);
  return o1 * o2 < 0 && o3 * o4 < 0;
}

function orient(a: { x: number; y: number }, b: { x: number; y: number }, c: { x: number; y: number }): number {
  return (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
}

function segmentIntersectsRect(
  p: { x: number; y: number },
  q: { x: number; y: number },
  rect: { x1: number; y1: number; x2: number; y2: number },
): boolean {
  if (pointInRect(p, rect) || pointInRect(q, rect)) return true;
  const corners = [
    { x: rect.x1, y: rect.y1 },
    { x: rect.x2, y: rect.y1 },
    { x: rect.x2, y: rect.y2 },
    { x: rect.x1, y: rect.y2 },
  ];
  for (let i = 0; i < 4; i += 1) {
    const a = corners[i];
    const b = corners[(i + 1) % 4];
    if (segmentsIntersect(p, q, a, b)) return true;
  }
  return false;
}

function pointInRect(
  p: { x: number; y: number },
  rect: { x1: number; y1: number; x2: number; y2: number },
): boolean {
  return p.x >= rect.x1 && p.x <= rect.x2 && p.y >= rect.y1 && p.y <= rect.y2;
}
