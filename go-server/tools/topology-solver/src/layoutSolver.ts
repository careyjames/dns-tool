import {
  CompiledProblem,
  EdgeSpec,
  LayoutResult,
  LayoutSpec,
  LayoutState,
  PrimitiveConstraint,
  RankAssignment,
  ViewportProfile,
} from './types.js';
import { compileConstraints } from './constraintCompiler.js';
import { evaluateMetrics } from './metrics.js';
import { routeEdges } from './router.js';

export interface SolveOptions {
  profileId: string;
  previous?: LayoutState;
}

function mulberry32(seed: number): () => number {
  let s = Math.trunc(seed);
  return () => {
    s = Math.trunc(s + 0x6d2b79f5);
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function solveLayout(spec: LayoutSpec, options: SolveOptions): LayoutResult {
  const profile = spec.viewportProfiles[options.profileId];
  if (!profile) throw new Error(`Unknown viewport profile ${options.profileId}`);

  const compiled = compileConstraints(spec, profile);
  compiled.ranks = assignRanks(spec);
  compiled.flowNodeOrder = flattenRanks(compiled.ranks);

  const anchors = extractAnchors(spec);
  const draft = makeDraftState(spec, profile, compiled.ranks, compiled, anchors);
  const feasible = makeFeasible(draft, compiled);
  const refined = constrainedStressSolve(spec, profile, compiled, feasible, anchors, options.previous);

  eliminateOverlaps(spec, compiled, refined);

  const routedEdges = routeEdges(spec, compiled, refined);
  const metrics = evaluateMetrics(spec, compiled, refined, routedEdges);

  return {
    nodeCenters: Object.fromEntries(
      spec.nodes.map((n) => [n.id, { x: Math.round(refined.x[n.id] * 10) / 10, y: Math.round(refined.y[n.id] * 10) / 10 }]),
    ),
    routedEdges,
    metrics,
    debug: {
      ranks: compiled.ranks,
      stressHistory: refined.stressHistory,
      activeConstraintsX: refined.activeConstraintsX.length,
      activeConstraintsY: refined.activeConstraintsY.length,
    },
  };
}

interface AnchorTarget {
  x?: number;
  y?: number;
  weight: number;
}

function extractAnchors(spec: LayoutSpec): Map<string, AnchorTarget> {
  const anchors = new Map<string, AnchorTarget>();
  for (const c of spec.highLevelConstraints) {
    if (c.type === 'anchor') {
      const ids = c.selector.ids ?? [];
      for (const id of ids) {
        anchors.set(id, { x: c.x, y: c.y, weight: c.weight });
      }
    }
  }
  return anchors;
}

function topoSort(spec: LayoutSpec, flowEdges: EdgeSpec[], outgoing: Map<string, string[]>): string[] {
  const incoming = new Map<string, string[]>();
  for (const n of spec.nodes) {
    incoming.set(n.id, []);
  }
  for (const e of flowEdges) {
    incoming.get(e.target)?.push(e.source);
  }

  const indegree = new Map<string, number>();
  for (const n of spec.nodes) indegree.set(n.id, incoming.get(n.id)?.length ?? 0);

  const queue = spec.nodes
    .map((n) => n.id)
    .filter((id) => (indegree.get(id) ?? 0) === 0)
    .sort((a, b) => a.localeCompare(b));
  const topo: string[] = [];

  while (queue.length) {
    const id = queue.shift()!;
    topo.push(id);
    for (const v of (outgoing.get(id) ?? []).sort((a, b) => a.localeCompare(b))) {
      indegree.set(v, (indegree.get(v) ?? 0) - 1);
      if ((indegree.get(v) ?? 0) === 0) {
        queue.push(v);
        queue.sort((a, b) => a.localeCompare(b));
      }
    }
  }

  if (topo.length !== spec.nodes.length) {
    throw new Error('Flow graph contains a cycle; implement SCC condensation before ranking.');
  }
  return topo;
}

export function assignRanks(spec: LayoutSpec): RankAssignment {
  const flowEdges = spec.edges.filter((e) => e.kind === 'flow');
  const outgoing = new Map<string, string[]>();

  for (const n of spec.nodes) {
    outgoing.set(n.id, []);
  }
  for (const e of flowEdges) {
    outgoing.get(e.source)?.push(e.target);
  }

  const topo = topoSort(spec, flowEdges, outgoing);

  const nodeToRank: Record<string, number> = {};
  for (const id of topo) nodeToRank[id] = 0;
  for (const id of topo) {
    for (const v of outgoing.get(id) ?? []) {
      nodeToRank[v] = Math.max(nodeToRank[v] ?? 0, (nodeToRank[id] ?? 0) + 1);
    }
  }

  const rankToNodes: Record<number, string[]> = {};
  for (const id of Object.keys(nodeToRank).sort((a, b) => a.localeCompare(b))) {
    const r = nodeToRank[id];
    if (!rankToNodes[r]) rankToNodes[r] = [];
    rankToNodes[r].push(id);
  }

  barycentreOrderingPass(rankToNodes, flowEdges, nodeToRank);

  return { nodeToRank, rankToNodes };
}

function barycentreOrderingPass(
  rankToNodes: Record<number, string[]>,
  flowEdges: EdgeSpec[],
  nodeToRank: Record<string, number>,
): void {
  const adjDown = new Map<string, string[]>();
  const adjUp = new Map<string, string[]>();
  for (const e of flowEdges) {
    if (!adjDown.has(e.source)) adjDown.set(e.source, []);
    adjDown.get(e.source)!.push(e.target);
    if (!adjUp.has(e.target)) adjUp.set(e.target, []);
    adjUp.get(e.target)!.push(e.source);
  }

  const ranks = Object.keys(rankToNodes).map(Number).sort((a, b) => a - b);

  for (let sweep = 0; sweep < 4; sweep++) {
    sweepForward(ranks, rankToNodes, adjUp);
    sweepBackward(ranks, rankToNodes, adjDown);
  }
}

function sweepForward(
  ranks: number[],
  rankToNodes: Record<number, string[]>,
  adjUp: Map<string, string[]>,
): void {
  for (let ri = 1; ri < ranks.length; ri++) {
    const r = ranks[ri];
    const prevRank = ranks[ri - 1];
    const prevOrder = new Map(rankToNodes[prevRank].map((id, i) => [id, i]));
    const nodes = rankToNodes[r];
    const indexed = nodes.map((id) => {
      const ups = adjUp.get(id) ?? [];
      const positions = ups.filter((u) => prevOrder.has(u)).map((u) => prevOrder.get(u)!);
      const score = positions.length > 0 ? positions.reduce((a, b) => a + b, 0) / positions.length : Infinity;
      return { id, score };
    });
    indexed.sort((a, b) => a.score - b.score || a.id.localeCompare(b.id));
    rankToNodes[r] = indexed.map((x) => x.id);
  }
}

function sweepBackward(
  ranks: number[],
  rankToNodes: Record<number, string[]>,
  adjDown: Map<string, string[]>,
): void {
  for (let ri = ranks.length - 2; ri >= 0; ri--) {
    const r = ranks[ri];
    const nextRank = ranks[ri + 1];
    const nextOrder = new Map(rankToNodes[nextRank].map((id, i) => [id, i]));
    const nodes = rankToNodes[r];
    const indexed = nodes.map((id) => {
      const downs = adjDown.get(id) ?? [];
      const positions = downs.filter((d) => nextOrder.has(d)).map((d) => nextOrder.get(d)!);
      const score = positions.length > 0 ? positions.reduce((a, b) => a + b, 0) / positions.length : Infinity;
      return { id, score };
    });
    indexed.sort((a, b) => a.score - b.score || a.id.localeCompare(b.id));
    rankToNodes[r] = indexed.map((x) => x.id);
  }
}

function flattenRanks(ranks: RankAssignment): string[] {
  return Object.keys(ranks.rankToNodes)
    .map(Number)
    .sort((a, b) => a - b)
    .flatMap((r) => [...ranks.rankToNodes[r]]);
}

function makeDraftState(
  spec: LayoutSpec,
  profile: ViewportProfile,
  ranks: RankAssignment,
  compiled: CompiledProblem,
  anchors: Map<string, AnchorTarget>,
): LayoutState {
  const x: Record<string, number> = {};
  const y: Record<string, number> = {};

  for (const node of spec.nodes) {
    const zone = compiled.zones[node.zoneId];
    if (!zone) continue;

    const anchor = anchors.get(node.id);
    if (anchor) {
      x[node.id] = anchor.x ?? (zone.x1 + zone.x2) / 2;
      y[node.id] = anchor.y ?? (zone.y1 + zone.y2) / 2;
    } else {
      x[node.id] = (zone.x1 + zone.x2) / 2;
      y[node.id] = (zone.y1 + zone.y2) / 2;
    }
  }

  const zoneNodeGroups = new Map<string, string[]>();
  for (const node of spec.nodes) {
    if (!zoneNodeGroups.has(node.zoneId)) zoneNodeGroups.set(node.zoneId, []);
    zoneNodeGroups.get(node.zoneId)!.push(node.id);
  }

  for (const [zoneId, nodeIds] of zoneNodeGroups) {
    const zone = compiled.zones[zoneId];
    if (!zone || nodeIds.length <= 1) continue;

    const zoneCx = (zone.x1 + zone.x2) / 2;
    const zoneCy = (zone.y1 + zone.y2) / 2;

    const nodesInZone = nodeIds.filter((id) => !anchors.has(id));
    if (nodesInZone.length === 0) continue;

    const totalHeight = nodesInZone.reduce((sum, id) => sum + compiled.nodeBoxes[id].height, 0);
    const gaps = Math.max(0, nodesInZone.length - 1) * profile.intraRankGap;
    const stackHeight = totalHeight + gaps;

    let cursorY = zoneCy - stackHeight / 2;
    for (const id of nodesInZone) {
      const box = compiled.nodeBoxes[id];
      x[id] = zoneCx;
      y[id] = cursorY + box.halfH;
      cursorY += box.height + profile.intraRankGap;
    }
  }

  return { x, y, stressHistory: [], activeConstraintsX: [], activeConstraintsY: [] };
}

function makeFeasible(state: LayoutState, compiled: CompiledProblem): LayoutState {
  const next: LayoutState = {
    ...state,
    x: { ...state.x },
    y: { ...state.y },
    activeConstraintsX: [],
    activeConstraintsY: [],
  };

  for (let pass = 0; pass < 16; pass++) {
    applyPrimitiveConstraints(next, compiled.primitives, 'x');
    applyPrimitiveConstraints(next, compiled.primitives, 'y');
  }

  return next;
}

function constrainedStressSolve(
  spec: LayoutSpec,
  profile: ViewportProfile,
  compiled: CompiledProblem,
  initial: LayoutState,
  anchors: Map<string, AnchorTarget>,
  previous?: LayoutState,
): LayoutState {
  const state: LayoutState = {
    ...initial,
    x: { ...initial.x },
    y: { ...initial.y },
    prevX: previous?.x,
    prevY: previous?.y,
    stressHistory: [],
    activeConstraintsX: [],
    activeConstraintsY: [],
  };

  const maxIter = spec.solverPolicy.maxIterations;
  for (let iter = 0; iter < maxIter; iter++) {
    const t = iter / maxIter;
    const stepScale = 0.04 * (1 - t * 0.5);

    const activeX = generateActiveConstraints(spec, compiled, state, 'x');
    const activeY = generateActiveConstraints(spec, compiled, state, 'y');
    state.activeConstraintsX = activeX;
    state.activeConstraintsY = activeY;

    solveAxisImproved(spec, compiled, state, 'x', activeX, anchors, stepScale);
    solveAxisImproved(spec, compiled, state, 'y', activeY, anchors, stepScale);

    const stress = computeStress(spec, state, anchors);
    state.stressHistory.push(stress);

    if (hasConverged(state.stressHistory, spec.solverPolicy.convergenceEpsilon, spec.solverPolicy.stressWindow)) {
      break;
    }
  }

  return state;
}

function solveAxisImproved(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
  axis: 'x' | 'y',
  active: PrimitiveConstraint[],
  anchors: Map<string, AnchorTarget>,
  stepScale: number,
): void {
  const coord = axis === 'x' ? state.x : state.y;

  for (const e of spec.edges) {
    const s = e.source;
    const t = e.target;
    const dx = state.x[t] - state.x[s];
    const dy = state.y[t] - state.y[s];
    const dist = Math.hypot(dx, dy) || 1;
    const desired = desiredLength(spec, e);
    const err = dist - desired;
    const w = edgeWeight(spec, e) * stepScale;
    const component = axis === 'x' ? dx / dist : dy / dist;
    const delta = component * err * w;
    coord[s] += delta;
    coord[t] -= delta;
  }

  const anchorWeight = spec.solverPolicy.weights.anchor;
  for (const [id, anchor] of anchors) {
    const target = axis === 'x' ? anchor.x : anchor.y;
    if (target == null) continue;
    const current = coord[id];
    coord[id] += (target - current) * anchorWeight * anchor.weight * 0.3;
  }

  const prevCoord = axis === 'x' ? state.prevX : state.prevY;
  if (prevCoord) {
    for (const n of spec.nodes) {
      coord[n.id] += (prevCoord[n.id] - coord[n.id]) * spec.solverPolicy.weights.stability * 0.05;
    }
  }

  applyPrimitiveConstraints(state, active, axis);
}

function applyPrimitiveConstraints(
  state: LayoutState,
  constraints: PrimitiveConstraint[],
  axis: 'x' | 'y',
): void {
  const coord = axis === 'x' ? state.x : state.y;

  const sorted = [...constraints].filter((c) => c.axis === axis).sort((a, b) => b.priority - a.priority);

  for (const c of sorted) {
    switch (c.type) {
      case 'bound':
        coord[c.nodeId] = c.op === '>=' ? Math.max(coord[c.nodeId], c.value) : Math.min(coord[c.nodeId], c.value);
        break;
      case 'fixed':
        coord[c.nodeId] = c.value;
        break;
      case 'equality': {
        const avg = (coord[c.a] + (coord[c.b] - c.offset)) / 2;
        coord[c.a] = avg;
        coord[c.b] = avg + c.offset;
        break;
      }
      case 'separation': {
        const left = coord[c.left];
        const right = coord[c.right];
        if (right - left < c.gap) {
          const mid = (left + right) / 2;
          coord[c.left] = mid - c.gap / 2;
          coord[c.right] = mid + c.gap / 2;
        }
        break;
      }
    }
  }
}

function detectOverlap(
  state: LayoutState,
  compiled: CompiledProblem,
  a: string,
  b: string,
  pad: number,
): { overlapX: number; overlapY: number } | null {
  const boxA = compiled.nodeBoxes[a];
  const boxB = compiled.nodeBoxes[b];
  const dx = Math.abs(state.x[a] - state.x[b]);
  const dy = Math.abs(state.y[a] - state.y[b]);
  const overlapX = boxA.halfW + boxB.halfW + pad - dx;
  const overlapY = boxA.halfH + boxB.halfH + pad - dy;
  if (overlapX > 0 && overlapY > 0) {
    return { overlapX, overlapY };
  }
  return null;
}

function generateActiveConstraints(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
  axis: 'x' | 'y',
): PrimitiveConstraint[] {
  const out: PrimitiveConstraint[] = compiled.primitives.filter((c) => c.axis === axis);

  const ids = spec.nodes.map((n) => n.id).sort((a, b) => a.localeCompare(b));
  const pad = 16;
  for (let i = 0; i < ids.length; i++) {
    for (let j = i + 1; j < ids.length; j++) {
      const a = ids[i];
      const b = ids[j];
      const overlap = detectOverlap(state, compiled, a, b, pad);
      if (!overlap) continue;

      const coord = axis === 'x' ? state.x : state.y;
      const halfKey = axis === 'x' ? 'halfW' : 'halfH';
      const left = coord[a] <= coord[b] ? a : b;
      const right = left === a ? b : a;
      out.push({
        type: 'separation',
        axis,
        left,
        right,
        gap: compiled.nodeBoxes[left][halfKey] + compiled.nodeBoxes[right][halfKey] + pad,
        hard: true,
        priority: 950,
        sourceTag: 'dynamic-non-overlap',
      });
    }
  }

  return out;
}

function resolveNodeOverlap(state: LayoutState, a: string, b: string, compiled: CompiledProblem, pad: number): boolean {
  const overlap = detectOverlap(state, compiled, a, b, pad);
  if (!overlap) return false;

  if (overlap.overlapX <= overlap.overlapY) {
    const shift = overlap.overlapX / 2 + 1;
    if (state.x[a] <= state.x[b]) {
      state.x[a] -= shift;
      state.x[b] += shift;
    } else {
      state.x[a] += shift;
      state.x[b] -= shift;
    }
  } else {
    const shift = overlap.overlapY / 2 + 1;
    if (state.y[a] <= state.y[b]) {
      state.y[a] -= shift;
      state.y[b] += shift;
    } else {
      state.y[a] += shift;
      state.y[b] -= shift;
    }
  }
  return true;
}

function clampNodesToZones(spec: LayoutSpec, compiled: CompiledProblem, state: LayoutState): void {
  for (const node of spec.nodes) {
    const zone = compiled.zones[node.zoneId];
    if (!zone) continue;
    const box = compiled.nodeBoxes[node.id];
    state.x[node.id] = Math.max(zone.x1 + zone.padding + box.halfW, Math.min(zone.x2 - zone.padding - box.halfW, state.x[node.id]));
    state.y[node.id] = Math.max(zone.y1 + zone.padding + box.halfH, Math.min(zone.y2 - zone.padding - box.halfH, state.y[node.id]));
  }
}

function eliminateOverlaps(spec: LayoutSpec, compiled: CompiledProblem, state: LayoutState): void {
  const pad = 16;
  const ids = spec.nodes.map((n) => n.id).sort((a, b) => a.localeCompare(b));

  for (let pass = 0; pass < 30; pass++) {
    let changed = false;
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        if (resolveNodeOverlap(state, ids[i], ids[j], compiled, pad)) {
          changed = true;
        }
      }
    }

    clampNodesToZones(spec, compiled, state);
    if (!changed) break;
  }
}

function computeStress(spec: LayoutSpec, state: LayoutState, anchors: Map<string, AnchorTarget>): number {
  let total = 0;
  for (const e of spec.edges) {
    const dx = state.x[e.target] - state.x[e.source];
    const dy = state.y[e.target] - state.y[e.source];
    const dist = Math.hypot(dx, dy) || 1;
    const desired = desiredLength(spec, e);
    const err = dist - desired;
    total += edgeWeight(spec, e) * err * err;
  }

  for (const [id, anchor] of anchors) {
    const dx = anchor.x != null ? state.x[id] - anchor.x : 0;
    const dy = anchor.y != null ? state.y[id] - anchor.y : 0;
    total += spec.solverPolicy.weights.anchor * anchor.weight * (dx * dx + dy * dy);
  }

  return total;
}

function desiredLength(spec: LayoutSpec, e: EdgeSpec): number {
  const minLen = e.minLen ?? 1;
  return 100 * minLen;
}

function edgeWeight(spec: LayoutSpec, e: EdgeSpec): number {
  if (e.weight != null) return e.weight;
  if (e.kind === 'flow') return spec.solverPolicy.weights.flow;
  if (e.kind === 'hard_dependency') return spec.solverPolicy.weights.hardDependency;
  return spec.solverPolicy.weights.softDependency;
}

function hasConverged(history: number[], epsilon: number, window: number): boolean {
  if (history.length < window + 1) return false;
  const current = history.at(-1)!;
  const previous = history[history.length - 1 - window];
  const rel = Math.abs(previous - current) / Math.max(1, Math.abs(previous));
  return rel < epsilon;
}
