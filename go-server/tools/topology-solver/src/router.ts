import {
  CompiledProblem,
  LayoutSpec,
  LayoutState,
  LayoutLabelBox,
  PolylinePoint,
  RoutedEdge,
} from './types.js';

export function routeEdges(
  spec: LayoutSpec,
  compiled: CompiledProblem,
  state: LayoutState,
): RoutedEdge[] {
  return [...spec.edges]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((e) => {
      if (e.kind === 'flow') {
        return routeFlowEdge(compiled, state, e.id, e.source, e.target, e.label);
      }
      return routeOverlayEdge(compiled, state, e.id, e.source, e.target, e.label);
    });
}

function routeFlowEdge(
  compiled: CompiledProblem,
  state: LayoutState,
  edgeId: string,
  source: string,
  target: string,
  label?: string,
): RoutedEdge {
  const sx = state.x[source];
  const sy = state.y[source];
  const tx = state.x[target];
  const ty = state.y[target];
  const sBox = compiled.nodeBoxes[source];
  const tBox = compiled.nodeBoxes[target];

  let points: PolylinePoint[];

  if (tx > sx) {
    const startX = sx + sBox.halfW;
    const endX = tx - tBox.halfW;

    if (endX <= startX + 4 || Math.abs(sy - ty) < 2) {
      points = [
        { x: startX, y: sy },
        { x: Math.max(endX, startX), y: ty },
      ];
    } else {
      const midX = (startX + endX) / 2;
      points = [
        { x: startX, y: sy },
        { x: midX, y: sy },
        { x: midX, y: ty },
        { x: endX, y: ty },
      ];
    }
  } else {
    points = [
      { x: sx + sBox.halfW, y: sy },
      { x: tx + tBox.halfW, y: ty },
    ];
  }

  return {
    edgeId,
    points,
    labelBox: label ? makeLabelBox(points, label) : undefined,
  };
}

function routeOverlayEdge(
  compiled: CompiledProblem,
  state: LayoutState,
  edgeId: string,
  source: string,
  target: string,
  label?: string,
): RoutedEdge {
  const sx = state.x[source];
  const sy = state.y[source];
  const tx = state.x[target];
  const ty = state.y[target];

  const points: PolylinePoint[] = [
    { x: sx, y: sy },
    { x: tx, y: ty },
  ];

  return {
    edgeId,
    points,
    labelBox: label ? makeLabelBox(points, label) : undefined,
  };
}

function makeLabelBox(points: PolylinePoint[], label: string): LayoutLabelBox {
  let totalLen = 0;
  const segLens: number[] = [];
  for (let i = 1; i < points.length; i++) {
    const dx = points[i].x - points[i - 1].x;
    const dy = points[i].y - points[i - 1].y;
    segLens.push(Math.hypot(dx, dy));
    totalLen += segLens.at(-1)!;
  }

  const targetDist = totalLen * 0.5;
  let accum = 0;
  let midX = (points[0].x + points.at(-1)!.x) / 2;
  let midY = (points[0].y + points.at(-1)!.y) / 2;

  for (let i = 0; i < segLens.length; i++) {
    if (accum + segLens[i] >= targetDist) {
      const t = segLens[i] > 0 ? (targetDist - accum) / segLens[i] : 0.5;
      midX = points[i].x + (points[i + 1].x - points[i].x) * t;
      midY = points[i].y + (points[i + 1].y - points[i].y) * t;
      break;
    }
    accum += segLens[i];
  }

  const width = Math.max(56, label.length * 7 + 16);
  const height = 22;
  return {
    x: midX - width / 2,
    y: midY - height / 2,
    width,
    height,
  };
}
