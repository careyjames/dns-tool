export const NODE_SHAPES = new Set(['rect', 'roundRect', 'circle', 'diamond', 'cylinder', 'hexagon', 'label'] as const);
export type NodeShape =
  | 'rect'
  | 'roundRect'
  | 'circle'
  | 'diamond'
  | 'cylinder'
  | 'hexagon'
  | 'label';

export const EDGE_CLASSES = new Set(['flow', 'hard_dependency', 'soft_dependency'] as const);
export type EdgeClass = 'flow' | 'hard_dependency' | 'soft_dependency';

export type Axis = 'x' | 'y';

export type ZoneShape = 'rect' | 'corridor';

export interface LayoutSpec {
  metadata: LayoutMetadata;
  viewportProfiles: Record<string, ViewportProfile>;
  zones: ZoneSpec[];
  nodes: NodeSpec[];
  edges: EdgeSpec[];
  highLevelConstraints: HighLevelConstraint[];
  solverPolicy: SolverPolicy;
}

export interface LayoutMetadata {
  name: string;
  version: string;
  seed: number;
  units: 'px';
}

export interface ViewportProfile {
  id: string;
  width: number;
  height: number;
  dpr?: number;
  rankGap: number;
  intraRankGap: number;
  stageGapY: number;
  margins: {
    top: number;
    right: number;
    bottom: number;
    left: number;
  };
  zoneTemplates: Record<string, ZoneTemplate>;
}

export interface ZoneTemplate {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  shape?: ZoneShape;
  padding?: number;
}

export interface ZoneSpec {
  id: string;
  label: string;
  orderX: number;
  orderY?: number;
  shape?: ZoneShape;
  tags?: string[];
}

export interface NodeSpec {
  id: string;
  label: string;
  zoneId: string;
  shape: NodeShape;
  width: number;
  height: number;
  radius?: number;
  sub?: string;
  tags?: string[];
  data?: Record<string, unknown>;
  anchor?: Partial<AnchorTarget>;
}

export interface EdgeSpec {
  id: string;
  source: string;
  target: string;
  kind: EdgeClass;
  minLen?: number;
  weight?: number;
  label?: string;
  labelT?: number;
  routing?: Partial<EdgeRoutingPolicy>;
  data?: Record<string, unknown>;
}

export interface AnchorTarget {
  x: number;
  y: number;
  weight: number;
}

export interface EdgeRoutingPolicy {
  style: 'polyline' | 'spline';
  monotoneX: boolean;
  preferredExitSide?: 'left' | 'right' | 'top' | 'bottom' | 'auto';
  preferredEntrySide?: 'left' | 'right' | 'top' | 'bottom' | 'auto';
  obstaclePadding: number;
}

export interface SolverPolicy {
  maxIterations: number;
  convergenceEpsilon: number;
  stressWindow: number;
  weights: {
    flow: number;
    hardDependency: number;
    softDependency: number;
    anchor: number;
    stability: number;
  };
  routing: {
    defaultObstaclePadding: number;
    flowMonotoneX: boolean;
    maxBends: number;
  };
}

export type HighLevelConstraint =
  | OrderZonesConstraint
  | StackZonesConstraint
  | DistributeConstraint
  | AlignConstraint
  | AnchorConstraint
  | ContainConstraint
  | KeepRelativeOrderConstraint
  | FixedCoordinateConstraint
  | PreferCompactnessConstraint;

export interface Selector {
  ids?: string[];
  zoneId?: string;
  tag?: string;
  shape?: NodeShape;
}

export interface OrderZonesConstraint {
  type: 'order-zones';
  axis: Axis;
  orderedZoneIds: string[];
  gap: number;
  priority?: number;
}

export interface StackZonesConstraint {
  type: 'stack-zones';
  axis: Axis;
  orderedZoneIds: string[];
  gap: number;
  priority?: number;
}

export interface DistributeConstraint {
  type: 'distribute';
  axis: Axis;
  selector: Selector;
  gap: number;
  preserveInputOrder?: boolean;
  sortBy?: 'label' | 'id';
  priority?: number;
}

export interface AlignConstraint {
  type: 'align';
  axis: Axis;
  selector: Selector;
  priority?: number;
}

export interface AnchorConstraint {
  type: 'anchor';
  selector: Selector;
  x?: number;
  y?: number;
  weight: number;
}

export interface ContainConstraint {
  type: 'contain';
  selector: Selector;
  zoneId: string;
  padding: number;
  priority?: number;
}

export interface KeepRelativeOrderConstraint {
  type: 'keep-relative-order';
  axis: Axis;
  selector: Selector;
  gap: number;
  priority?: number;
}

export interface FixedCoordinateConstraint {
  type: 'fixed-coordinate';
  nodeId: string;
  axis: Axis;
  value: number;
  priority?: number;
}

export interface PreferCompactnessConstraint {
  type: 'prefer-compactness';
  selector: Selector;
  axis: Axis;
  weight: number;
}

export type PrimitiveConstraint =
  | SeparationConstraint
  | EqualityConstraint
  | BoundConstraint
  | FixedConstraint;

export interface SeparationConstraint {
  type: 'separation';
  axis: Axis;
  left: string;
  right: string;
  gap: number;
  hard: boolean;
  priority: number;
  sourceTag?: string;
}

export interface EqualityConstraint {
  type: 'equality';
  axis: Axis;
  a: string;
  b: string;
  offset: number;
  hard: boolean;
  priority: number;
  sourceTag?: string;
}

export interface BoundConstraint {
  type: 'bound';
  axis: Axis;
  nodeId: string;
  op: '>=' | '<=';
  value: number;
  hard: boolean;
  priority: number;
  sourceTag?: string;
}

export interface FixedConstraint {
  type: 'fixed';
  axis: Axis;
  nodeId: string;
  value: number;
  hard: boolean;
  priority: number;
  sourceTag?: string;
}

export interface CompiledProblem {
  spec: LayoutSpec;
  profile: ViewportProfile;
  flowNodeOrder: string[];
  ranks: RankAssignment;
  primitives: PrimitiveConstraint[];
  zones: Record<string, ResolvedZone>;
  nodeBoxes: Record<string, NodeBox>;
}

export interface ResolvedZone {
  id: string;
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  padding: number;
}

export interface NodeBox {
  id: string;
  width: number;
  height: number;
  halfW: number;
  halfH: number;
}

export interface RankAssignment {
  nodeToRank: Record<string, number>;
  rankToNodes: Record<number, string[]>;
}

export interface LayoutState {
  x: Record<string, number>;
  y: Record<string, number>;
  prevX?: Record<string, number>;
  prevY?: Record<string, number>;
  stressHistory: number[];
  activeConstraintsX: PrimitiveConstraint[];
  activeConstraintsY: PrimitiveConstraint[];
}

export interface PolylinePoint {
  x: number;
  y: number;
}

export interface RoutedEdge {
  edgeId: string;
  points: PolylinePoint[];
  labelBox?: LayoutLabelBox;
}

export interface LayoutLabelBox {
  x: number;
  y: number;
  width: number;
  height: number;
}

export interface LayoutResult {
  nodeCenters: Record<string, { x: number; y: number }>;
  routedEdges: RoutedEdge[];
  metrics: MetricsReport;
  debug?: Record<string, unknown>;
}

export interface MetricsReport {
  nodeOverlaps: number;
  labelOverlaps: number;
  flowCrossings: number;
  totalCrossings: number;
  edgeNodeIntersections: number;
  flowMonotonicityViolations: number;
  bendsTotal: number;
  averageAngularResolution: number;
  area: number;
  stress: number;
  medianResizeDrift?: number;
}
