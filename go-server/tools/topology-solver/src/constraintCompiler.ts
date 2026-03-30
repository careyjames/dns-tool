import {
  Axis,
  BoundConstraint,
  CompiledProblem,
  ContainConstraint,
  DistributeConstraint,
  EqualityConstraint,
  HighLevelConstraint,
  LayoutSpec,
  NodeBox,
  PrimitiveConstraint,
  ResolvedZone,
  Selector,
  SeparationConstraint,
  ViewportProfile,
} from './types.js';
import { computeNodeBox, estimateTextWidth } from './nodeMetrics.js';

function stableCompare(a: string, b: string): number {
  return a.localeCompare(b);
}

function selectNodeIds(spec: LayoutSpec, selector: Selector): string[] {
  const out = spec.nodes
    .filter((n) => {
      if (selector.ids && !selector.ids.includes(n.id)) return false;
      if (selector.zoneId && n.zoneId !== selector.zoneId) return false;
      if (selector.tag && !(n.tags ?? []).includes(selector.tag)) return false;
      if (selector.shape && n.shape !== selector.shape) return false;
      return true;
    })
    .map((n) => n.id);

  return out.sort(stableCompare);
}

function boundForZone(
  nodeId: string,
  axis: Axis,
  zone: ResolvedZone,
  halfExtent: number,
  padding: number,
  priority = 1000,
  sourceTag = 'zone-containment',
): BoundConstraint[] {
  if (axis === 'x') {
    return [
      {
        type: 'bound',
        axis,
        nodeId,
        op: '>=',
        value: zone.x1 + padding + halfExtent,
        hard: true,
        priority,
        sourceTag,
      },
      {
        type: 'bound',
        axis,
        nodeId,
        op: '<=',
        value: zone.x2 - padding - halfExtent,
        hard: true,
        priority,
        sourceTag,
      },
    ];
  }

  return [
    {
      type: 'bound',
      axis,
      nodeId,
      op: '>=',
      value: zone.y1 + padding + halfExtent,
      hard: true,
      priority,
      sourceTag,
    },
    {
      type: 'bound',
      axis,
      nodeId,
      op: '<=',
      value: zone.y2 - padding - halfExtent,
      hard: true,
      priority,
      sourceTag,
    },
  ];
}

export function compileConstraints(
  spec: LayoutSpec,
  profile: ViewportProfile,
): CompiledProblem {
  const zones = resolveZones(spec, profile);
  const primitives: PrimitiveConstraint[] = [];

  for (const node of [...spec.nodes].sort((a, b) => stableCompare(a.id, b.id))) {
    const zone = zones[node.zoneId];
    if (!zone) {
      throw new Error(`Node ${node.id} references unknown zone ${node.zoneId}`);
    }
    let halfW = node.width / 2;
    let halfH = node.height / 2;
    if (node.radius != null) {
      const box = computeNodeBox(
        {
          shape: node.shape,
          radius: node.radius,
          label: node.label,
          sub: node.sub ?? null,
          scale: 1,
          fontLabel: 14,
          fontSub: 10,
        },
        estimateTextWidth,
      );
      halfW = box.halfW;
      halfH = box.halfH;
    }
    primitives.push(
      ...boundForZone(node.id, 'x', zone, halfW, zone.padding),
      ...boundForZone(node.id, 'y', zone, halfH, zone.padding),
    );
  }

  for (const c of spec.highLevelConstraints) {
    primitives.push(...compileHighLevelConstraint(spec, zones, c));
  }

  return {
    spec,
    profile,
    flowNodeOrder: [],
    ranks: { nodeToRank: {}, rankToNodes: {} },
    primitives,
    zones,
    nodeBoxes: Object.fromEntries(
      spec.nodes.map((n) => {
        if (n.radius != null) {
          const box = computeNodeBox(
            {
              shape: n.shape,
              radius: n.radius,
              label: n.label,
              sub: n.sub ?? null,
              scale: 1,
              fontLabel: 14,
              fontSub: 10,
            },
            estimateTextWidth,
          );
          box.id = n.id;
          return [n.id, box as NodeBox];
        }
        return [
          n.id,
          {
            id: n.id,
            width: n.width,
            height: n.height,
            halfW: n.width / 2,
            halfH: n.height / 2,
          },
        ];
      }),
    ),
  };
}

function resolveZones(
  spec: LayoutSpec,
  profile: ViewportProfile,
): Record<string, ResolvedZone> {
  const out: Record<string, ResolvedZone> = {};
  for (const z of spec.zones) {
    const t = profile.zoneTemplates[z.id];
    if (!t) {
      throw new Error(`Missing viewport zone template for zone ${z.id}`);
    }
    out[z.id] = {
      id: z.id,
      x1: t.x1,
      y1: t.y1,
      x2: t.x2,
      y2: t.y2,
      padding: t.padding ?? 8,
    };
  }
  return out;
}

function compileHighLevelConstraint(
  spec: LayoutSpec,
  zones: Record<string, ResolvedZone>,
  c: HighLevelConstraint,
): PrimitiveConstraint[] {
  switch (c.type) {
    case 'order-zones':
    case 'stack-zones':
      return compileZoneOrdering(spec, zones, c.axis, c.orderedZoneIds, c.gap, c.priority ?? 900, c.type);

    case 'distribute':
      return compileDistribution(spec, c);

    case 'align':
      return compileAlignment(spec, c.selector, c.axis, c.priority ?? 850);

    case 'anchor':
      return [];
      // Soft anchor terms belong in the objective, not in primitive hard constraints.

    case 'contain':
      return compileContain(spec, zones, c);

    case 'keep-relative-order':
      return compileKeepRelativeOrder(spec, c.selector, c.axis, c.gap, c.priority ?? 800);

    case 'fixed-coordinate':
      return [
        {
          type: 'fixed',
          axis: c.axis,
          nodeId: c.nodeId,
          value: c.value,
          hard: true,
          priority: c.priority ?? 1000,
          sourceTag: 'fixed-coordinate',
        },
      ];

    case 'prefer-compactness':
      return [];
      // Soft term in the objective, not a primitive hard constraint.

    default: {
      const neverValue: never = c;
      throw new Error(`Unsupported high-level constraint ${(neverValue as any).type}`);
    }
  }
}

function compileZoneOrdering(
  spec: LayoutSpec,
  zones: Record<string, ResolvedZone>,
  axis: Axis,
  orderedZoneIds: string[],
  gap: number,
  priority: number,
  sourceTag: string,
): PrimitiveConstraint[] {
  const constraints: PrimitiveConstraint[] = [];
  for (let i = 0; i < orderedZoneIds.length - 1; i += 1) {
    const a = zones[orderedZoneIds[i]];
    const b = zones[orderedZoneIds[i + 1]];
    if (!a || !b) continue;

    const aNodes = spec.nodes.filter((n) => n.zoneId === a.id).map((n) => n.id).sort(stableCompare);
    const bNodes = spec.nodes.filter((n) => n.zoneId === b.id).map((n) => n.id).sort(stableCompare);

    for (const left of aNodes) {
      for (const right of bNodes) {
        constraints.push({
          type: 'separation',
          axis,
          left,
          right,
          gap,
          hard: true,
          priority,
          sourceTag,
        });
      }
    }
  }
  return constraints;
}

function compileDistribution(
  spec: LayoutSpec,
  c: DistributeConstraint,
): PrimitiveConstraint[] {
  let ids = selectNodeIds(spec, c.selector);
  if (c.sortBy === 'label') {
    const byId = new Map(spec.nodes.map((n) => [n.id, n]));
    ids = ids.sort((a, b) => (byId.get(a)?.label ?? a).localeCompare(byId.get(b)?.label ?? b));
  }
  const out: SeparationConstraint[] = [];
  for (let i = 0; i < ids.length - 1; i += 1) {
    out.push({
      type: 'separation',
      axis: c.axis,
      left: ids[i],
      right: ids[i + 1],
      gap: c.gap,
      hard: true,
      priority: c.priority ?? 850,
      sourceTag: 'distribute',
    });
  }
  return out;
}

function compileAlignment(
  spec: LayoutSpec,
  selector: Selector,
  axis: Axis,
  priority: number,
): PrimitiveConstraint[] {
  const ids = selectNodeIds(spec, selector);
  if (ids.length < 2) return [];
  const root = ids[0];
  const out: EqualityConstraint[] = [];
  for (let i = 1; i < ids.length; i += 1) {
    out.push({
      type: 'equality',
      axis,
      a: root,
      b: ids[i],
      offset: 0,
      hard: true,
      priority,
      sourceTag: 'align',
    });
  }
  return out;
}

function compileContain(
  spec: LayoutSpec,
  zones: Record<string, ResolvedZone>,
  c: ContainConstraint,
): PrimitiveConstraint[] {
  const ids = selectNodeIds(spec, c.selector);
  const zone = zones[c.zoneId];
  if (!zone) throw new Error(`Unknown zone ${c.zoneId}`);
  const out: PrimitiveConstraint[] = [];
  for (const id of ids) {
    const node = spec.nodes.find((n) => n.id === id);
    if (!node) continue;
    out.push(
      ...boundForZone(id, 'x', zone, node.width / 2, c.padding, c.priority ?? 1000, 'contain'),
      ...boundForZone(id, 'y', zone, node.height / 2, c.padding, c.priority ?? 1000, 'contain'),
    );
  }
  return out;
}

function compileKeepRelativeOrder(
  spec: LayoutSpec,
  selector: Selector,
  axis: Axis,
  gap: number,
  priority: number,
): PrimitiveConstraint[] {
  const ids = selectNodeIds(spec, selector);
  const out: SeparationConstraint[] = [];
  for (let i = 0; i < ids.length - 1; i += 1) {
    out.push({
      type: 'separation',
      axis,
      left: ids[i],
      right: ids[i + 1],
      gap,
      hard: true,
      priority,
      sourceTag: 'keep-relative-order',
    });
  }
  return out;
}
