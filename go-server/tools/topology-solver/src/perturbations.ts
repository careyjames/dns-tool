import type { LayoutSpec, EdgeSpec, NodeSpec } from './types.js';

export interface PerturbationDef {
  id: string;
  type: string;
  factor?: number;
  edge?: { source: string; target: string; kind: string };
  nodeId?: string;
  from?: string;
  newId?: string;
  newLabel?: string;
  zoneId?: string;
  sequence?: string[];
}

export function applyPerturbation(spec: LayoutSpec, perturbation: PerturbationDef): LayoutSpec {
  switch (perturbation.type) {
    case 'identity':
      return structuredClone(spec);
    case 'label_scale':
      return applyLabelScale(spec, perturbation.factor ?? 1);
    case 'add_edge':
      return applyAddEdge(spec, perturbation);
    case 'remove_node':
      return applyRemoveNode(spec, perturbation.nodeId!);
    case 'clone_node':
      return applyCloneNode(spec, perturbation);
    case 'viewport_sequence':
      return structuredClone(spec);
    default:
      throw new Error(`Unknown perturbation type: ${perturbation.type}`);
  }
}

function applyLabelScale(spec: LayoutSpec, factor: number): LayoutSpec {
  const copy = structuredClone(spec);
  for (const node of copy.nodes) {
    node.width = Math.round(node.width * factor);
  }
  return copy;
}

function applyAddEdge(spec: LayoutSpec, p: PerturbationDef): LayoutSpec {
  const copy = structuredClone(spec);
  if (!p.edge) return copy;

  const sourceNode = copy.nodes.find((n: NodeSpec) => n.id === p.edge!.source);
  const targetNode = copy.nodes.find((n: NodeSpec) => n.id === p.edge!.target);
  if (!sourceNode || !targetNode) return copy;

  const newEdge: EdgeSpec = {
    id: `pert_${p.id}`,
    source: p.edge.source,
    target: p.edge.target,
    kind: p.edge.kind as EdgeSpec['kind'],
    label: `added_${p.id}`,
  };
  copy.edges.push(newEdge);
  return copy;
}

function applyRemoveNode(spec: LayoutSpec, nodeId: string): LayoutSpec {
  const copy = structuredClone(spec);
  copy.nodes = copy.nodes.filter((n: NodeSpec) => n.id !== nodeId);
  copy.edges = copy.edges.filter((e: EdgeSpec) => e.source !== nodeId && e.target !== nodeId);

  for (const c of copy.highLevelConstraints) {
    if ('selector' in c && c.selector?.ids) {
      c.selector.ids = c.selector.ids.filter((id: string) => id !== nodeId);
    }
  }
  return copy;
}

function applyCloneNode(spec: LayoutSpec, p: PerturbationDef): LayoutSpec {
  const copy = structuredClone(spec);
  const source = copy.nodes.find((n: NodeSpec) => n.id === p.from);
  if (!source || !p.newId) return copy;

  const newNode: NodeSpec = {
    ...structuredClone(source),
    id: p.newId,
    label: p.newLabel ?? p.newId,
    zoneId: p.zoneId ?? source.zoneId,
  };
  copy.nodes.push(newNode);

  const clonedEdges = copy.edges
    .filter((e: EdgeSpec) => e.target === p.from && e.kind === 'flow')
    .map((e: EdgeSpec) => ({
      id: `clone_${p.newId}_${e.id}`,
      source: e.source,
      target: p.newId!,
      kind: 'flow' as const,
    }));
  copy.edges.push(...clonedEdges);

  return copy;
}

export function getViewportSequence(perturbation: PerturbationDef): string[] | null {
  if (perturbation.type === 'viewport_sequence' && perturbation.sequence) {
    return perturbation.sequence;
  }
  return null;
}
