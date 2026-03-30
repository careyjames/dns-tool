import { readFileSync } from 'node:fs';
import type { LayoutSpec } from './types.js';
import { NODE_SHAPES, EDGE_CLASSES } from './types.js';

interface ValidationError {
  path: string;
  message: string;
}

function validateNodes(spec: LayoutSpec, zoneIds: Set<string>, errors: ValidationError[]): Set<string> {
  const nodeIds = new Set<string>();
  for (const node of spec.nodes) {
    if (nodeIds.has(node.id)) {
      errors.push({ path: `nodes.${node.id}`, message: 'duplicate node ID' });
    }
    nodeIds.add(node.id);

    if (!zoneIds.has(node.zoneId)) {
      errors.push({ path: `nodes.${node.id}.zoneId`, message: `references unknown zone "${node.zoneId}"` });
    }
    if (!NODE_SHAPES.has(node.shape)) {
      errors.push({ path: `nodes.${node.id}.shape`, message: `invalid shape "${node.shape}"` });
    }
    if (node.width <= 0 || node.height <= 0) {
      errors.push({ path: `nodes.${node.id}`, message: 'width and height must be positive' });
    }
  }
  return nodeIds;
}

function validateEdges(spec: LayoutSpec, nodeIds: Set<string>, errors: ValidationError[]): void {
  const edgeIds = new Set<string>();
  for (const edge of spec.edges) {
    if (edgeIds.has(edge.id)) {
      errors.push({ path: `edges.${edge.id}`, message: 'duplicate edge ID' });
    }
    edgeIds.add(edge.id);

    if (!nodeIds.has(edge.source)) {
      errors.push({ path: `edges.${edge.id}.source`, message: `references unknown node "${edge.source}"` });
    }
    if (!nodeIds.has(edge.target)) {
      errors.push({ path: `edges.${edge.id}.target`, message: `references unknown node "${edge.target}"` });
    }
    if (!EDGE_CLASSES.has(edge.kind)) {
      errors.push({ path: `edges.${edge.id}.kind`, message: `invalid kind "${edge.kind}"` });
    }
  }
}

function validateSpec(spec: LayoutSpec): ValidationError[] {
  const errors: ValidationError[] = [];

  if (!spec.metadata?.name) errors.push({ path: 'metadata.name', message: 'missing' });
  if (!spec.metadata?.seed) errors.push({ path: 'metadata.seed', message: 'missing' });
  if (spec.metadata?.units !== 'px') errors.push({ path: 'metadata.units', message: 'must be "px"' });

  if (!spec.viewportProfiles || Object.keys(spec.viewportProfiles).length === 0) {
    errors.push({ path: 'viewportProfiles', message: 'must have at least one profile' });
  }

  const zoneIds = new Set(spec.zones.map(z => z.id));
  if (zoneIds.size !== spec.zones.length) {
    errors.push({ path: 'zones', message: 'duplicate zone IDs' });
  }

  const nodeIds = validateNodes(spec, zoneIds, errors);
  validateEdges(spec, nodeIds, errors);

  for (const profileId of Object.keys(spec.viewportProfiles)) {
    const profile = spec.viewportProfiles[profileId];
    for (const zid of zoneIds) {
      if (!profile.zoneTemplates[zid]) {
        errors.push({ path: `viewportProfiles.${profileId}.zoneTemplates`, message: `missing template for zone "${zid}"` });
      }
    }
  }

  return errors;
}

function main() {
  const path = process.argv[2];
  if (!path) {
    console.error('Usage: tsx src/validate.ts <spec.json>');
    process.exit(1);
  }

  const raw = readFileSync(path, 'utf-8');
  const spec: LayoutSpec = JSON.parse(raw);
  const errors = validateSpec(spec);

  if (errors.length > 0) {
    console.error(`INVALID: ${errors.length} error(s):`);
    for (const e of errors) {
      console.error(`  ${e.path}: ${e.message}`);
    }
    process.exit(1);
  } else {
    console.log(`VALID: ${spec.nodes.length} nodes, ${spec.edges.length} edges, ${spec.zones.length} zones`);
    console.log(`Profiles: ${Object.keys(spec.viewportProfiles).join(', ')}`);
    const flowCount = spec.edges.filter(e => e.kind === 'flow').length;
    const hardCount = spec.edges.filter(e => e.kind === 'hard_dependency').length;
    const softCount = spec.edges.filter(e => e.kind === 'soft_dependency').length;
    console.log(`Edges: ${flowCount} flow, ${hardCount} hard_dependency, ${softCount} soft_dependency`);
    process.exit(0);
  }
}

main();
