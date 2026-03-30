#!/usr/bin/env node
import { Client } from '@notionhq/client';
import { readFileSync } from 'fs';

let connectionSettings;

async function getAccessToken() {
  if (connectionSettings && connectionSettings.settings.expires_at && new Date(connectionSettings.settings.expires_at).getTime() > Date.now()) {
    return connectionSettings.settings.access_token;
  }
  const hostname = process.env.REPLIT_CONNECTORS_HOSTNAME;
  const xReplitToken = process.env.REPL_IDENTITY
    ? 'repl ' + process.env.REPL_IDENTITY
    : process.env.WEB_REPL_RENEWAL
    ? 'depl ' + process.env.WEB_REPL_RENEWAL
    : null;
  if (!xReplitToken) throw new Error('X-Replit-Token not found');
  connectionSettings = await fetch(
    'https://' + hostname + '/api/v2/connection?include_secrets=true&connector_names=notion',
    { headers: { 'Accept': 'application/json', 'X-Replit-Token': xReplitToken } }
  ).then(r => r.json()).then(d => d.items?.[0]);
  const accessToken = connectionSettings?.settings?.access_token || connectionSettings?.settings?.oauth?.credentials?.access_token;
  if (!accessToken) throw new Error('Notion not connected');
  return accessToken;
}

async function getNotionClient() {
  const accessToken = await getAccessToken();
  return new Client({ auth: accessToken });
}

async function findParentPage(notion) {
  const search = await notion.search({ query: "DNS Tool", filter: { property: "object", value: "page" } });
  const workspacePage = search.results.find(r => {
    const title = r.properties?.title?.title?.[0]?.plain_text;
    return title === "DNS Tool" && r.parent?.type === "workspace";
  });
  if (workspacePage) {
    return workspacePage.id;
  }
  throw new Error('No workspace-level "DNS Tool" page found. Run notion-roadmap-sync.mjs first.');
}

async function findOrCreateDatabase(notion, parentId, title, properties) {
  const search = await notion.search({ query: title, filter: { property: "object", value: "database" } });
  const existing = search.results.find(r => {
    const t = r.title?.[0]?.plain_text;
    return t === title;
  });
  if (existing) {
    console.log(`  Found existing: "${title}" → ${existing.id}`);
    const existingProps = Object.keys(existing.properties || {});
    const desiredProps = Object.keys(properties);
    const missing = desiredProps.filter(p => !existingProps.includes(p));
    if (missing.length > 0) {
      console.log(`  Migrating schema: adding ${missing.join(', ')}`);
      const patch = {};
      for (const p of missing) patch[p] = properties[p];
      await notion.databases.update({ database_id: existing.id, properties: patch });
      console.log(`  Schema migration complete`);
    }
    return existing.id;
  }

  console.log(`  Creating: "${title}"`);
  const db = await notion.databases.create({
    parent: { type: "page_id", page_id: parentId },
    title: [{ type: "text", text: { content: title } }],
    is_inline: false,
    properties,
  });
  console.log(`  Created: "${title}" → ${db.id}`);
  return db.id;
}

async function createDecisionLog(notion, parentId) {
  return findOrCreateDatabase(notion, parentId, "DNS Tool — Decision Log", {
    "Decision": { title: {} },
    "Date": { date: {} },
    "Rationale": { rich_text: {} },
    "Commit Ref": { rich_text: {} },
    "Status": {
      select: {
        options: [
          { name: "Active", color: "green" },
          { name: "Superseded", color: "yellow" },
          { name: "Reverted", color: "red" },
          { name: "Pending Review", color: "blue" },
        ]
      }
    },
    "Category": {
      select: {
        options: [
          { name: "Architecture", color: "blue" },
          { name: "Governance", color: "purple" },
          { name: "Security", color: "red" },
          { name: "Protocol", color: "green" },
          { name: "Infrastructure", color: "orange" },
          { name: "Process", color: "yellow" },
        ]
      }
    },
  });
}

async function createSessionJournal(notion, parentId) {
  return findOrCreateDatabase(notion, parentId, "DNS Tool — Session Journal", {
    "Session": { title: {} },
    "Date": { date: {} },
    "Summary": { rich_text: {} },
    "Changes Made": { rich_text: {} },
    "Files Modified": { rich_text: {} },
    "Version": { rich_text: {} },
    "Lesson ID": { rich_text: {} },
    "Root Cause": { rich_text: {} },
    "Prevention Rule": { rich_text: {} },
    "Follow-up Items": { rich_text: {} },
    "Resolved In": { rich_text: {} },
    "Unresolved": { checkbox: {} },
    "Session Type": {
      select: {
        options: [
          { name: "Feature", color: "blue" },
          { name: "Fix", color: "orange" },
          { name: "Bug Fix", color: "orange" },
          { name: "Refactor", color: "purple" },
          { name: "Pipeline", color: "green" },
          { name: "Documentation", color: "yellow" },
          { name: "Research", color: "red" },
          { name: "Security", color: "red" },
          { name: "Quality", color: "green" },
          { name: "Governance", color: "purple" },
          { name: "Testing", color: "blue" },
          { name: "Infrastructure", color: "gray" },
        ]
      }
    },
  });
}

async function createEDERegister(notion, parentId) {
  return findOrCreateDatabase(notion, parentId, "DNS Tool — EDE Register", {
    "Title": { title: {} },
    "EDE-ID": { rich_text: {} },
    "Date": { date: {} },
    "Category": {
      select: {
        options: [
          { name: "scoring_calibration", color: "blue" },
          { name: "evidence_reinterpretation", color: "purple" },
          { name: "drift_detection", color: "green" },
          { name: "resolver_trust", color: "orange" },
          { name: "false_positive", color: "red" },
          { name: "confidence_decay", color: "yellow" },
          { name: "governance_correction", color: "pink" },
          { name: "citation_error", color: "brown" },
          { name: "overclaim", color: "gray" },
          { name: "standards_misattribution", color: "default" },
        ]
      }
    },
    "Severity": {
      select: {
        options: [
          { name: "critical", color: "red" },
          { name: "significant", color: "orange" },
          { name: "moderate", color: "yellow" },
          { name: "minor", color: "green" },
          { name: "High", color: "orange" },
          { name: "Medium", color: "yellow" },
          { name: "Low", color: "green" },
        ]
      }
    },
    "Attribution": {
      select: {
        options: [
          { name: "Human Error", color: "orange" },
          { name: "AI Error", color: "red" },
          { name: "Both", color: "purple" },
          { name: "Process Gap", color: "yellow" },
        ]
      }
    },
    "Status": {
      select: {
        options: [
          { name: "open", color: "red" },
          { name: "investigating", color: "yellow" },
          { name: "closed", color: "green" },
        ]
      }
    },
    "Commit": { rich_text: {} },
    "Protocols Affected": { multi_select: {
      options: [
        { name: "SPF", color: "blue" },
        { name: "DKIM", color: "green" },
        { name: "DMARC", color: "purple" },
        { name: "DANE", color: "orange" },
        { name: "DNSSEC", color: "red" },
        { name: "BIMI", color: "yellow" },
        { name: "MTA-STS", color: "pink" },
        { name: "TLS-RPT", color: "gray" },
        { name: "CAA", color: "brown" },
        { name: "Drift", color: "default" },
      ]
    }},
    "Resolution": { rich_text: {} },
    "Confidence Impact": { rich_text: {} },
    "Correction Action": { rich_text: {} },
    "Prevention Rule": { rich_text: {} },
    "Authoritative Source": { rich_text: {} },
  });
}

async function syncEDEEntries(notion, edeDbId) {
  const integrity = JSON.parse(readFileSync('static/data/integrity_stats.json', 'utf8'));
  const events = integrity.events || [];

  const existing = await notion.databases.query({ database_id: edeDbId, page_size: 100 });
  const existingByEDE = new Map();
  for (const page of existing.results) {
    const edeId = page.properties["EDE-ID"]?.rich_text?.[0]?.plain_text;
    if (edeId) existingByEDE.set(edeId, page);
  }

  let created = 0, skipped = 0;
  for (const evt of events) {
    if (existingByEDE.has(evt.id)) {
      console.log(`  [SKIP] ${evt.id} already exists`);
      skipped++;
      continue;
    }

    const properties = {
      "Title": { title: [{ text: { content: evt.title } }] },
      "EDE-ID": { rich_text: [{ text: { content: evt.id } }] },
      "Date": { date: { start: evt.date } },
      "Category": { select: { name: evt.category } },
      "Severity": { select: { name: evt.severity } },
      "Status": { select: { name: evt.status } },
      "Commit": { rich_text: [{ text: { content: evt.commit.slice(0, 12) } }] },
      "Protocols Affected": { multi_select: evt.protocols_affected.map(p => ({ name: p })) },
      "Resolution": { rich_text: [{ text: { content: (evt.resolution || '').slice(0, 2000) } }] },
      "Confidence Impact": { rich_text: [{ text: { content: (evt.confidence_impact || '').slice(0, 2000) } }] },
    };

    await notion.pages.create({ parent: { database_id: edeDbId }, properties });
    console.log(`  [OK] ${evt.id}: ${evt.title}`);
    created++;
  }

  console.log(`  EDE sync: ${created} created, ${skipped} skipped`);
}

async function createArchitecturePage(notion, parentId) {
  const search = await notion.search({ query: "DNS Tool — Architecture Overview", filter: { property: "object", value: "page" } });
  const existing = search.results.find(r => {
    const t = r.properties?.title?.title?.[0]?.plain_text;
    return t === "DNS Tool — Architecture Overview";
  });
  if (existing) {
    console.log(`  Found existing: "Architecture Overview" → ${existing.id}`);
    return existing.id;
  }

  const page = await notion.pages.create({
    parent: { type: "page_id", page_id: parentId },
    properties: {
      title: { title: [{ text: { content: "DNS Tool — Architecture Overview" } }] },
    },
    children: [
      {
        object: "block",
        type: "heading_2",
        heading_2: { rich_text: [{ text: { content: "Canonical Hierarchy" } }] },
      },
      {
        object: "block",
        type: "numbered_list_item",
        numbered_list_item: { rich_text: [{ text: { content: "Git (IT-Help-San-Diego/dns-tool) — single source of truth for all code, diagrams, and documentation" } }] },
      },
      {
        object: "block",
        type: "numbered_list_item",
        numbered_list_item: { rich_text: [{ text: { content: "Architecture Page (/architecture) — public investor-facing rendering of Git-canonical diagrams" } }] },
      },
      {
        object: "block",
        type: "numbered_list_item",
        numbered_list_item: { rich_text: [{ text: { content: "Miro Board (uXjVG83d8PY=) — internal collaboration mirror (PRIVATE, requires login)" } }] },
      },
      {
        object: "block",
        type: "numbered_list_item",
        numbered_list_item: { rich_text: [{ text: { content: "Notion (this workspace) — control plane, collaboration hub, decision log, EDE register" } }] },
      },
      {
        object: "block",
        type: "numbered_list_item",
        numbered_list_item: { rich_text: [{ text: { content: "GitHub Issues — accountability, triage, external contributions" } }] },
      },
      {
        object: "block",
        type: "divider",
        divider: {},
      },
      {
        object: "block",
        type: "heading_2",
        heading_2: { rich_text: [{ text: { content: "Live Links" } }] },
      },
      {
        object: "block",
        type: "bulleted_list_item",
        bulleted_list_item: { rich_text: [
          { text: { content: "Production: " } },
          { text: { content: "https://dnstool.it-help.tech", link: { url: "https://dnstool.it-help.tech" } } },
        ]},
      },
      {
        object: "block",
        type: "bulleted_list_item",
        bulleted_list_item: { rich_text: [
          { text: { content: "Architecture: " } },
          { text: { content: "https://dnstool.it-help.tech/architecture", link: { url: "https://dnstool.it-help.tech/architecture" } } },
        ]},
      },
      {
        object: "block",
        type: "bulleted_list_item",
        bulleted_list_item: { rich_text: [
          { text: { content: "GitHub: " } },
          { text: { content: "https://github.com/IT-Help-San-Diego/dns-tool", link: { url: "https://github.com/IT-Help-San-Diego/dns-tool" } } },
        ]},
      },
      {
        object: "block",
        type: "divider",
        divider: {},
      },
      {
        object: "block",
        type: "heading_2",
        heading_2: { rich_text: [{ text: { content: "Sync Pipeline" } }] },
      },
      {
        object: "block",
        type: "paragraph",
        paragraph: { rich_text: [{ text: { content: "The three-layer sync pipeline ensures diagrams flow from Git Mermaid sources through SVG rendering to Miro board mirrors. Pipeline runs: render-diagrams.sh → sync-mermaid-miro.mjs (idempotent, widget-ID tracked) → verify-pipeline-sync.mjs (fail-closed on drift)." } }] },
      },
      {
        object: "block",
        type: "heading_2",
        heading_2: { rich_text: [{ text: { content: "Version" } }] },
      },
      {
        object: "block",
        type: "paragraph",
        paragraph: { rich_text: [{ text: { content: "Current: 26.35.08 | License: BUSL-1.1 | DOI: 10.5281/zenodo.18854899" } }] },
      },
    ],
  });
  console.log(`  Created: "Architecture Overview" → ${page.id}`);
  return page.id;
}

async function seedDecisionLog(notion, decisionDbId) {
  const existing = await notion.databases.query({ database_id: decisionDbId, page_size: 100 });
  if (existing.results.length > 0) {
    console.log(`  Decision Log already has ${existing.results.length} entries — skipping seed`);
    return;
  }

  const decisions = [
    {
      decision: "Git is canonical source of truth for all diagrams and documentation",
      date: "2026-03-07",
      rationale: "Miro cannot be updated in-place (API limitation). Architecture page renders Git-canonical Mermaid. Eliminates governance conflict between BOUNDARY_MATRIX.md and architecture.html.",
      category: "Governance",
      status: "Active",
    },
    {
      decision: "Notion as public collaboration hub and control plane",
      date: "2026-03-07",
      rationale: "Full bidirectional API access confirmed. Massively underutilized with only roadmap DB. Decision log, session journal, and EDE register added.",
      category: "Governance",
      status: "Active",
    },
    {
      decision: "SVG drift promoted from warning to error in verify pipeline",
      date: "2026-03-07",
      rationale: "Pipeline must fail-closed on stale SVGs. A warning allowed drift to go unnoticed. Errors force re-render before deployment.",
      category: "Process",
      status: "Active",
    },
    {
      decision: "Miro sync refactored to idempotent delete+create pattern",
      date: "2026-03-07",
      rationale: "Previous implementation always POST-created new images, causing duplicates. Widget IDs now tracked in pipeline-config.json for delete-before-create.",
      category: "Infrastructure",
      status: "Active",
    },
    {
      decision: "GitHub labels standardized with triage/priority/type taxonomy",
      date: "2026-03-07",
      rationale: "Issue templates referenced labels that didn't exist. Labels now created: triage:{research,ux,security-redirect}, priority:{P0-P3}, type:{bug,enhancement,documentation,ede}.",
      category: "Process",
      status: "Active",
    },
  ];

  for (const d of decisions) {
    await notion.pages.create({
      parent: { database_id: decisionDbId },
      properties: {
        "Decision": { title: [{ text: { content: d.decision } }] },
        "Date": { date: { start: d.date } },
        "Rationale": { rich_text: [{ text: { content: d.rationale } }] },
        "Category": { select: { name: d.category } },
        "Status": { select: { name: d.status } },
      },
    });
    console.log(`  [OK] Decision: ${d.decision.slice(0, 60)}...`);
  }
}

(async () => {
  try {
    const notion = await getNotionClient();
    console.log("Notion connected\n");

    const parentId = await findParentPage(notion);
    console.log(`Parent page: ${parentId}\n`);

    console.log("=== Decision Log ===");
    const decisionDbId = await createDecisionLog(notion, parentId);
    await seedDecisionLog(notion, decisionDbId);

    console.log("\n=== Session Journal ===");
    const sessionDbId = await createSessionJournal(notion, parentId);

    console.log("\n=== EDE Register ===");
    const edeDbId = await createEDERegister(notion, parentId);
    await syncEDEEntries(notion, edeDbId);

    console.log("\n=== Architecture Overview ===");
    await createArchitecturePage(notion, parentId);

    console.log("\n" + "=".repeat(55));
    console.log("  Notion Control Plane Setup Complete");
    console.log("  Decision Log:          " + decisionDbId);
    console.log("  Session Journal:       " + sessionDbId);
    console.log("  EDE Register:          " + edeDbId);
    console.log("=".repeat(55) + "\n");
  } catch (e) {
    console.error("Error:", e.message);
    if (e.body) console.error("Details:", e.body);
    process.exit(1);
  }
})();
