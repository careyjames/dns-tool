#!/usr/bin/env node
// DNS Tool — Notion Roadmap Sync
// Creates/syncs a kanban-style roadmap database in Notion
// Integration: Replit Notion connector (connection:conn_notion_01KJ83GM6TZV44W76ZEQ0C2TN8)

import { Client } from '@notionhq/client';

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

const ROADMAP_ITEMS = [
  { title: "Intelligence Confidence Audit Engine (ICAE)", status: "Done", type: "Feature", priority: "High", version: "129 Test Cases" },
  { title: "Intelligence Currency Assurance Engine (ICuAE)", status: "Done", type: "Feature", priority: "High", version: "29 Test Cases" },
  { title: "Email Header Analyzer", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "Drift Engine Phases 1–2", status: "Done", type: "Feature", priority: "High", version: "v26.19.40" },
  { title: "Architecture Page", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.77–83" },
  { title: "DKIM Selector Expansion (39→81+)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.69–70" },
  { title: "Brand Verdict Matrix Overhaul", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.71" },
  { title: "Optional Authentication (Google OAuth 2.0 PKCE)", status: "Done", type: "Feature", priority: "High", version: "v26.20.56–57" },
  { title: "Probe Network First Node", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "LLM Documentation Strategy", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.26" },
  { title: "Color Science Page (CIE Scotopic, WCAG)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Badge System (SVG, Shields.io)", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Domain Snapshot", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Certificate Transparency Resilience", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.76" },
  { title: "Nmap DNS Security Probing", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "One-Liner Verification Commands", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Zone File Upload for Analysis", status: "Done", type: "Feature", priority: "Medium", version: "v26.20.0+" },
  { title: "Hash Integrity Audit Engine", status: "Done", type: "Feature", priority: "Medium", version: "v26.21.45" },
  { title: "Download Verification (SHA-3-512)", status: "Done", type: "Feature", priority: "Medium", version: "v26.21.49–50" },
  { title: "Accountability Log", status: "Done", type: "Feature", priority: "Medium", version: "v26.21.46" },
  { title: "Glass Badge System (ICAE, Protocol, Section)", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.38–43" },
  { title: "Covert Recon Mode", status: "Done", type: "Feature", priority: "High", version: "v26.20.0+" },
  { title: "Web/DNS/Email Hosting Detection", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.43" },
  { title: "Question Branding System (dt-question)", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.70" },
  { title: "XSS Security Fix (Tooltip Safe DOM)", status: "Done", type: "Security", priority: "High", version: "v26.25.26" },
  { title: "Approach & Methodology Page", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.83" },
  { title: "TTL Alignment & Big Picture Questions", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.93" },
  { title: "Unified Confidence Aggregation (ICD 203)", status: "Done", type: "Feature", priority: "High", version: "v26.25.94" },
  { title: "Homepage Simplification & TTL Deep Linking", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.95" },
  { title: "DMARC External Auth Remediation", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.95" },
  { title: "Symbiotic Security — Five Archetypes Section", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.96" },
  { title: "Methodology Page Rename & Cross-Links", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.96" },
  { title: "Delegation Consistency Analyzer", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.94" },
  { title: "Nameserver Fleet Matrix", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.94" },
  { title: "DNSSEC Operations Deep Dive", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.94" },
  { title: "Live SonarCloud Badge & Evidence Qualification", status: "Done", type: "Feature", priority: "Medium", version: "v26.25.97" },
  { title: "Probe Network Second Node (Kali)", status: "Done", type: "Feature", priority: "High", version: "v26.26.02" },
  { title: "Multi-Probe Consensus Engine", status: "Done", type: "Feature", priority: "High", version: "v26.26.02" },
  { title: "Public Roadmap Page", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.02" },
  { title: "SonarCloud Quality Gate Fix", status: "Done", type: "Quality", priority: "High", version: "v26.26.03" },
  { title: "Nmap Subdomain Enrichment", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.02" },
  { title: "Admin Probe Management Panel", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.02" },
  { title: "LLMs.txt & JSON-LD Consistency Audit", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.04" },
  { title: "Stats Page Visual Redesign", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.05" },
  { title: "Notion Bidirectional Sync", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.05" },
  { title: "Covert Mode Color Leak Audit", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.05" },
  { title: "Stats Confidence Engine Preview Card", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.05" },
  { title: "Failed Analysis Transparency Page", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.05" },
  { title: "Documentation Reality Check (LLMs + JSON-LD + Roadmap)", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.06" },
  { title: "Covert Mode Tactical Red Filter (MIL-STD-3009)", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.08" },
  { title: "Covert Mode Environment Presets (Submarine/Tactical/Operator)", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.10" },
  { title: "Operator Mode Color Science (mix-blend-mode: color)", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.11" },
  { title: "Covert Environment Icons & Accent Gray Hierarchy", status: "Done", type: "Feature", priority: "Medium", version: "v26.26.12" },
  { title: "SonarCloud Deep Sweep — String Constants & Regex Hardening", status: "Done", type: "Quality", priority: "High", version: "v26.26.12" },
  { title: "SonarCloud Hotspot & Vulnerability Review — Full Audit Trail", status: "Done", type: "Quality", priority: "High", version: "v26.26.15" },
  { title: "Rules of Engagement Page (/roe)", status: "Done", type: "Feature", priority: "High", version: "v26.26.17" },
  { title: "Nmap Ethics Statement on /approach", status: "Done", type: "Feature", priority: "High", version: "v26.26.17" },
  { title: "GPTZero AI Detection Audit — Full Site Scan", status: "Done", type: "Quality", priority: "High", version: "v26.26.17" },
  { title: "Sources Page CSS Mid-Word Break Fix", status: "Done", type: "Bug Fix", priority: "Medium", version: "v26.26.17" },
  { title: "Fact-Check Corrections (TTL Tuner, 1983 Tagline)", status: "Done", type: "Quality", priority: "Medium", version: "v26.26.17" },
  { title: "Homepage GPTZero Compliance Rewrite", status: "Done", type: "Quality", priority: "High", version: "v26.26.17" },
  { title: "Visual Cohesion — Top-to-Bottom Consistency", status: "In Progress", type: "Feature", priority: "Medium", notes: "Glass treatment, question branding, token system" },
  { title: "GPTZero Page-by-Page Prose Optimization", status: "In Progress", type: "Quality", priority: "High", notes: "Rewrite flagged sentences across all pages to reduce AI detection scores. Target: <20% per page." },
  { title: "Covert Mode Mobile Red Screen Fix", status: "Next Up", type: "Bug Fix", priority: "High", notes: "iPhone 17 Pro shows near-solid red in report view. mix-blend-mode: multiply on OLED. May need mobile media query or opacity adjustment." },
  { title: "Morse Code Easter Egg", status: "In Progress", type: "Feature", priority: "Low", notes: "GarageBand Morse code audio (morse-hack-the-planet). AAC 192kbps export." },
  { title: "DoH/DoT Detection", status: "Next Up", type: "Feature", priority: "High", notes: "DNS-over-HTTPS (RFC 8484) and DNS-over-TLS (RFC 7858) posture analysis" },
  { title: "Distributed Probe Mesh (Good Net Citizens)", status: "Next Up", type: "Feature", priority: "High", notes: "Volunteer browser-based DNS probes via DoH relay" },
  { title: "API Access (Programmatic Analysis)", status: "Next Up", type: "Feature", priority: "High", notes: "Rate limiting, authentication, versioning" },
  { title: "CLI App (Homebrew/Binary)", status: "Next Up", type: "Feature", priority: "High", notes: "Terminal app for macOS/Linux" },
  { title: "Personal Analysis History", status: "Backlog", type: "Feature", priority: "Medium", notes: "Per-user session tracking" },
  { title: "Drift Notifications (Discord + Webhook)", status: "Done", type: "Feature", priority: "High", version: "v26.34.54", notes: "Multi-channel drift alerting: Discord embeds, generic webhooks. 30s delivery loop, SSRF-protected, per-endpoint routing." },
  { title: "GitHub Issues Triage (3-Tier)", status: "Done", type: "Feature", priority: "High", version: "v26.34.54", notes: "Research Mission Critical (P0), Cosmetic UX/UI, Security Vulnerability redirect. Kubernetes-style label state machine. Auto-validation workflows." },
  { title: "Add to Drift Monitoring Button", status: "Next Up", type: "Feature", priority: "High", notes: "One-click watchlist enrollment from results.html for logged-in users" },
  { title: "Email Notification Channel (SES/SMTP)", status: "Next Up", type: "Feature", priority: "High", notes: "Executive-friendly email alerts for drift events" },
  { title: "HTTPS-Only Webhook Enforcement", status: "Next Up", type: "Feature", priority: "High", notes: "Reject non-HTTPS webhook endpoints for security" },
  { title: "Drift Engine Alerts", status: "Done", type: "Feature", priority: "Medium", version: "v26.34.54", notes: "Replaced by Drift Notifications. Discord + generic webhook operational. Email channel planned." },
  { title: "Saved Reports", status: "Backlog", type: "Feature", priority: "Medium", notes: "Snapshot storage and user library" },
  { title: "Drift Engine Phases 3–4", status: "Backlog", type: "Feature", priority: "Medium", notes: "Timeline visualization, scheduled monitoring" },
  { title: "Probe Security.txt + Landing Pages", status: "Backlog", type: "Feature", priority: "Medium", notes: "Transparency artifacts for probe VPS nodes" },
  { title: "Homebrew Distribution", status: "Backlog", type: "Feature", priority: "Medium", notes: "macOS/Linux package distribution for CLI app" },
  { title: "Globalping.io Integration", status: "Backlog", type: "Feature", priority: "Low", notes: "Distributed DNS resolution from 100+ locations" },
  { title: "Zone File Import as Drift Baseline", status: "Backlog", type: "Feature", priority: "Low", notes: "Baseline snapshot comparison" },
  { title: "Raw Intelligence API Access", status: "Backlog", type: "Feature", priority: "Low", notes: "Direct intelligence access" },
  { title: "ISC Recommendation Path Integration", status: "Backlog", type: "Feature", priority: "Low", notes: "Integration with ISC remediation/hardening recommendations" },
];

async function findOrCreateDatabase(notion) {
  const search = await notion.search({ query: "DNS Tool Roadmap", filter: { property: "object", value: "database" } });
  const existing = search.results.find(r => {
    const title = r.title?.[0]?.plain_text;
    return title === "DNS Tool Roadmap";
  });
  if (existing) {
    console.log("Found existing database:", existing.id);
    return existing.id;
  }

  console.log("Creating new database...");
  const db = await notion.databases.create({
    parent: { type: "page_id", page_id: await getParentPageId(notion) },
    title: [{ type: "text", text: { content: "DNS Tool Roadmap" } }],
    is_inline: false,
    properties: {
      "Title": { title: {} },
      "Status": {
        select: {
          options: [
            { name: "Backlog", color: "default" },
            { name: "Next Up", color: "yellow" },
            { name: "In Progress", color: "blue" },
            { name: "Done", color: "green" },
          ]
        }
      },
      "Type": {
        select: {
          options: [
            { name: "Feature", color: "blue" },
            { name: "Security", color: "red" },
            { name: "Bug", color: "orange" },
            { name: "Idea", color: "purple" },
          ]
        }
      },
      "Priority": {
        select: {
          options: [
            { name: "High", color: "red" },
            { name: "Medium", color: "yellow" },
            { name: "Low", color: "gray" },
          ]
        }
      },
      "Version": { rich_text: {} },
      "Notes": { rich_text: {} },
    }
  });
  console.log("Created database:", db.id);
  return db.id;
}

async function getParentPageId(notion) {
  const search = await notion.search({ query: "DNS Tool", filter: { property: "object", value: "page" } });
  if (search.results.length > 0) {
    return search.results[0].id;
  }
  const page = await notion.pages.create({
    parent: { type: "workspace", workspace: true },
    properties: { title: { title: [{ text: { content: "DNS Tool" } }] } },
  });
  console.log("Created parent page:", page.id);
  return page.id;
}

async function getAllPages(notion, databaseId) {
  const pages = [];
  let cursor = undefined;
  do {
    const response = await notion.databases.query({
      database_id: databaseId,
      page_size: 100,
      start_cursor: cursor,
    });
    pages.push(...response.results);
    cursor = response.has_more ? response.next_cursor : undefined;
  } while (cursor);
  return pages;
}

function getPageTitle(page) {
  return page.properties.Title?.title?.[0]?.plain_text || '';
}

function getPageStatus(page) {
  return page.properties.Status?.select?.name || '';
}

function getPageType(page) {
  return page.properties.Type?.select?.name || '';
}

function getPagePriority(page) {
  return page.properties.Priority?.select?.name || '';
}

function getPageNotes(page) {
  return page.properties.Notes?.rich_text?.[0]?.plain_text || '';
}

async function syncDatabase(notion, databaseId) {
  const existingPages = await getAllPages(notion, databaseId);
  const existingByTitle = new Map();
  for (const page of existingPages) {
    const title = getPageTitle(page);
    if (title) existingByTitle.set(title, page);
  }
  console.log(`Database has ${existingByTitle.size} existing items`);

  const codebaseTitles = new Set(ROADMAP_ITEMS.map(i => i.title));
  let created = 0, updated = 0, skipped = 0;

  for (const item of ROADMAP_ITEMS) {
    const existingPage = existingByTitle.get(item.title);

    if (!existingPage) {
      const properties = {
        "Title": { title: [{ text: { content: item.title } }] },
        "Status": { select: { name: item.status } },
        "Type": { select: { name: item.type } },
        "Priority": { select: { name: item.priority } },
      };
      if (item.version) {
        properties["Version"] = { rich_text: [{ text: { content: item.version } }] };
      }
      if (item.notes) {
        properties["Notes"] = { rich_text: [{ text: { content: item.notes } }] };
      }
      await notion.pages.create({ parent: { database_id: databaseId }, properties });
      created++;
      continue;
    }

    const notionStatus = getPageStatus(existingPage);
    if (notionStatus !== item.status) {
      const updateProps = {
        "Status": { select: { name: item.status } },
      };
      if (item.version) {
        updateProps["Version"] = { rich_text: [{ text: { content: item.version } }] };
      }
      await notion.pages.update({ page_id: existingPage.id, properties: updateProps });
      console.log(`  Updated: "${item.title}" (${notionStatus} → ${item.status})`);
      updated++;
    } else {
      skipped++;
    }
  }

  const notionOnlyItems = [];
  for (const [title, page] of existingByTitle) {
    if (!codebaseTitles.has(title)) {
      notionOnlyItems.push({
        title,
        status: getPageStatus(page),
        type: getPageType(page),
        priority: getPagePriority(page),
        notes: getPageNotes(page),
      });
    }
  }

  console.log(`\nSync results: ${created} created, ${updated} updated, ${skipped} unchanged`);

  if (notionOnlyItems.length > 0) {
    console.log(`\n--- Ideas from Notion (${notionOnlyItems.length} items not in codebase) ---`);
    for (const item of notionOnlyItems) {
      console.log(`  [${item.status}] ${item.title} (${item.type}, ${item.priority})${item.notes ? ' — ' + item.notes : ''}`);
    }
    console.log('--- End Notion-only items ---\n');
  }
}

(async () => {
  try {
    const notion = await getNotionClient();
    console.log("Notion connected");
    const databaseId = await findOrCreateDatabase(notion);
    await syncDatabase(notion, databaseId);
    console.log("Roadmap sync complete!");
    console.log(`Database ID: ${databaseId}`);
  } catch (e) {
    console.error("Error:", e.message);
    if (e.body) console.error("Details:", e.body);
    process.exit(1);
  }
})();
