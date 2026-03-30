#!/usr/bin/env node
import { readFileSync } from 'fs';

const API_KEY = process.env.GPTZERO_API;
const BASE_URL = 'https://api.gptzero.me/v2/predict/text';
const MODEL_VERSION = '2026-02-14-base';
const APP_BASE = process.env.APP_URL || 'http://localhost:5000';

const PAGES = [
  { name: 'About (Origin Story)', path: '/about' },
  { name: 'Approach (Methodology)', path: '/approach' },
  { name: 'Sources', path: '/sources' },
  { name: 'Security Policy', path: '/security-policy' },
  { name: 'Architecture', path: '/architecture' },
  { name: 'Confidence', path: '/confidence' },
  { name: 'Changelog', path: '/changelog' },
  { name: 'Subdomain FAQ', path: '/faq/subdomains' },
];

const TEXT_FILES = [
  { name: 'llms.txt', path: '/llms.txt' },
  { name: 'llms-full.txt', path: '/llms-full.txt' },
];

async function extractTextFromHTML(html) {
  let text = html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
    .replace(/<nav[^>]*>[\s\S]*?<\/nav>/gi, '')
    .replace(/<footer[^>]*>[\s\S]*?<\/footer>/gi, '')
    .replace(/<head[^>]*>[\s\S]*?<\/head>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&mdash;/g, '\u2014')
    .replace(/&ndash;/g, '\u2013')
    .replace(/&rsquo;/g, '\u2019')
    .replace(/&ldquo;/g, '\u201C')
    .replace(/&rdquo;/g, '\u201D')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&nbsp;/g, ' ')
    .replace(/&sect;/g, '\u00A7')
    .replace(/&middot;/g, '\u00B7')
    .replace(/&#\d+;/g, '')
    .replace(/\s+/g, ' ')
    .trim();

  const skipPhrases = [
    'Skip to main content',
    'DNS Tool v',
    'Toggle navigation',
    'Toggle Covert',
    'Sign In',
    'Sign Out',
  ];
  for (const phrase of skipPhrases) {
    text = text.replace(new RegExp(phrase.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '');
  }

  return text;
}

async function fetchPage(path) {
  const url = `${APP_BASE}${path}`;
  const resp = await fetch(url, {
    headers: { 'User-Agent': 'GPTZeroScanner/1.0 (internal audit)' },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status} for ${url}`);
  return resp.text();
}

async function scanWithGPTZero(text, name) {
  const maxLen = 50000;
  const trimmed = text.length > maxLen ? text.substring(0, maxLen) : text;

  const resp = await fetch(BASE_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': API_KEY,
    },
    body: JSON.stringify({
      document: trimmed,
      version: MODEL_VERSION,
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`GPTZero API error for ${name}: ${resp.status} ${err}`);
  }

  return resp.json();
}

function formatResults(name, result) {
  const doc = result.documents?.[0];
  if (!doc) return { name, error: 'No document in response' };

  const flaggedSentences = (doc.sentences || [])
    .filter(s => s.generated_prob > 0.8)
    .map(s => ({
      text: s.sentence,
      aiProb: (s.generated_prob * 100).toFixed(1) + '%',
    }));

  return {
    name,
    predictedClass: doc.predicted_class,
    aiProbability: (doc.completely_generated_prob * 100).toFixed(1) + '%',
    averageGenProb: ((doc.average_generated_prob || 0) * 100).toFixed(1) + '%',
    confidence: doc.confidence_category,
    confidenceScore: ((doc.confidence_score || 0) * 100).toFixed(1) + '%',
    totalSentences: (doc.sentences || []).length,
    flaggedSentences: flaggedSentences.length,
    flagged: flaggedSentences,
  };
}

async function main() {
  if (!API_KEY) {
    console.error('GPTZERO_API environment variable not set');
    process.exit(1);
  }

  console.log('=== GPTZero AI Detection Scan ===');
  console.log(`Model: ${MODEL_VERSION}`);
  console.log(`Base URL: ${APP_BASE}`);
  console.log(`Pages to scan: ${PAGES.length + TEXT_FILES.length}`);
  console.log('');

  const results = [];

  for (const page of PAGES) {
    try {
      process.stdout.write(`Scanning ${page.name}...`);
      const html = await fetchPage(page.path);
      const text = await extractTextFromHTML(html);
      if (text.length < 50) {
        console.log(` SKIP (too short: ${text.length} chars)`);
        continue;
      }
      const apiResult = await scanWithGPTZero(text, page.name);
      const formatted = formatResults(page.name, apiResult);
      results.push(formatted);
      console.log(` ${formatted.predictedClass} (${formatted.aiProbability} AI, ${formatted.flaggedSentences} flagged)`);

      await new Promise(r => setTimeout(r, 1500));
    } catch (err) {
      console.log(` ERROR: ${err.message}`);
      results.push({ name: page.name, error: err.message });
    }
  }

  for (const file of TEXT_FILES) {
    try {
      process.stdout.write(`Scanning ${file.name}...`);
      const text = await fetchPage(file.path);
      if (text.length < 50) {
        console.log(` SKIP (too short: ${text.length} chars)`);
        continue;
      }
      const apiResult = await scanWithGPTZero(text, file.name);
      const formatted = formatResults(file.name, apiResult);
      results.push(formatted);
      console.log(` ${formatted.predictedClass} (${formatted.aiProbability} AI, ${formatted.flaggedSentences} flagged)`);

      await new Promise(r => setTimeout(r, 1500));
    } catch (err) {
      console.log(` ERROR: ${err.message}`);
      results.push({ name: file.name, error: err.message });
    }
  }

  console.log('\n=== SUMMARY ===\n');

  const tableData = results
    .filter(r => !r.error)
    .map(r => ({
      Page: r.name,
      Verdict: r.predictedClass,
      'AI Prob': r.aiProbability,
      'Avg Gen': r.averageGenProb,
      Confidence: `${r.confidence} (${r.confidenceScore})`,
      Flagged: `${r.flaggedSentences}/${r.totalSentences}`,
    }));

  console.table(tableData);

  const allFlagged = results
    .filter(r => !r.error && r.flagged?.length > 0)
    .flatMap(r => r.flagged.map(f => ({ page: r.name, ...f })));

  if (allFlagged.length > 0) {
    console.log(`\n=== FLAGGED SENTENCES (>${80}% AI probability) ===\n`);
    for (const item of allFlagged) {
      console.log(`[${item.page}] ${item.aiProb}`);
      console.log(`  "${item.text}"`);
      console.log('');
    }
  } else {
    console.log('\nNo sentences flagged above 80% AI probability.');
  }

  const output = {
    scanDate: new Date().toISOString(),
    model: MODEL_VERSION,
    results,
    flaggedSentences: allFlagged,
  };

  const outPath = 'scripts/gptzero-results.json';
  const { writeFileSync } = await import('fs');
  writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\nFull results saved to ${outPath}`);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});
