// Walks the activity features on a running server and saves screenshots: "Color blocks by →
// Activity", write-then-execute findings (Notes, region Inspector), a block's writers, and content
// search. Needs an analysis made with "Record memory activity" (and "Snapshot block contents" for
// the search).
//   node tests/e2e/activity.mjs <analysisId> [outDir] [baseUrl] [query]
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const [id, outDir = 'build/screenshots/activity', base = 'http://127.0.0.1:5177', query = '192.168.81.129'] = process.argv.slice(2);
if (!id) { console.error('usage: activity.mjs <analysisId> [outDir] [baseUrl] [query]'); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({ channel: 'msedge', headless: true,
  args: ['--enable-webgl', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
const page = await browser.newPage({ viewport: { width: 1700, height: 1000 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
const shot = name => page.screenshot({ path: path.join(outDir, `${name}.png`) });
const report = {};

await page.goto(`${base}/#a=${id}`);
await page.waitForFunction(() => document.getElementById('counts').textContent.includes('live blocks'), null, { timeout: 60000 });
await page.waitForFunction(() => window.ttdscape.services.activity.model, null, { timeout: 30000 });

// Notes summarize the write-then-execute findings.
await page.click('button.tab[data-tab="notes"]');
report.notes = (await page.locator('#notes').innerText()).split('\n').filter(l => /activity|Write-then|page/i.test(l));

// Colour by activity at the busiest write bucket.
await page.click('button.tab[data-tab="view"]');
await page.selectOption('#color', 'activity');
const busiest = await page.evaluate(() => {
  const m = window.ttdscape.services.activity.model;
  let best = 0;
  for (let b = 0; b < m.total.length; b++) if (m.total[b] > m.total[best]) best = b;
  const evt = Math.min(window.ttdscape.data.events.count - 1, Math.round((best + 0.5) * m.eventsPerBucket));
  window.ttdscape.seek(evt);
  return evt;
});
report.busiestEvent = busiest;
await page.waitForTimeout(800);
await shot('01-activity-colors');

// The region with the most findings, in the Inspector.
const findings = await page.evaluate(() => {
  const app = window.ttdscape, f = app.services.activity.findings;
  if (!f.length) return null;
  const count = new Map();
  for (const x of f) if (x.region !== null) count.set(x.region, (count.get(x.region) ?? 0) + 1);
  const r = [...count].sort((a, b) => b[1] - a[1])[0]?.[0];
  if (r === undefined) return null;
  app.seek(f.find(x => x.region === r).exec.evt);
  app.select({ kind: 'region', r }, { focus: true, reveal: true });
  return { region: app.regionLabel(r), pages: count.get(r) };
});
report.findings = findings;
if (findings) {
  await page.waitForSelector('.wx-row');
  report.firstFinding = await page.locator('.wx-row').first().innerText();
  await page.evaluate(() => document.querySelector('.activity-section')?.scrollIntoView());
  await shot('02-write-then-execute');
}

// Content search, then the block's writers.
await page.click('button.tab[data-tab="find"]');
report.searchStatusBefore = await page.locator('#tab-find .group p.muted').last().innerText();
if (await page.locator('#content-search').isDisabled()) {
  // No snapshots in this analysis: the search part is skipped.
  report.errors = errors;
  console.log(JSON.stringify(report, null, 2));
  await browser.close();
  process.exit(0);
}
await page.fill('#content-search', query);
await page.press('#content-search', 'Enter');
await page.waitForFunction(() => !/Searching/.test(document.querySelector('#tab-find .group p.muted:last-of-type')?.textContent ?? 'Searching'), null, { timeout: 30000 });
report.search = await page.locator('#tab-find .group p[role=status]').innerText();
const match = page.locator('button.content-match').first();
if (await match.count()) {
  report.firstMatch = await match.innerText();
  await match.click();
  await page.waitForSelector('.activity-section');
  report.blockWriters = await page.locator('.activity-section').first().innerText();
  await page.click('button.tab[data-tab="memory"]');
  await page.waitForSelector('.hex-row');
  await page.waitForTimeout(500);
  report.memoryStrings = await page.locator('button.memory-string').allInnerTexts();
  await shot('03-content-search');
}

report.errors = errors;
console.log(JSON.stringify(report, null, 2));
await browser.close();
