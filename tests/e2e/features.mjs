// Walks the viewer's features on a running server and saves screenshots: region browser and
// highlights, pacing playback by calls, the live calls pane and a call's arguments.
//   node tests/e2e/features.mjs <analysisId> [outDir] [baseUrl]
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const [id, outDir = 'build/screenshots/features', base = 'http://127.0.0.1:5177'] = process.argv.slice(2);
if (!id) { console.error('usage: features.mjs <analysisId> [outDir] [baseUrl]'); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({ channel: 'msedge', headless: true,
  args: ['--enable-webgl', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
const page = await browser.newPage({ viewport: { width: 1700, height: 1000 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
const shot = name => page.screenshot({ path: path.join(outDir, `${name}.png`) });
const report = {};

await page.goto(`${base}/#a=${id}&e=1500`);
await page.waitForFunction(() => document.getElementById('counts').textContent.includes('live blocks'), null, { timeout: 60000 });
await page.waitForTimeout(1500);
report.clock = await page.locator('#clock').innerText();
await shot('01-loaded');

// Region browser: find the image regions of the network stack and highlight them.
await page.click('button.tab[data-tab="regions"]');
await page.fill('#region-search', 'dll');
await page.waitForTimeout(300);
report.regionStatus = await page.locator('#tab-regions p.muted').innerText();
await page.locator('.region-row input').nth(0).check();
await page.locator('.region-row input').nth(1).check();
await page.check('#region-dim');
await page.waitForTimeout(700);
report.highlighted = await page.evaluate(() => [...window.ttdscape.regionHighlight].map(r => window.ttdscape.regionName(r)));
await shot('02-regions-highlighted');
await page.click('text=Clear highlights');

// Pace by calls, slowly, and watch the live calls pane.
await page.click('button.tab[data-tab="view"]');
await page.selectOption('#pace', 'calls');
await page.selectOption('#speed', '3');
await page.selectOption('#beam-length', '3');
await page.click('#play');
await page.waitForTimeout(3000);
await shot('03-playing-by-calls');
await page.click('#play');
await page.waitForTimeout(800);
report.clockPaused = await page.locator('#clock').innerText();
report.callsStatus = await page.locator('#tab-live-calls .calls-status').innerText();
report.firstRows = await page.locator('#tab-live-calls .call-row').evaluateAll(rows => rows.slice(0, 5).map(r => r.innerText.replace(/\s+/g, ' ').slice(0, 220)));
await shot('04-paused-live-calls');

// A call's arguments in the Inspector.
await page.fill('#call-search', 'InternetConnect');
await page.click('#play');
await page.waitForTimeout(100);
await page.click('#play');
await page.evaluate(() => window.ttdscape.seek(window.ttdscape.data.events.count - 1));
await page.waitForTimeout(800);
const row = page.locator('#tab-live-calls .call-row').first();
if (await row.count()) {
  await row.click();
  await page.waitForTimeout(1200);
  report.inspector = (await page.locator('#details').innerText()).slice(0, 900);
  await shot('05-call-arguments');
}
report.firstRowWhen = await page.locator('#tab-live-calls .call-row .call-when').first().innerText().catch(() => null);

// CAPA tab: the timeline around the playhead, then grouped by capability.
await page.evaluate(() => window.ttdscape.seek(3000));
await page.click('button.tab[data-tab="capa"]');
await page.waitForTimeout(1500);
report.capaStatus = await page.locator('#tab-capa .calls-status').innerText();
report.capaRows = await page.locator('.capa-row').evaluateAll(rows => rows.slice(-4).map(r => r.innerText.replace(/\s+/g, ' ').slice(0, 200)));
await shot('06-capa-timeline');
await page.selectOption('#capa-view', 'rules');
await page.waitForTimeout(500);
await page.locator('.capa-group summary').first().click();
await page.waitForTimeout(300);
report.capaGroups = await page.locator('.capa-group').count();
await shot('07-capa-by-capability');
await page.selectOption('#capa-view', 'timeline');
report.errors = errors;
console.log(JSON.stringify(report, null, 1));
await browser.close();
