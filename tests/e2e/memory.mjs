// Walks the memory features on a running server and saves screenshots: the Threads tab, pointer
// links from call arguments, the Memory tab (hex view) and the access history of a block.
//   node tests/e2e/memory.mjs <analysisId> [outDir] [baseUrl] [event]
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const [id, outDir = 'build/screenshots/memory', base = 'http://127.0.0.1:5177', event = ''] = process.argv.slice(2);
if (!id) { console.error('usage: memory.mjs <analysisId> [outDir] [baseUrl] [event]'); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({ channel: 'msedge', headless: true,
  args: ['--enable-webgl', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
const page = await browser.newPage({ viewport: { width: 1700, height: 1000 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
const shot = name => page.screenshot({ path: path.join(outDir, `${name}.png`) });
const report = {};

await page.goto(`${base}/#a=${id}${event ? `&e=${event}` : ''}`);
await page.waitForFunction(() => document.getElementById('counts').textContent.includes('live blocks'), null, { timeout: 60000 });
await page.waitForTimeout(1000);

// Threads: one card per thread, busy ones first.
await page.click('button.tab[data-tab="threads"]');
await page.waitForSelector('.thread-card', { timeout: 30000 });
report.threads = await page.locator('#tab-threads .calls-status').innerText();
report.firstThread = (await page.locator('.thread-card').first().innerText()).split('\n').slice(0, 3).join(' | ');
await shot('01-threads');

// Pointer links in the calls list: the first one selects its block or region.
await page.click('button.tab[data-tab="live-calls"]');
await page.waitForSelector('.call-row', { timeout: 30000 });
const link = page.locator('.call-args button.ptr').first();
await link.waitFor({ timeout: 30000 }).catch(() => {});
report.pointer = (await link.count()) ? await link.innerText() : null;
if (report.pointer) await link.click();
else {
  // No pointer on screen: select the newest live block instead.
  await page.evaluate(() => {
    const app = window.ttdscape, live = app.time.liveBlocksAt(app.current);
    app.select({ kind: 'block', b: live[live.length - 1] }, { reveal: true });
  });
}
report.selection = await page.evaluate(() => JSON.stringify(window.ttdscape.selection));

// The Memory tab shows the selection's bytes at the playhead.
await page.click('button.tab[data-tab="memory"]');
await page.waitForSelector('.hex-row', { timeout: 30000 });
report.memoryTarget = await page.locator('.memory-target').innerText();
report.memoryStatus = await page.locator('.memory-status').innerText();
report.firstRow = await page.locator('.hex-row').first().innerText();
report.strings = await page.locator('button.memory-string').allInnerTexts();
await shot('02-memory');

// Access history in the Inspector.
await page.click('button.tab[data-tab="inspector"]');
const load = page.locator('.access-history button', { hasText: /^Load/ });
await load.click();
await page.waitForFunction(() => document.querySelector('.access-row') || /No accesses|Could not/.test(document.querySelector('.access-history')?.textContent ?? ''), null, { timeout: 120000 });
report.accesses = await page.locator('.access-history p').first().innerText();
report.writers = (await page.locator('.access-group > span').allInnerTexts()).slice(0, 5);
report.firstAccess = (await page.locator('.access-row').count()) ? await page.locator('.access-row').first().innerText() : null;
await shot('03-accesses');

// Step to the next access with ], then select two bytes in the hex view.
const before = await page.evaluate(() => window.ttdscape.current);
await page.evaluate(() => window.ttdscape.seek(0));
await page.keyboard.press(']');
report.nextAccess = { before, after: await page.evaluate(() => window.ttdscape.current) };
await page.click('button.tab[data-tab="memory"]');
await page.waitForSelector('.hex-row .b[data-o]');
await page.locator('.hex-row .b[data-o]').nth(0).click();
await page.locator('.hex-row .b[data-o]').nth(3).click({ modifiers: ['Shift'] });
report.byteSelection = await page.locator('.memory-pane-history, .actions button', { hasText: /^Accesses to/ }).first().innerText();
await shot('04-memory-selection');

report.errors = errors;
console.log(JSON.stringify(report, null, 2));
await browser.close();
