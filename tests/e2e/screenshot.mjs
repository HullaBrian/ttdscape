// Opens the viewer on a running server, loads an analysis and saves screenshots at several events.
//   node tests/e2e/screenshot.mjs <analysisId> [outDir] [baseUrl]
// Uses the system Edge (no browser download) with SwiftShader WebGL, as Heapscape's tests do.
import { chromium } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const [id, outDir = 'build/screenshots', base = 'http://127.0.0.1:5177'] = process.argv.slice(2);
if (!id) { console.error('usage: screenshot.mjs <analysisId> [outDir] [baseUrl]'); process.exit(2); }
fs.mkdirSync(outDir, { recursive: true });

const browser = await chromium.launch({ channel: 'msedge', headless: true,
  args: ['--enable-webgl', '--use-angle=swiftshader', '--enable-unsafe-swiftshader'] });
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 } });
const errors = [];
page.on('pageerror', e => errors.push(e.message));
page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });

await page.goto(`${base}/#a=${id}`);
await page.waitForFunction(() => document.getElementById('counts').textContent.includes('live blocks'), null, { timeout: 60000 });
await page.waitForTimeout(1500);
await page.screenshot({ path: path.join(outDir, 'end.png') });

// Scrub to a few points by clicking the timeline.
const box = await page.locator('#timeline canvas').boundingBox();
for (const f of [0.1, 0.5]) {
  await page.mouse.click(box.x + box.width * f, box.y + box.height / 2);
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(outDir, `t${Math.round(f * 100)}.png`) });
}
// Select the first leak group, if any (Leaks tab).
await page.click('button.tab[data-tab="leaks"]');
const leak = page.locator('#leak-list button').first();
if (await leak.count()) {
  await leak.click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: path.join(outDir, 'leak.png') });
}
// Call beams: play for a moment at slow speed, pause, and capture (skipped if calls were not recorded).
const beams = await page.evaluate(() => !document.getElementById('beam-legend').textContent.includes('Not recorded'));
if (beams) {
  await page.keyboard.press('KeyX');
  await page.click('button.tab[data-tab="view"]');
  await page.selectOption('#pace', 'events');
  await page.selectOption('#speed', '0.25');
  await page.mouse.click(box.x + box.width * 0.3, box.y + box.height / 2);
  await page.click('#play');
  await page.waitForTimeout(1500);
  await page.screenshot({ path: path.join(outDir, 'beams-playing.png') });
  await page.click('#play');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outDir, 'beams.png') });
  await page.selectOption('#calls', 'all');
  await page.waitForTimeout(500);
  await page.screenshot({ path: path.join(outDir, 'beams-all.png') });
}
console.log(JSON.stringify({ footer: await page.locator('footer').innerText(), errors }, null, 1));
await browser.close();
