// Screen check for the Sign-In Attempts page: sorting and blocking by hand,
// with mocked server replies. Run from the app folder:
//   node tests/sign-in-attempts.screen.js      (needs Playwright)
// Exits non-zero if any check fails.
const assert = require('assert');
const path = require('path');
const { chromium } = require('playwright');

const PAGE = 'file://' + path.join(__dirname, '..', 'renderer', 'index.html');

function mock({ total, refuseSignedIn = false }) {
  return [({ total, refuseSignedIn }) => {
    window.calls = [];
    const rows = [
      { rank: 0, ip: '45.33.1.5', country: 'France', network: 'Zeta', tries: 5, ssh: 5, mail: 0, probes: 0, visits: 2, days: 2, users: ['root'], last: 300 },
      { rank: 1, ip: '9.9.9.9', country: 'Brazil', network: 'Alpha', tries: 50, ssh: 50, mail: 0, probes: 0, visits: 61, days: 7, users: [], last: 100 },
      { rank: 2, ip: '2.2.2.2', country: 'Chile', network: 'Mid', tries: 9, ssh: 9, mail: 0, probes: 0, visits: 1, days: 1, users: ['bob'], last: 200 },
    ];
    const api = {
      label: async () => 'test',
      helper: async (a, args) => {
        window.calls.push([a, ...args]);
        if (a === 'attacks') {
          let out = rows;
          if (args[1] === 'visits') out = [rows[1], rows[0], rows[2]];
          if (args[1] === 'network') out = [rows[0], rows[2], rows[1]];
          return { days: 7, total: { addresses: total, ssh: 64, mail: 0, probes: 0, bans: 0, left_out: 0, returning: 2, key_ok: 0 },
            rows: out, sort: args[1] ? { key: args[1], dir: args[2] } : null, countries: [], server: {}, geo: {} };
        }
        if (a === 'block-list') return { blocked: [], active: true, boot: true };
        if (a === 'ip-info') {
          if (args[0] === Array.from(new TextEncoder().encode('10.0.0.1'), (b) => b.toString(16).padStart(2, '0')).join('')) throw new Error('HELPER: that is not a public address');
          return { geo: { country: 'Brazil', network: 'Alpha' }, who: { registry: { org: 'Alpha Hosting' } } };
        }
        if (a === 'block-add') {
          if (refuseSignedIn && args.length === 2) throw new Error('HELPER: that address signed in successfully here (a mailbox or upload account) on 2026-10-30; confirm to block it anyway');
          return { blocked: args.length && args[0].length > 20 ? '9.9.9.0/24' : '9.9.9.9/32', replaced: [] };
        }
        return {};
      },
    };
    window.argus = new Proxy(api, { get: (t, k) => t[k] || (async () => null) });   // anything else: a harmless no-op
  }, { total, refuseSignedIn }];
}

async function open(browser, opts) {
  const p = await browser.newPage();
  const errs = [];
  p.on('pageerror', (e) => errs.push(String(e)));
  await p.addInitScript(...mock(opts));
  await p.goto(PAGE);
  await p.evaluate(() => {
    document.querySelectorAll('[hidden]').forEach((e) => { if (e.closest('#view-signins') || e.id === 'view-signins' || e.querySelector('#view-signins')) e.hidden = false; });
    return loadSignins();
  });
  await p.waitForTimeout(150);
  return { p, errs };
}
const order = (p) => p.$$eval('#si-rows tr', (trs) => trs.map((t) => t.cells[0].textContent));
const calls = (p) => p.evaluate(() => window.calls.map((c) => c.join(',')));
const sortBy = async (p, k) => { await p.click(`#si-table th[data-sort="${k}"] .th-sort`); await p.waitForTimeout(150); };

let failed = 0;
async function check(name, fn) {
  try { await fn(); console.log('ok  ', name); }
  catch (e) { failed++; console.log('FAIL', name, '\n   ', e.message.split('\n')[0]); }
}

(async () => {
  const browser = await chromium.launch();

  await check('more addresses than shown: a sort asks the server', async () => {
    const { p, errs } = await open(browser, { total: 900 });
    await sortBy(p, 'visits');
    assert.ok((await calls(p)).includes('attacks,7,visits,desc'));
    assert.strictEqual((await order(p))[0], '9.9.9.9');
    assert.match(await p.textContent('#si-count'), /^First 3 of 900 by Visits \(descending\)/);
    assert.strictEqual(await p.getAttribute('#si-table th[data-sort="visits"]', 'aria-sort'), 'descending');
    assert.deepStrictEqual(errs, []);
  });

  await check('every address fits: sorting is local, Default Order restores the server order', async () => {
    const { p, errs } = await open(browser, { total: 3 });
    await sortBy(p, 'ip');
    assert.deepStrictEqual(await order(p), ['2.2.2.2', '9.9.9.9', '45.33.1.5']);
    assert.ok(!(await calls(p)).some((c) => c.startsWith('attacks,7,')), 'no server sort');
    await p.click('#si-sort-reset'); await p.waitForTimeout(100);
    assert.deepStrictEqual(await order(p), ['45.33.1.5', '9.9.9.9', '2.2.2.2']);
    assert.strictEqual(await p.isVisible('#si-sort-reset'), false);
    assert.strictEqual(await p.evaluate(() => document.activeElement?.className), 'th-sort');
    assert.deepStrictEqual(errs, []);
  });

  await check('Default Order after a server-sorted period that fits', async () => {
    const { p } = await open(browser, { total: 3 });
    await p.evaluate(() => { siSort = { key: 'network', dir: -1 }; return loadSignins(); });   // e.g. the period changed while sorted
    await p.waitForTimeout(150);
    await p.click('#si-sort-reset'); await p.waitForTimeout(100);
    assert.deepStrictEqual(await order(p), ['45.33.1.5', '9.9.9.9', '2.2.2.2']);
  });

  await check('block by hand: one address', async () => {
    const { p, errs } = await open(browser, { total: 3 });
    await p.click('#bl-add'); await p.fill('#ask-input', '9.9.9.9'); await p.click('#ask-ok'); await p.waitForTimeout(150);
    assert.match(await p.textContent('dialog[open]'), /Block 9\.9\.9\.9\/32\?[\s\S]*Alpha Hosting/);
    await p.click('dialog[open] #confirm-ok'); await p.waitForTimeout(150);
    const c = await calls(p);
    assert.ok(c.some((x) => x.startsWith('block-add,') && x.split(',').length === 3), 'block-add with address and note');
    assert.deepStrictEqual(errs, []);
  });

  await check('block by hand: a network needs BLOCK typed, and the network address is shown', async () => {
    const { p } = await open(browser, { total: 3 });
    await p.click('#bl-add'); await p.fill('#ask-input', '9.9.9.7/24'); await p.click('#ask-ok'); await p.waitForTimeout(150);
    assert.match(await p.textContent('dialog[open]'), /Block 9\.9\.9\.0\/24\?/);
    assert.strictEqual(await p.isDisabled('dialog[open] #confirm-ok'), true, 'OK waits for BLOCK');
  });

  await check('block by hand: an IPv6 /32 is a network, not one address', async () => {
    const { p } = await open(browser, { total: 3 });
    await p.click('#bl-add'); await p.fill('#ask-input', '2a03:4000::/32'); await p.click('#ask-ok'); await p.waitForTimeout(150);
    assert.match(await p.textContent('dialog[open]'), /Block 2a03:4000::\/32\?[\s\S]*Every address in/);
    assert.strictEqual(await p.isDisabled('dialog[open] #confirm-ok'), true, 'OK waits for BLOCK');
    await p.fill('dialog[open] input', 'BLOCK'); await p.click('dialog[open] #confirm-ok'); await p.waitForTimeout(150);
    const sent = await p.evaluate(() => window.calls.find((c) => c[0] === 'block-add')?.[1]);
    assert.strictEqual(Buffer.from(sent, 'hex').toString(), '2a03:4000::/32');
  });

  await check('block by hand: a private address stops before any confirm', async () => {
    const { p } = await open(browser, { total: 3 });
    await p.click('#bl-add'); await p.fill('#ask-input', '10.0.0.1'); await p.click('#ask-ok'); await p.waitForTimeout(150);
    assert.strictEqual(await p.$('dialog[open]'), null);
    assert.ok(!(await calls(p)).some((x) => x.startsWith('block-add')));
  });

  await check('block by hand: an address where a mailbox signed in asks again, then confirms', async () => {
    const { p } = await open(browser, { total: 3, refuseSignedIn: true });
    await p.click('#bl-add'); await p.fill('#ask-input', '9.9.9.9'); await p.click('#ask-ok'); await p.waitForTimeout(150);
    await p.click('dialog[open] #confirm-ok'); await p.waitForTimeout(150);
    assert.match(await p.textContent('dialog[open]'), /Block 9\.9\.9\.9\/32 Anyway\?/);
    await p.fill('dialog[open] input', 'BLOCK'); await p.click('dialog[open] #confirm-ok'); await p.waitForTimeout(150);
    assert.ok((await calls(p)).some((x) => x.startsWith('block-add,') && x.endsWith(',confirm-signed-in')));
  });

  await browser.close();
  console.log(failed ? `${failed} failed` : 'all passed');
  process.exitCode = failed ? 1 : 0;
})();
