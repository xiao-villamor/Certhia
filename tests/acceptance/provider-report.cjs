const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');

(async () => {
  const [base, id, scenario] = process.argv.slice(2);
  const osv = scenario === 'osv';
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const session = await page.request.post(base + '/api/auth/login', {
      headers: { Origin: base }, data: { email: process.env.CERTHIA_TEST_EMAIL, password: process.env.CERTHIA_TEST_PASSWORD }
    });
    assert.equal(session.status(), 200);
    await page.goto(base + '/scans/' + id);
    const summary = page.locator('.scan-meta').getByText('Scanners', { exact: true }).locator('..');
    const names = await summary.locator('strong').innerText();
    for (const engine of ['Trivy', 'Grype', osv ? 'OSV-Scanner' : 'Syft']) assert.ok(names.includes(engine));
    const cve = osv ? 'CVE-2099-0002' : 'CVE-2024-3651';
    const ghsa = osv ? 'GHSA-2345-6789-cfgh' : 'GHSA-jjg7-2v4v-x38h';
    const detectors = osv ? ['Grype', 'OSV-Scanner', 'Trivy'] : ['Grype', 'Trivy'];
    const scanViews = page.getByRole('group', {name:'Report views'});
    const comparison = page.getByRole('region', {name:'Scanner differences',exact:true});
    const findingsTab = scanViews.getByRole('button',{name:/^Findings/});
    assert.equal(await findingsTab.getAttribute('aria-pressed'), 'true');
    assert.equal(await comparison.count(), 0);
    if (osv) {
      await page.route(/\/report\/scanner-differences\?/, route => route.fulfill({status:503,json:{error:'Scanner evidence temporarily unavailable.'}}), {times:1});
    }
    await scanViews.getByRole('button', {name:'Scanner differences',exact:true}).click();
    await comparison.getByRole('heading', {name:'Scanner differences',exact:true}).waitFor();
    if (osv) {
      await comparison.getByRole('alert').waitFor();
      await comparison.getByRole('button',{name:'Try again'}).click();
    }
    await comparison.getByRole('link', {name:'Download discrepancy report'}).waitFor();
    assert.match(await comparison.innerText(), /automatically reconciled/);
    const result = await (await page.request.get(base + '/api/scans/' + id + '/report/discrepancies')).json();
    const totals = comparison.locator('.findings-counts');
    assert.match(await totals.innerText(), new RegExp(result.agreed + ' agreed'));
    assert.match(await totals.innerText(), new RegExp(result.autoResolved + ' automatically reconciled'));
    assert.match(await totals.innerText(), new RegExp(result.needsReview + ' needs? review'));
    if (osv) {
      const load = comparison.getByRole('button',{name:'Load more scanner differences',exact:true});
      assert.equal(await comparison.getByRole('article').count(),10);
      await load.scrollIntoViewIfNeeded();
      await page.waitForFunction(() => document.querySelectorAll('.scanner-differences article').length === 15);
      assert.equal(await load.count(),0);
      await comparison.getByRole('button', {name:'Needs review', exact:true}).click();
      assert.equal(await comparison.getByRole('button', {name:'Needs review', exact:true}).getAttribute('aria-pressed'), 'true');
      const scannerSearch = comparison.getByRole('textbox', {name:'Search scanner differences'});
      await scannerSearch.fill('CVE-2099-9988');
      const pending = comparison.getByRole('article').filter({hasText:'CVE-2099-9988'});
      assert.match(await pending.innerText(), /CVE-2099-9988/);
      assert.match(await pending.innerText(), /Reported fix 2.1/);
      assert.equal(await pending.getByText('No matching observation in this group').count(), 2);
      await scannerSearch.fill('CVE-2099-9999');
      const severityOnly = comparison.getByRole('article').filter({hasText:'CVE-2099-9999'});
      await severityOnly.getByText('Severity only',{exact:true}).waitFor();
      assert.match(await severityOnly.innerText(), /report the same fix 2\.1\.0/);
      assert.equal(await severityOnly.getByRole('listitem').count(), 3);
      await comparison.getByRole('button', {name:'Reconciled',exact:true}).click();
      await scannerSearch.fill('GHSA-2345-6789-cfgh');
      const evidence = comparison.getByRole('list', {name:'Scanner evidence'});
      await evidence.waitFor();
      assert.equal(await evidence.getByRole('listitem').count(), 3);
      assert.match(await evidence.innerText(), /OSV-Scanner/);
      await comparison.getByRole('textbox', {name:'Search scanner differences'}).fill('GHSA-2345-6789-cfgh');
      await evidence.waitFor();
      await page.setViewportSize({width:390,height:844});
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      await comparison.getByRole('button', {name:'Find ' + cve + ' in findings'}).click();
      assert.equal(await page.getByRole('textbox',{name:'Filter report'}).inputValue(), cve);
      await page.goBack();
      await comparison.getByRole('heading',{name:'Scanner differences',exact:true}).waitFor();
      assert.equal(await comparison.getByRole('textbox',{name:'Search scanner differences'}).inputValue(), ghsa);
      await page.reload();
      await comparison.getByRole('link',{name:'Download discrepancy report'}).waitFor();
      await page.setViewportSize({width:1280,height:800});
    }
    await findingsTab.click();
    const button = page.getByRole('button', { name: 'View details for ' + cve });
    await page.getByRole('textbox', { name: 'Filter report' }).fill(ghsa);
    await button.waitFor();
    assert.equal(await page.getByRole('button', { name: /^View details for / }).count(), 1);
    const row = page.getByRole('row').filter({ has: button });
    assert.ok((await row.innerText()).includes(ghsa));
    assert.deepEqual((await row.locator('.detector').allTextContents()).sort(), detectors);
    await button.click();
    const dialog = page.getByRole('dialog', { name: cve });
    assert.equal(await dialog.getByText(ghsa, { exact: true }).innerText(), ghsa);
    const sources = dialog.locator('.detectors .detector');
    assert.deepEqual((await sources.allTextContents()).sort(), detectors);
    assert.deepEqual(errors, []);
    console.log('PASS browser: aliases searchable, one row, actual detectors in table and finding details');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
