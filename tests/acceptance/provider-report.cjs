const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');

(async () => {
  const [base, id, scenario] = process.argv.slice(2);
  const osv = scenario === 'osv';
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
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
    const comparison = page.locator('details').filter({has: page.locator('summary').getByText('Scanner differences')});
    await comparison.locator('summary').click();
    await comparison.getByRole('link', {name:'Download discrepancy report'}).waitFor();
    assert.match(await comparison.innerText(), /automatically reconciled/);
    const result = await (await page.request.get(base + '/api/scans/' + id + '/report/discrepancies')).json();
    assert.ok((await comparison.innerText()).includes(result.agreed + ' agree · ' + result.autoResolved + ' automatically reconciled · ' + result.needsReview + ' need review'));
    if (osv) {
      const evidence = comparison.getByRole('list', {name:'Scanner evidence'});
      assert.equal(await evidence.getByRole('listitem').count(), 3);
      assert.match(await evidence.innerText(), /OSV-Scanner/);
    }
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
    console.log('PASS browser: aliases searchable, one row, actual detectors in table and finding details');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
