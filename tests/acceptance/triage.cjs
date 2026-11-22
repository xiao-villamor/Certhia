const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');

async function main() {
  const [base, scanId, sharedScan, tracker] = process.argv.slice(2);
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    const login = await page.request.post(base + '/api/auth/login', {
      headers: { Origin: base },
      data: { email: process.env.CERTHIA_TEST_EMAIL, password: process.env.CERTHIA_TEST_PASSWORD }
    });
    assert.equal(login.status(), 200, 'Sign in to the disposable Certhia instance');
    await page.goto(base + '/scans/' + scanId);
    if (sharedScan === 'exceptions') {
      const finding = page.getByRole('button', { name: 'View details for CVE-2099-0001' }).first();
      const dialog = page.getByRole('dialog', { name: 'CVE-2099-0001' });
      const filter = page.getByRole('combobox', { name: 'Filter findings by status' });
      await finding.click();
      await dialog.getByText('Exception', {exact: true}).click();
      await dialog.getByRole('button', {name: 'Add exception'}).click();
      assert.equal(await dialog.getByRole('combobox', {name: /^Exception scope/}).inputValue(), 'reference');
      await dialog.getByRole('textbox', {name: 'Reason', exact: true}).fill('Browser change');
      const tomorrow = new Date(Date.now() + 86400000).toISOString().slice(0, 10);
      await dialog.locator('input[type=date]').fill(tomorrow);
      await dialog.getByRole('button', {name: 'Save tracking'}).click();
      await dialog.waitFor({state: 'hidden'});
      await filter.selectOption('excepted');
      await finding.click();
      await dialog.getByText('Browser change', {exact: true}).waitFor();
      await dialog.getByRole('button', {name: 'Remove exception'}).click();
      await dialog.getByRole('button', {name: 'Save tracking'}).click();
      await dialog.waitFor({state: 'hidden'});
      await finding.waitFor({state: 'hidden'});
      await filter.selectOption('open');
      await finding.waitFor({state: 'visible'});
      assert.deepEqual(errors, []);
      console.log('PASS browser: add an exception, filter excepted findings, and remove the exception');
      return;
    }
    if (sharedScan) {
      const label = 'View details for CVE-2099-0001';
      await page.getByRole('button', { name: label }).first().click();
      const dialog = page.getByRole('dialog', { name: 'CVE-2099-0001' });
      const summary = dialog.getByRole('region', { name: 'Vulnerability evidence' });
      await summary.getByText('Trivy', {exact:true}).waitFor();
      assert.equal(await summary.getByText('Trivy', {exact:true}).count(), 1);
      await dialog.getByText('Affected packages (2)', {exact:true}).click();
      assert.equal(await dialog.getByRole('table').getByRole('row').count(), 3);
      await dialog.getByRole('combobox',{name:/^Tracking status/}).selectOption('in_progress');
      await dialog.getByRole('combobox',{name:'Issue tracker'}).selectOption(tracker);
      await dialog.getByRole('textbox',{name:'Issue ID'}).fill('SEC-6020');
      assert.equal(await dialog.getByRole('combobox',{name:/^Ticket scope/}).inputValue(), 'advisory');
      await dialog.getByRole('button', { name: 'Save tracking' }).click();
      await dialog.waitFor({state:'hidden'});
      await page.goto(base + '/scans/' + sharedScan);
      await page.getByRole('button', { name: label }).first().click();
      await dialog.getByRole('link', { name: 'SEC-6020' }).waitFor();
      assert.equal(await dialog.getByRole('combobox',{name:/^Tracking status/}).inputValue(), 'open');
      if (process.env.CERTHIA_TRACKING_SCREENSHOT) {
        await page.goto(base + '/scans/' + scanId);
        await page.getByRole('button', { name: label }).first().click();
        await dialog.getByRole('link', { name: 'SEC-6020' }).waitFor();
        await dialog.getByText('Affected packages (2)', {exact:true}).click();
        await dialog.screenshot({path: process.env.CERTHIA_TRACKING_SCREENSHOT, animations:'disabled'});
      }
      assert.deepEqual(errors, []);
      console.log('PASS browser: two packages, one detector badge and shared issue, independent image status');
      return;
    }
    const cases = [
      { id: 'CVE-2099-0001', label: 'False positive', status: 'false_positive', note: 'False positive for the test image.' },
      { id: 'CVE-2099-0002', label: 'Accepted risk', status: 'accepted_risk', note: 'Risk accepted for the test image.' }
    ];
    const finding = id => page.getByRole('button', { name: 'View details for ' + id });
    for (const item of cases) {
      await finding(item.id).click();
      const dialog = page.getByRole('dialog', { name: item.id });
      await dialog.getByRole('combobox', { name: /^Tracking status/ }).selectOption(item.status);
      await dialog.getByRole('textbox', { name: /Note/ }).fill(item.note);
      await dialog.getByRole('button', { name: 'Save tracking' }).click();
      await dialog.waitFor({ state: 'hidden' });
    }
    await page.reload();
    for (const [index, item] of cases.entries()) {
      await page.getByRole('combobox', { name: 'Filter findings by status' }).selectOption(item.status);
      await finding(item.id).waitFor({ state: 'visible' });
      await finding(cases[1 - index].id).waitFor({ state: 'hidden' });
      await finding(item.id).click();
      const dialog = page.getByRole('dialog', { name: item.id });
      const selected = dialog.getByRole('combobox', { name: /^Tracking status/ });
      await selected.waitFor({ state: 'attached' });
      assert.equal(await selected.inputValue(), item.status);
      assert.equal(await dialog.getByRole('textbox', { name: /Note/ }).inputValue(), item.note);
      await dialog.getByRole('button', { name: 'Cancel' }).click();
    }
    assert.deepEqual(errors, []);
    console.log('PASS browser with real API: save both statuses with notes, reload and filter each one');
  } finally {
    await browser.close();
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
