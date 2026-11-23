const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const { readFile } = require('node:fs/promises');

(async () => {
  const [origin, baseline, target, failed, archive, mixed] = process.argv.slice(2);
  const browser = await chromium.launch();
  try {
    const context = await browser.newContext({viewport: {width:1280,height:800}});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    page.setDefaultTimeout(9000);
    const auth = await page.request.post(origin + '/api/auth/login', {
      headers:{Origin:origin}, data:{email:process.env.CERTHIA_TEST_EMAIL,password:process.env.CERTHIA_TEST_PASSWORD}
    });
    assert.equal(auth.status(), 200);

    await page.goto(origin + '/compare?target=' + target);
    const before = page.getByRole('combobox', {name:'Earlier report',exact:true});
    const after = page.getByRole('combobox', {name:'Newer report',exact:true});
    await before.locator(`option[value="${baseline}"]`).waitFor({state:'attached'});
    await page.getByText('Suggested previous version',{exact:false}).waitFor();
    assert.equal(await before.inputValue(),baseline);
    assert.equal(await after.inputValue(),target);
    assert.equal((await before.boundingBox()).height,(await after.boundingBox()).height);
    assert.ok((await before.boundingBox()).height <= 44);
    assert.equal((await before.boundingBox()).y,(await after.boundingBox()).y);
    assert.equal(await before.locator('option').filter({hasText:'mixed'}).count(),0);
    await page.getByRole('checkbox',{name:'Compare across repositories'}).check();
    await before.locator('option[value="' + mixed + '"]').waitFor({state:'attached'});
    await page.getByRole('checkbox',{name:'Compare across repositories'}).uncheck();
    await before.locator('option[value="' + mixed + '"]').waitFor({state:'detached'});
    await before.selectOption(baseline);
    await page.getByRole('button',{name:'Compare reports',exact:true}).click();
    await page.getByRole('heading',{name:'Release security changelog',exact:true}).waitFor();
    const args = new URL(page.url()).searchParams;
    assert.equal(args.get('target'),target);
    assert.equal(args.get('baseline'),baseline);
    await page.reload();
    await page.getByRole('heading',{name:'Release security changelog',exact:true}).waitFor();
    const comparisonTable = page.getByRole('table').first();
    await comparisonTable.getByRole('columnheader',{name:'Linked issue'}).waitFor();
    const changed = comparisonTable.getByRole('row').filter({hasText:'demo-runtime'});
    assert.match(await changed.innerText(), /Earlier report\s+CMP-101\s+Newer report\s+CMP-102/);
    assert.equal(await changed.getByRole('link',{name:'Open Jira issue CMP-102'}).getAttribute('href'),
      'https://issues.example.test/(security)/CMP-102');
    assert.equal(await comparisonTable.getByRole('link',{name:'Open Jira issue CMP-103'}).count(), 1);
    const [changelog] = await Promise.all([
      page.waitForEvent('download'), page.getByRole('button',{name:'Download security changelog'}).click()
    ]);
    const markdown = await readFile(await changelog.path(), 'utf8');
    assert.ok(markdown.includes('Earlier report [CMP-101](https://issues.example.test/%28security%29/CMP-101), Newer report [CMP-102](https://issues.example.test/%28security%29/CMP-102)'));
    assert.equal((markdown.match(/\[CMP-103\]/g) || []).length, 1);
    await page.getByRole('button',{name:/^New high or critical/}).click();
    await page.getByRole('checkbox',{name:'Has reported fix'}).check();
    const comparisonRows = page.getByRole('table').first().getByRole('row');
    assert.equal(await comparisonRows.count(),2);
    assert.match(await comparisonRows.last().innerText(),/demo-runtime/);
    await comparisonRows.last().getByRole('button',{name:/demo-runtime/}).click();
    const addedDetail = page.getByRole('dialog',{name:/demo-runtime/});
    await addedDetail.getByText('No detection from the compared scanners.').waitFor();
    assert.equal(await addedDetail.getByRole('link',{name:'Open earlier scan'}).count(),0);
    await addedDetail.getByRole('button',{name:'Close dialog'}).click();
    await addedDetail.waitFor({state:'hidden'});

    const stillDetected = page.getByRole('button',{name:/^Still detected/});
    await stillDetected.click();
    const comparisonSearch = page.getByRole('textbox',{name:'Search comparison findings'});
    await comparisonSearch.fill('CVE-2099-0001');
    const comparisonUrl = page.url();
    const finding = comparisonTable.getByRole('button',{name:'CVE-2099-0001 · demo-package',exact:true});
    await finding.press('Enter');
    const detail = page.getByRole('dialog',{name:'CVE-2099-0001 · demo-package',exact:true});
    await detail.getByRole('region',{name:'Advisory description'}).waitFor();
    assert.equal(await detail.getByRole('link',{name:'Open newer scan'}).getAttribute('target'),'_blank');
    assert.match(await detail.getByRole('link',{name:'Open earlier scan'}).getAttribute('href'), new RegExp('/scans/' + baseline + '\\?'));
    await detail.getByRole('link',{name:'Open Jira issue CMP-102'}).waitFor();
    assert.equal(page.url(),comparisonUrl);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await detail.evaluate(dialog=>dialog.getBoundingClientRect().right<=innerWidth),true);
    await page.keyboard.press('Escape');
    await detail.waitFor({state:'hidden'});
    assert.equal(page.url(),comparisonUrl);
    assert.equal(await comparisonSearch.inputValue(),'CVE-2099-0001');
    assert.equal(await stillDetected.getAttribute('aria-pressed'),'true');
    assert.equal(await finding.evaluate(button=>document.activeElement===button),true);
    await page.setViewportSize({width:1280,height:800});

    await page.getByRole('button',{name:'Scan tags or digests'}).click();
    await page.getByText('Certhia reuses matching completed scans',{exact:false}).waitFor();
    assert.equal(await page.getByRole('group',{name:'Newer image'}).getByRole('textbox',{name:'Image reference'}).inputValue(),'example.test/two/build:v2');
    await page.goto(origin + '/scans/' + target);
    const findings = page.locator('.findings-table');
    await findings.locator('.finding-row').first().waitFor();
    assert.equal(await page.locator('#image-details').evaluate(el => Boolean(el.compareDocumentPosition(document.querySelector('#scan-findings')) & Node.DOCUMENT_POSITION_FOLLOWING)), true);
    await page.getByRole('button',{name:'Copy image digest'}).waitFor();
    const imageActions = page.locator('.image-menu > summary');
    const actionPanel = page.getByRole('group',{name:'Image actions',exact:true});
    await imageActions.focus();
    await page.keyboard.press('Enter');
    await actionPanel.getByRole('link',{name:'Analyze patches'}).waitFor();
    await page.keyboard.press('Tab');
    assert.equal(await actionPanel.getByRole('link',{name:'Download image archive'}).evaluate(el=>document.activeElement===el),true);
    await page.keyboard.press('Escape');
    await actionPanel.waitFor({state:'hidden'});
    assert.equal(await imageActions.evaluate(el=>document.activeElement===el),true);
    await imageActions.click();
    await actionPanel.getByRole('button',{name:'Publish image'}).click();
    const publish = page.getByRole('dialog',{name:'Publish image'});
    assert.equal(await publish.getByRole('textbox',{name:'Destination image'}).evaluate(el=>document.activeElement===el),true);
    await publish.getByRole('button',{name:'Cancel'}).click();
    await publish.waitFor({state:'hidden'});
    assert.equal(await imageActions.evaluate(el=>document.activeElement===el),true);
    await page.route('**/api/images/' + target + '/layers', route=>route.fulfill({json:{
      layers:[{digest:'sha256:fixture',size:1048576,mediaType:'application/vnd.oci.image.layer.v1.tar'}],compressedBytes:1048576,repeatedBytes:0
    }}));
    await page.route('**/api/images/' + target + '/layers/0/files', route=>route.fulfill({json:{
      index:0,uncompressedBytes:12,files:[{path:'app/settings.txt',type:'file',size:12}]
    }}));
    await imageActions.click();
    await actionPanel.getByRole('button',{name:'Inspect image layers'}).click();
    const layers = page.getByRole('dialog',{name:'Image layers'});
    await layers.getByRole('button',{name:'View files'}).click();
    await layers.getByText('app/settings.txt',{exact:true}).waitFor();
    await layers.getByRole('button',{name:'Close',exact:true}).click();
    await layers.waitFor({state:'hidden'});
    assert.ok((await findings.locator('.finding-row').first().boundingBox()).height < 160);
    assert.ok((await findings.locator('.finding-summary').first().innerText()).length <= 121);
    await findings.getByRole('button',{name:/^View details for /}).first().click();
    const tracking = page.getByRole('dialog');
    await tracking.getByRole('region',{name:'Scanner description'}).getByText(/End of scanner description\./).waitFor();
    await page.setViewportSize({width:390,height:844});
    assert.ok((await tracking.getByRole('combobox',{name:/^Manual tracking status/}).boundingBox()).y < 550);
    await page.setViewportSize({width:1280,height:800});
    await page.keyboard.press('Escape');
    await tracking.waitFor({state:'hidden'});
    await page.getByRole('group',{name:'Filter findings by severity'}).getByRole('button',{name:/high/i}).click();
    await page.getByRole('button',{name:'Clear filters'}).click();
    await page.getByRole('button',{name:'Downloads',exact:true}).click();
    const downloads = page.getByRole('heading',{name:'Report downloads',exact:true});
    assert.equal(await downloads.evaluate(el=>document.activeElement === el),true);
    assert.ok((await downloads.boundingBox()).y < 800);
    const [file] = await Promise.all([
      page.waitForEvent('download'), page.getByRole('link',{name:'Download SPDX JSON',exact:true}).click()
    ]);
    assert.match(file.suggestedFilename(),/^certhia-build-v2-linux-amd64-.+\.spdx\.json$/);
    await page.getByRole('group',{name:'Report views'}).getByRole('button',{name:/^Findings/}).click();
    await page.setViewportSize({width:390,height:844});
    assert.equal(await findings.evaluate(table=>table.scrollWidth <= table.parentElement.clientWidth),true);
    await findings.getByText('Fix · 1.2.4',{exact:true}).first().waitFor();
    const phoneFinding = findings.locator('.finding-row').first();
    assert.ok((await phoneFinding.locator('td').first().boundingBox()).width > 160);
    assert.ok((await phoneFinding.boundingBox()).height < 240);
    await page.setViewportSize({width:320,height:760});
    await imageActions.click();
    const menuBox = await actionPanel.boundingBox();
    assert.ok(menuBox.x >= 0 && menuBox.x + menuBox.width <= 320);
    await page.locator('.scan-heading h1').click();
    await actionPanel.waitFor({state:'hidden'});
    await page.setViewportSize({width:1280,height:800});

    await page.goto(origin + '/scans/' + mixed);
    const scopes = page.getByRole('group',{name:'Filter findings by ecosystem'});
    const java = findings.getByRole('button',{name:'View details for CVE-2099-4242'});
    const osGroup = findings.getByRole('button',{name:/^OS packages 101$/});
    await osGroup.waitFor();
    assert.equal(await java.count(),0);
    const moreFindings = page.getByRole('button',{name:'Load more findings',exact:true});
    await moreFindings.scrollIntoViewIfNeeded();
    await page.waitForFunction(() => document.querySelectorAll('.finding-row').length >= 100);
    await moreFindings.scrollIntoViewIfNeeded();
    await java.waitFor();
    assert.equal(await findings.locator('.finding-row').count(),102);
    assert.equal(await page.getByRole('button',{name:'Load more findings'}).count(),0);
    await scopes.getByRole('button',{name:'Java',exact:true}).click();
    await java.waitFor();
    assert.equal(await findings.locator('.finding-row').count(),1);
    await scopes.getByRole('button',{name:'All',exact:true}).click();
    await osGroup.click();
    assert.equal(await osGroup.getAttribute('aria-expanded'),'false');
    await java.waitFor();
    assert.equal(await page.getByRole('button',{name:'Load more findings'}).count(),0);
    await osGroup.click();
    await java.waitFor({state:'hidden'});

    await page.goto(origin + '/scans/' + failed);
    await page.getByRole('link',{name:'Edit and retry',exact:true}).click();
    const reference = page.getByRole('textbox',{name:/Image reference/});
    await reference.waitFor();
    assert.equal(await reference.inputValue(),'recovery.example.test/team/fails:v1');
    assert.equal(await page.getByRole('combobox',{name:'Platform',exact:true}).inputValue(),'linux/arm64');
    assert.equal(await page.getByRole('spinbutton',{name:'Queue priority'}).inputValue(),'-3');
    await page.getByRole('button',{name:'Start scan',exact:true}).first().click();
    const launcher = page.getByRole('dialog',{name:'Start scan'});
    await launcher.getByRole('radio',{name:'Image archive'}).check();
    await launcher.locator('input[type=file]').setInputFiles(archive);
    await page.waitForFunction(() => [...document.querySelectorAll('dialog input')].some(input=>input.value==='certhia/fixture:test'));
    await launcher.getByRole('button',{name:'Cancel',exact:true}).click();

    await page.goto(origin + '/scheduled-scans');
    await page.getByRole('button',{name:'Add schedule',exact:true}).first().click();
    const schedule = page.getByRole('dialog');
    const cron = schedule.getByRole('textbox',{name:/UTC cron expression/});
    await schedule.getByRole('combobox',{name:'Schedule preset'}).selectOption('0 * * * *');
    await schedule.getByText(/Next run in your time zone/).waitFor();
    await cron.fill('daily');
    await schedule.getByRole('alert').waitFor();
    assert.equal(await cron.getAttribute('aria-invalid'),'true');
    await schedule.getByRole('combobox',{name:'Image selection'}).selectOption('kubernetes');
    await schedule.getByRole('textbox',{name:/Namespace/}).fill('denied');
    await schedule.getByText(/You can save a disabled draft/).waitFor();
    assert.equal(await schedule.getByRole('checkbox',{name:'Enable schedule'}).isDisabled(),true);
    await schedule.getByRole('button',{name:'Cancel',exact:true}).click();

    await page.goto(origin + '/patches?scan=' + target);
    const advisory = page.getByRole('checkbox',{name:'CVE-2099-0001',exact:true});
    await advisory.waitFor();
    assert.equal(await advisory.count(),1);
    const row = page.getByRole('row').filter({has:advisory});
    assert.match(await row.innerText(),/demo-package/);
    assert.match(await row.innerText(),/demo-runtime/);

    await page.goto(origin + '/audit-logs');
    await page.getByRole('link',{name:'example.test/two/build:v2',exact:true}).waitFor();
    assert.equal(await page.getByRole('columnheader',{name:'Actor',exact:true}).count(),1);
    assert.deepEqual(errors,[]);
    console.log('PASS UX regressions: shareable comparison with in-place details and linked issues, severity filters, desktop downloads, mobile findings, editable retry, archive suggestion, schedules, patch scope and audit names');
  } finally { await browser.close(); }
})().catch(error => {console.error(error);process.exitCode=1;});
