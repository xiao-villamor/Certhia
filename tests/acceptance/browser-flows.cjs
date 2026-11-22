const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');

const root = path.resolve(process.env.CERTHIA_PROJECT || process.cwd(), 'web/build');
const origin = 'http://certhia.test';
const reference = 'example.test/team/api:1.0';
const registry = {id:'reg-1', name:'Team registry', host:'example.test', provider:'gitea', authenticated:true};
const user = {id:'operator', email:'operator@example.test', role:'operator'};
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

(async () => {
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({acceptDownloads:true});
    const violations = [];
    const submissions = [];
    const scopes = [];
    let catalogMode = 'restricted';
    let artifactReply = 'error';
    let releaseSlow;
    page.setDefaultTimeout(5500);
    page.on('pageerror', error => violations.push(error.message));
    await page.route(origin + '/**', async route => {
      const req = route.request();
      const url = new URL(req.url());
      const key = url.pathname;
      const json = (value, status = 200) => route.fulfill({status, json:value});
      if (!key.startsWith('/api/')) {
        if (key.startsWith('/_app/') || key === '/certhia.png') {
          return route.fulfill({path:path.join(root,key)});
        }
        return route.fulfill({path:path.join(root,'200.html'), contentType:'text/html'});
      }
      if (key === '/api/auth/me') return json({user,local:true,oidcEmailLinking:false});
      if (key === '/api/registries') return json([registry]);
      if (key === '/api/scanners/available') return json({local:['trivy','syft'],registry:['trivy','syft'],defaults:['trivy']});
      if (key === '/api/discover/kubernetes/namespaces') return json({error:'Namespace enumeration is restricted.'},403);
      if (key === '/api/discover/kubernetes') {
        const namespace = url.searchParams.get('namespace');
        scopes.push(namespace);
        if (namespace === 'slow') await new Promise(resolve => { releaseSlow = resolve; });
        if (namespace === 'denied') return json({error:'Kubernetes rejected discovery.'},403);
        return json(namespace === 'empty' ? [] : [{reference,label:(namespace || 'default') + '/api-0'}]);
      }
      if (key === '/api/discover/swarm') return json([{reference,label:'api-service'}]);
      if (key === '/api/discover/docker') return json([{reference:'sha256:' + '1'.repeat(64),label:'team/api:1'}]);
      if (key === '/api/discover/dockerhub') return json([{reference:'docker.io/library/alpine',label:'alpine'}]);
      if (key.startsWith('/api/registries/reg-1/catalog')) return json(catalogMode === 'restricted'
        ? {images:[],refreshedAt:null,error:'Catalog listing is restricted.',nextCursor:null}
        : {images:['team/api'], refreshedAt:new Date().toISOString(), error:null,nextCursor:null});
      if (key === '/api/registries/reg-1/tags') return json({error:'Could not list tags.'},403);
      if (key === '/api/scans' && req.method() === 'POST') {
        submissions.push(req.postDataJSON());
        return json({id:'inventory'},202);
      }
      const parts = key.split('/');
      const scanId = parts[3];
      if (parts[2] === 'scans' && parts.length === 4) {
        const inventoryAvailable = scanId === 'inventory';
        const counts = {critical:0,high:0,medium:0,low:0,unknown:0,packages:Number(inventoryAvailable)};
        return json({id:scanId,reference,platform:'linux/amd64',source:'kubernetes',
          status:'completed',createdAt:'2026-10-01T10:00:00Z',finishedAt:'2026-10-01T10:00:10Z',counts,
          report:{counts,packages:inventoryAvailable ? [{name:'demo',version:'1',ecosystem:'deb'}] : [],
            inventoryAvailable,findings:[],checks:[],digest:null,os:'Debian',sizeBytes:512}});
      }
      if (parts[4] === 'classifications') return json([]);
      if (parts[4] === 'progress') return json({id:scanId,status:'completed',activity:[]});
      if (parts[4] === 'watch') return route.fulfill({body:'null',contentType:'application/json'});
      if (parts[4] === 'scanner-results' && parts.length === 5) {
        if (scanId === 'unavailable' && artifactReply === 'error') return json({error:'Unavailable'},503);
        if (scanId === 'artifact') await delay(400);
        return json({scanners:scanId === 'artifact' ? ['sbom'] : []});
      }
      if (parts[5] === 'sbom') return route.fulfill({contentType:'application/vnd.cyclonedx+json',
        headers:{'Content-Disposition':'attachment; filename="inventory.cdx.json"'},
        body:JSON.stringify({bomFormat:'CycloneDX',components:[{name:'demo'}]})});
      throw Error('Unexpected request: ' + key);
    });

    await page.goto(origin + '/scans/new?mode=kubernetes');
    const main = page.getByRole('main');
    const ns = main.getByRole('combobox',{name:'Namespace',exact:true});
    const ref = main.getByRole('textbox',{name:/Image reference/});
    const findPods = main.getByRole('button',{name:'Find pod images'});
    await main.getByText('Namespace suggestions are unavailable.',{exact:false}).waitFor();
    await ns.fill('prod');
    await findPods.click();
    const options = main.getByRole('combobox',{name:/Pod images/});
    await options.selectOption({label:'prod/api-0 · ' + reference});
    assert.equal(await ref.inputValue(),reference);
    await main.getByRole('combobox',{name:'Registry connection'}).selectOption(registry.id);
    assert.equal(await options.inputValue(),reference);
    await ns.fill('empty');
    assert.equal(await ref.inputValue(),'');
    await findPods.click();
    await main.getByRole('status').filter({hasText:'No pod images found in empty'}).waitFor();
    await ns.fill('denied');
    await findPods.click();
    await main.getByRole('alert').filter({hasText:'Kubernetes rejected discovery.'}).waitFor();
    await ns.fill('slow');
    const slow = page.waitForRequest(/namespace=slow/);
    await findPods.click(); await slow;
    await ns.fill('prod');
    await findPods.click();
    await options.selectOption(reference);
    releaseSlow();
    await main.getByRole('button',{name:'Start scan',exact:true}).click();
    await page.waitForURL('**/scans/inventory');
    assert.deepEqual(submissions.at(-1),{reference,platform:'linux/amd64',registryId:'reg-1',source:'kubernetes',priority:0,scanners:[]});
    assert.ok(scopes.includes('denied'));
    const download = page.getByRole('link',{name:'Download CycloneDX SBOM'});
    assert.equal(await download.getAttribute('href'),'/api/scans/inventory/report/sbom');
    const file = page.waitForEvent('download');
    await download.click();
    const saved = await file;
    assert.equal(JSON.parse(await fs.readFile(await saved.path(),'utf8')).bomFormat,'CycloneDX');
    console.log('PASS Kubernetes selection, restricted namespaces, empty results, denied/late responses, registry credentials, scan submission and report download');

    await page.goto(origin + '/scans/artifact');
    await page.getByText('Checking for a scanner SBOM…').waitFor();
    assert.equal(await download.getAttribute('href'),'/api/scans/artifact/scanner-results/sbom');
    await page.goto(origin + '/scans/unavailable');
    await page.getByRole('link',{name:'Reload report'}).waitFor();
    assert.equal(await page.getByRole('button',{name:'Download CycloneDX SBOM'}).isDisabled(),true);
    artifactReply='ready';
    await page.getByRole('link',{name:'Reload report'}).click();
    await page.getByText('This scan has no package inventory.',{exact:false}).waitFor();
    console.log('PASS original artifact fallback, loading, missing inventory and recoverable artifact error');

    await page.goto(origin + '/scans/new?registry=reg-1');
    await main.getByText('Catalog listing is restricted.').waitFor();
    await main.getByRole('button',{name:'Enter image tag or digest'}).click();
    assert.ok(await ref.evaluate(el => document.activeElement === el));
    await ref.fill(reference);
    await main.getByRole('button',{name:'Start scan',exact:true}).click();
    await page.waitForURL('**/scans/inventory');
    assert.equal(submissions.at(-1).registryId,'reg-1');
    assert.equal(submissions.at(-1).reference,reference);
    catalogMode='tags-denied';
    await page.goto(origin + '/scans/new?registry=reg-1');
    await main.getByRole('combobox',{name:'Repository',exact:true}).selectOption('team/api');
    await main.getByText('Could not list tags.').waitFor();
    await main.getByRole('button',{name:'Enter image tag or digest'}).click();
    assert.ok(await ref.evaluate(el => document.activeElement === el));
    console.log('PASS restricted registry catalog and tags, keyboard focus, manual scan using saved credentials');

    await page.goto(origin + '/scans/new?mode=swarm');
    await main.getByRole('button',{name:'Find service images'}).click();
    await main.getByRole('combobox',{name:/Service images/}).selectOption({label:'api-service · ' + reference});
    assert.equal(await ref.inputValue(),reference);
    await main.getByRole('button',{name:'Start scan',exact:true}).click();
    await page.waitForURL('**/scans/inventory');
    assert.equal(submissions.at(-1).source,'swarm');
    await page.goto(origin + '/scans/new?mode=docker');
    await main.getByRole('button',{name:'Find local images'}).click();
    await main.getByRole('checkbox',{name:'Scan all discovered Docker images'}).check();
    assert.equal(await ref.getAttribute('required'),null);
    await page.goto(origin + '/scans/new');
    await main.locator('summary').filter({hasText:'Search Docker Hub'}).click();
    await main.getByRole('textbox',{name:'Docker Hub search'}).fill('alpine');
    await main.getByRole('button',{name:'Search Docker Hub'}).click();
    await main.getByRole('combobox',{name:/Discovered images/}).selectOption('docker.io/library/alpine');
    assert.equal(await ref.inputValue(),'docker.io/library/alpine');
    console.log('PASS Swarm submission, local Docker bulk selection, Docker Hub image search');

    await page.setViewportSize({width:390,height:844});
    await page.locator('button.mobile-scan-entry').click();
    const dialog = page.getByRole('dialog',{name:'Start scan'});
    await dialog.getByText('Kubernetes',{exact:true}).click();
    await dialog.getByRole('button',{name:'Find pod images'}).click();
    await dialog.getByRole('combobox',{name:/Pod images/}).selectOption(reference);
    await dialog.getByText('Docker Swarm',{exact:true}).click();
    assert.equal(await dialog.getByRole('textbox',{name:/Image reference/}).inputValue(),'');
    await dialog.getByRole('button',{name:'Cancel',exact:true}).click();
    assert.equal(await dialog.count(),0);
    assert.deepEqual(violations,[]);
    console.log('PASS mobile launch dialog, all namespaces, change of source, no browser exceptions');
  } finally { await browser.close(); }
})().catch(error => { console.error(error);process.exitCode=1; });
