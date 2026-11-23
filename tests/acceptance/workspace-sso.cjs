const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const { chromium } = require(process.env.CERTHIA_PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const origin = process.argv[2];
  const headers = { Origin: origin };
  const settingsUrl = origin + '/api/settings/sso';
  const secret = randomBytes(24).toString('hex');
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({viewport:{width:1280,height:800}});
    assert.equal((await page.request.post(origin + '/api/auth/login', {headers,data:{
      email:process.env.CERTHIA_TEST_EMAIL,password:process.env.CERTHIA_TEST_PASSWORD
    }})).status(), 200);
    await page.goto(origin + '/settings?section=sso');
    const callback = origin + '/api/auth/oidc/workspace-sso/callback';
    assert.equal(await page.getByLabel(/^Redirect URI/).inputValue(), callback);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.setViewportSize({width:1280,height:800});
    await page.getByLabel('Sign-in button name').fill('Company account');
    await page.getByLabel(/^OIDC issuer URL/).fill('https://identity.example.test/work');
    await page.getByLabel('Client ID', {exact:true}).fill('certhia');
    await page.getByLabel(/^Client secret/).fill(secret);
    await page.getByLabel(/^Allowed email domains/).fill('Example.test, example.test');
    await page.getByRole('button', {name:'Save single sign-on'}).click();
    await page.getByText('Single sign-on settings saved.').waitFor();
    assert.equal(await page.getByLabel(/^Client secret/).inputValue(), '');
    assert.equal(await page.getByLabel(/^Allowed email domains/).inputValue(), 'example.test');
    const stored = await (await page.request.get(settingsUrl)).json();
    assert.ok(!JSON.stringify(stored).includes(secret));
    assert.equal(stored.settings.enabled, true);
    assert.deepEqual((await (await page.request.get(origin + '/api/auth/status')).json()).providers,
      [{id:'workspace-sso', name:'Company account'}]);

    const signedOut = await browser.newPage();
    await signedOut.goto(origin + '/login');
    await signedOut.getByRole('button', {name:'Sign in with Company account'}).waitFor();
    await signedOut.getByLabel('Password', {exact:true}).waitFor();
    assert.equal((await signedOut.request.get(settingsUrl)).status(), 401);
    const invalidCallback = await signedOut.request.get(callback, {maxRedirects:0});
    assert.equal(invalidCallback.status(), 303);
    assert.equal(invalidCallback.headers().location, '/login?error=oidc');
    const viewer = { email:'sso-viewer', password:randomBytes(24).toString('hex') };
    assert.equal((await page.request.post(origin + '/api/users', {headers, data:{
      ...viewer, displayName:'SSO test viewer', role:'viewer'
    }})).status(),201);
    assert.equal((await signedOut.request.post(origin + '/api/auth/login', {headers,data:viewer})).status(),200);
    assert.equal((await signedOut.request.get(settingsUrl)).status(),403);
    assert.equal((await signedOut.request.put(settingsUrl, {headers,data:{settings:stored.settings}})).status(),403);

    await page.goto(origin + '/settings?section=users');
    await page.getByRole('button', {name:'Add user',exact:true}).click();
    const fields = [/^Username/, /^Display name/, /^Role/, /^Initial password/];
    const boxes = await Promise.all(fields.map(label => page.getByLabel(label).boundingBox()));
    assert.equal(boxes[0].y, boxes[1].y);
    assert.equal(boxes[2].y, boxes[3].y);
    assert.equal(new Set(boxes.map(box => box.height)).size, 1);
    await page.setViewportSize({width:390,height:844});
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
    await page.getByLabel(/^Username/).fill('sso-invite@example.test');
    await page.getByLabel(/^Display name/).fill('SSO invite');
    await page.getByRole('button', {name:'Create account'}).click();
    await page.getByText('Account created.').waitFor();

    const invalid = await page.request.put(settingsUrl, {headers, data:{
      settings:{...stored.settings, issuer:'http://identity.example.test'}, clientSecret:secret
    }});
    assert.equal(invalid.status(), 400);
    assert.equal((await page.request.put(settingsUrl, {headers,data:{
      settings:{...stored.settings, clientId:'new-client'}
    }})).status(),400);
    assert.equal((await page.request.put(settingsUrl, {
      headers:{Origin:'https://unrelated.example.test'}, data:{settings:stored.settings}
    })).status(),403);
    assert.equal((await page.request.put(settingsUrl, {headers,data:{
      settings:{...stored.settings, enabled:false}
    }})).status(),200);
    assert.deepEqual((await (await page.request.get(origin + '/api/auth/status')).json()).providers, []);
    assert.equal((await signedOut.request.post(origin + '/api/auth/oidc/workspace-sso/start', {headers})).status(), 404);
    console.log('PASS workspace OIDC settings, secret handling, sign-in options, SSO invites, and user-form alignment');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
