import {createHash} from 'node:crypto';
import assert from 'node:assert/strict';

const base = process.env.CERTHIA_TEST_URL;
assert.ok(base, 'Set CERTHIA_TEST_URL to a disposable instance.');
const origin = new URL(base).origin;
const email = process.env.CERTHIA_TEST_ADMIN_EMAIL;
const password = process.env.CERTHIA_TEST_ADMIN_PASSWORD;
assert.ok(email && password, 'Set CERTHIA_TEST_ADMIN_EMAIL and CERTHIA_TEST_ADMIN_PASSWORD to the test instance admin credentials.');
let cookie;
const scanTarget = {
  reference: 'registry.example.test/team/image:latest',
  platform: 'linux/amd64'
};

async function request(path, {method = 'GET', data, token, authorization, expected = 200, raw = false} = {}) {
  const response = await fetch(new URL('/api' + path, base), {
    method,
    headers: {
      ...(data ? {'Content-Type':'application/json'} : {}),
      Origin: origin,
      ...(cookie && !token && !authorization ? {Cookie:cookie} : {}),
      ...(authorization || token ? {Authorization:authorization ?? 'Bearer ' + token} : {}),
    },
    body:data ? JSON.stringify(data) : undefined
  });
  if (!(Array.isArray(expected) ? expected.includes(response.status) : response.status === expected)) throw new Error(method + ' ' + path + ' returned ' + response.status + ' ' + await response.text());
  if (raw) return Buffer.from(await response.arrayBuffer());
  return expected === 204 ? undefined : response.json();
}

// Fixture registry names can fail locally before a cancellation gets to the worker.
async function cancelScan(id) {
  await request('/scans/' + id + '/cancel', {method:'POST', expected:[204,409]});
  assert.ok(['cancelled','failed'].includes((await request('/scans/' + id)).status));
}

async function checkDuplicate(first, duplicate) {
  if (duplicate.queued === 0) {
    assert.deepEqual(duplicate, {scanIds:first.scanIds, queued:0});
  } else {
    assert.equal((await request('/scans/' + first.scanIds[0])).status, 'failed');
    assert.equal(duplicate.queued, 1);
    assert.notDeepEqual(duplicate.scanIds, first.scanIds);
  }
}

const health = await request('/health');
assert.equal(health.status, 'ok');
await request('/scans', {expected:401});
const signIn = await fetch(new URL('/api/auth/login', base), {
  method:'POST', headers:{'Content-Type':'application/json', Origin:origin},
  body:JSON.stringify({email,password})
});
assert.equal(signIn.status, 200, 'Sign in as the test instance administrator.');
cookie = signIn.headers.get('set-cookie')?.split(';')[0];
assert.match(cookie, /^(?:__Host-)?certhia_session=/);
const schema = await request('/openapi.json');
assert.equal(schema.info.title, 'Certhia');
assert.ok(schema.paths['/scheduled-scans/{id}/execute'].post);
assert.equal((await request('/scans')).length, 0, 'Use an empty disposable database.');

const report = (version, withVulnerability) => ({
  SchemaVersion: 2,
  ArtifactType: 'container_image',
  Metadata: {RepoDigests:['registry.example.test/team/image@sha256:' + createHash('sha256').update(version).digest('hex')], Size:1234, OS:{Family:'alpine', Name:'3.22'}},
  Results: [{
    Class:'os-pkgs', Type: 'alpine', Target:'fixture package inventory', Packages:[{Name:'openssl',Version:version}],
    Vulnerabilities:withVulnerability ? [{
      VulnerabilityID:'FIXTURE-ADVISORY-1',PkgName:'openssl',InstalledVersion:version,FixedVersion:'3.2',Severity:'HIGH'
    }] : [],
    Misconfigurations:[{ID:'CFG',AVDID:'AVD-FIXTURE',Title:'Configuration check',Status:'FAIL',Severity:'LOW'}],
    Secrets:[{RuleID:'placeholder',Title:'Fixture secret finding',Severity:'HIGH',Match:'synthetic-secret-value',Code:{Lines:[{Content:'synthetic-secret-value'}]}}]
  }]
});
const importVersion = (tag, data) => request('/scans/import?' + new URLSearchParams({...scanTarget, reference:'registry.example.test/team/image:' + tag}),{
  method:'POST',data,expected:201
});
const baseline = (await importVersion('v1', report('3.1', true))).id;
const target = (await importVersion('v2', report('3.2', false))).id;
const before = await request('/scans/' + baseline);
assert.equal(before.report.checks.length, 2);
assert.equal(before.report.counts.high, 1);
for (const [format, signature] of [
  ['pdf','%PDF-'],['xlsx','PK'],['zip','PK'],['json','{'],['raw','{'],['sbom','{'],['vex','{'],['markdown','# Certhia image report']
]) {
  const download = await request('/scans/' + baseline + '/report/' + format,{raw:true});
  assert.ok(download.toString('utf8',0,signature.length).startsWith(signature), format);
  if (format === 'raw') assert.ok(!download.includes('synthetic-secret-value'));
  if (format === 'zip') {
    assert.ok(download.includes('report.pdf'));
    assert.ok(download.includes('report.xlsx'));
    assert.ok(download.includes('sbom.cdx.json'));
    assert.ok(download.includes('openvex.json'));
  }
}
const sbom = await request('/scans/' + baseline + '/report/sbom');
assert.equal(sbom.bomFormat, 'CycloneDX');
assert.match(sbom.metadata.component.purl, /^pkg:oci\/image@sha256%3A/);
assert.equal(sbom.components[0].name, 'openssl');
const vexBefore = await request('/scans/' + baseline + '/report/vex');
assert.equal(vexBefore['@context'], 'https://openvex.dev/ns/v0.2.0');
assert.equal(vexBefore.statements[0].products[0]['@id'], sbom.metadata.component['bom-ref']);
assert.equal(vexBefore.statements[0].status, 'under_investigation');
const comparison = await request('/compare?' + new URLSearchParams({baseline,target}));
assert.equal(comparison.changes.packages[0].status, 'Changed');
assert.equal(comparison.changes.findings[0].status, 'Removed');
await request('/scans/' + baseline + '/classifications',{method:'PUT',data:{
  finding:'FIXTURE-ADVISORY-1',status:'false_positive',note:'Fixture only'
},expected:204});
const vexAfter = await request('/scans/' + baseline + '/report/vex');
assert.equal(vexAfter.statements[0].status, 'not_affected');
assert.equal(vexAfter.statements[0].impact_statement, 'Fixture only');
const library = await request('/vulnerabilities?package=openssl');
assert.equal((await request('/library/packages')).openssl.HIGH, 1);
assert.equal(library[0].affected[0].status, 'false_positive');
assert.equal(library[0].affected[0].ecosystem, 'alpine');
assert.equal(Object.values(await request('/images'))[0].length, 2);

const trackingPath = '/scans/' + baseline + '/classifications';
const track = (status, extra = {}, expected = 204) => request(trackingPath, {method:'PUT', expected, data:{
  finding:'FIXTURE-ADVISORY-1', status, note:'Fixture tracking note', ...extra
}});
const trackers = '/settings/issue-trackers';
const jiraConfig = {name:'Security Jira', provider:'jira', urlTemplate:'https://tickets.example.test/browse/{id}'};
for (const urlTemplate of [
  'https://tickets.example.test/browse/42', 'https://{id}.example.test/issue',
  'https://user:secret@tickets.example.test/issue/{id}', 'https://tickets.example.test/{id}/{id}'
]) {
  await request(trackers,{method:'POST',data:{...jiraConfig,urlTemplate},expected:400});
}
const jira = await request(trackers,{method:'POST',data:jiraConfig,expected:201});
const redmine = await request(trackers,{method:'POST',data:{
  name:'Example Redmine',provider:'redmine',urlTemplate:'http://redmine.example.test:8080/issues/{id}'
},expected:201});
assert.deepEqual((await request(trackers)).map(item => item.name),['Example Redmine','Security Jira']);
const issue = {trackerId:jira.id, tracker:'jira', url:'https://tickets.example.test/browse/SEC-123', key:'SEC-123'};
await track('in_progress', {issue:{trackerId:jira.id, key:'SEC-123'}});
assert.deepEqual(await request('/scans/' + target + '/classifications'), []);
assert.deepEqual((await request('/vulnerabilities?advisory=FIXTURE-ADVISORY-1'))[0].affected[0].issue, issue);
const alias = (await importVersion('v1-alias', report('3.1', true))).id;
const aliasTrackingPath = '/scans/' + alias + '/classifications';
assert.deepEqual(await request(aliasTrackingPath), []);
await request(aliasTrackingPath,{method:'PUT',expected:204,data:{
  finding:'FIXTURE-ADVISORY-1',status:'accepted_risk',issue:{trackerId:jira.id,key:'SEC-456'}
}});
const versions = (await request('/vulnerabilities?latest=true&advisory=FIXTURE-ADVISORY-1'))[0].affected;
assert.equal(versions.find(row => row.scanId === baseline).issue.key, 'SEC-123');
assert.equal(versions.find(row => row.scanId === alias).issue.key, 'SEC-456');
assert.equal(versions.find(row => row.scanId === alias).status, 'accepted_risk');
await request('/images/delete',{method:'POST',data:{ids:[alias]}});
await request(trackers + '/' + jira.id,{method:'PUT',data:{...jiraConfig,urlTemplate:'https://new.example.test/browse/{id}'}});
await track('fixed');
assert.deepEqual((await request(trackingPath))[0].issue, issue);
for (const key of ['', '..', 'p/42', 'https://elsewhere.example.test/42']) {
  await track('open', {issue:{trackerId:jira.id,key}}, 400);
}
await track('open', {issue:{trackerId:'missing',key:'42'}}, 404);
const directLink = await request(trackingPath,{method:'PUT',data:{
  finding:'FIXTURE-ADVISORY-1',status:'open',issue:{tracker:'jira',url:'https://tickets.example.test/42',key:'42'}
},expected:422,raw:true});
assert.ok(directLink.length);
assert.equal((await request(trackingPath))[0].status, 'fixed');
await track('in_progress', {issue:{trackerId:jira.id,key:'SEC-124'}});
assert.equal((await request(trackingPath))[0].issue.url, 'https://new.example.test/browse/SEC-124');
await track('in_progress', {issue:{trackerId:redmine.id,key:'#3'}});
assert.equal((await request(trackingPath))[0].issue.url, 'http://redmine.example.test:8080/issues/3');
await request(trackers + '/' + redmine.id,{method:'DELETE',expected:204});
assert.deepEqual((await request(trackingPath))[0].issue, {
  tracker:'redmine',url:'http://redmine.example.test:8080/issues/3',key:'3'
});
await track('fixed', {issue:null});
const unlinked = (await request(trackingPath))[0];
assert.equal(unlinked.issue, null);
assert.equal(unlinked.status, 'fixed');
assert.equal(unlinked.note, 'Fixture tracking note');
await request(trackers + '/' + jira.id,{method:'DELETE',expected:204});

const patch = await request('/patches/analyze/' + baseline);
assert.equal(patch.packages[0].fixed, '3.2');
await request('/patches/execute',{method:'POST',data:{scanId:baseline,dryRun:true,selectedVulnIds:['FIXTURE-ADVISORY-1']},expected:202});
assert.equal((await request('/patches/history'))[0].status, 'planned');

const batch = await request('/scans/bulk',{method:'POST',data:{scans:[
  {...scanTarget, reference:'registry.example.test/team/batch:a',priority:-5},
  {...scanTarget, reference:'registry.example.test/team/batch:b',priority:10}
]},expected:202});
assert.equal((await request('/scans/' + batch.scanIds[1])).reference, 'registry.example.test/team/batch:b');
assert.equal((await request('/scans/bulk'))[0].total, 2);
await cancelScan(batch.scanIds[0]);

const schedule = await request('/scheduled-scans',{method:'POST',expected:201,data:{
  ...scanTarget,name:'Fixture schedule',expression:'0 3 * * *',enabled:false
}});
await request('/scheduled-scans/' + schedule.id,{method:'PUT',data:{
  ...schedule,enabled:true,expression:'0 6 * * *',
}});
const scheduled = await request('/scheduled-scans/' + schedule.id + '/execute',{method:'POST',expected:202});
assert.equal((await request('/scheduled-scans/history'))[0].scanId, scheduled.id);

await cancelScan(batch.scanIds[1]);
assert.equal((await request('/scans/bulk'))[0].finished, 2);

const patterned = await request('/scheduled-scans',{method:'POST',expected:201,data:{
  ...scanTarget,name:'Pattern test',expression:'0 9 * * *',enabled:false,mode:'pattern',
  imagePattern:'/team/batch$',tagPattern:'^b$',excludeTagPattern:'^dev$'
}});
const patternedRun = await request('/scheduled-scans/' + patterned.id + '/execute',{method:'POST',expected:202});
assert.deepEqual(patternedRun.scanIds, []);
assert.equal(patternedRun.total, 0);
await request('/scheduled-scans/' + patterned.id,{method:'DELETE',expected:204});

await request('/settings',{method:'PUT',data:{
  scanDays:30,auditDays:180,batchDays:45,channel:'webhook',notifyFailures:true,cleanupS3Artifacts:true
},expected:204});
assert.equal((await request('/settings')).scanDays, 30);
assert.ok((await request('/audit-logs')).some(entry => entry.action === 'settings.updated'));
assert.ok((await request('/discover/docker')).some(image => image.reference.startsWith('sha256:')));

const events = await fetch(new URL('/api/scans/' + batch.scanIds[1] + '/events', base), {headers:{Cookie:cookie}});
assert.match(await events.text(), /event: progress/);

await request('/scheduled-scans/' + schedule.id,{method:'DELETE',expected:204});
await cancelScan(scheduled.id);
await request('/images/delete',{method:'POST',data:{ids:[baseline,target,...batch.scanIds,scheduled.id]}});
assert.equal((await request('/scans')).length, 0);

const watchFixture = async (platform, data) => request('/scans/import?' + new URLSearchParams({
  reference:'registry.example.test/team/watch:stable',platform
}),{method:'POST',data,expected:201});
const original = await watchFixture('linux/amd64',report('3.1',true));
assert.equal(await request('/scans/' + original.id + '/watch'),null);
const watch = await request('/scans/' + original.id + '/watch',{method:'PUT'});
assert.equal((await request('/scans/' + original.id + '/watch',{method:'PUT'})).id,watch.id);
assert.equal((await request('/image-watches')).alerts.length,0);
const withNew = report('3.1',true);
const prior = withNew.Results[0].Vulnerabilities[0];
withNew.Results[0].Vulnerabilities.push({...prior,VulnerabilityID:'FIXTURE-NEW-2'});
const differentPlatform = await watchFixture('linux/arm64',withNew);
assert.equal((await request('/image-watches')).alerts.length,0);
const nextWatch = await watchFixture('linux/amd64',withNew);
const duplicateWatch = await watchFixture('linux/amd64',withNew);
const [{advisories,scanId,delivery}] = (await request('/image-watches')).alerts;
assert.deepEqual(advisories,['FIXTURE-NEW-2']);
assert.equal(scanId,nextWatch.id);
assert.equal(delivery,'pending');
assert.equal((await request('/image-watches')).alerts.length,1);
await request('/image-watches/' + watch.id,{method:'DELETE',expected:204});
assert.equal((await request('/image-watches')).watches.length,0);
await request('/images/delete',{method:'POST',data:{ids:[original.id,differentPlatform.id,nextWatch.id,duplicateWatch.id]}});

// The same advisory can appear in packages with different ecosystems.
const mixed = report('3.1', true);
mixed.Metadata.RepoDigests = ['registry.example.test/team/image@sha256:' + 'c'.repeat(64)];
delete mixed.Results[0].Type;
mixed.Results.push({...mixed.Results[0], Class:'lang-pkgs', Type:'java-archive'});
const mixedScan = (await importVersion('mixed', mixed)).id;
assert.deepEqual(
  (await request('/scans/' + mixedScan)).report.findings.map(finding => finding.ecosystem).sort(),
  ['java-archive', 'os-pkgs']
);
assert.deepEqual(
  (await request('/vulnerabilities'))[0].affected.map(item => item.ecosystem).sort(),
  ['java-archive', 'os-pkgs']
);
await request('/images/delete',{method:'POST',data:{ids:[mixedScan]}});

const availability = await request('/scanners/available');
assert.equal(availability.defaults, null);
assert.ok(availability.registry.includes('trivy'));
assert.deepEqual(availability.local, availability.registry);
await request('/settings/scanners',{method:'PUT',data:{scanners:['unknown']},expected:400});
const defaults = availability.registry.includes('grype') ? ['trivy','grype'] : ['trivy'];
await request('/settings/scanners',{method:'PUT',data:{scanners:[...defaults,'trivy']},expected:204});
assert.deepEqual((await request('/scanners/available')).defaults, defaults);
const registry = await request('/registries',{method:'POST',expected:201,data:{
  name:'Push test',host:'registry.example.test',provider:'harbor'
}});
const configPath = '/registries/' + registry.id + '/webhook';
assert.equal((await request(configPath)).createdAt, null);
const {token, ciPath, harborPath} = await request(configPath,{method:'POST'});
assert.ok(token.startsWith('certhia_wh_'));
assert.equal((await request(configPath)).token, undefined);
const ci = ciPath.slice(4);
const harbor = harborPath.slice(4);
await request(ci,{method:'POST',data:scanTarget,expected:401});
await request(ci,{method:'POST',token,data:{reference:'other.example/team/image:latest'},expected:400});
const pushed = await request(ci,{method:'POST',token,data:{reference:'team/image:next',platform:'linux/arm64'},expected:202});
assert.equal(pushed.queued, 1);
const duplicate = await request(ci,{method:'POST',token,data:{reference:'team/image:next',platform:'linux/arm64'},expected:202});
await checkDuplicate(pushed, duplicate);
const ciScan = await request('/scans/' + pushed.scanIds[0]);
assert.equal(ciScan.platform,'linux/arm64');
const ciScans = [...new Set([...pushed.scanIds,...duplicate.scanIds])];
for (const id of ciScans) await cancelScan(id);

const digest = 'sha256:' + 'b'.repeat(64);
const resources = ['next','stable'].map(tag => ({resource_url:'registry.example.test/team/image:' + tag,digest}));
const ignored = await request(harbor,{method:'POST',authorization:token,data:{type:'PULL_ARTIFACT'}});
assert.equal(ignored.ignored, true);
const harborPush = await request(harbor,{method:'POST',authorization:token,expected:202,data:{type:'PUSH_ARTIFACT',event_data:{resources}}});
assert.equal(harborPush.queued,1);
assert.equal((await request('/scans/' + harborPush.scanIds[0])).reference,'registry.example.test/team/image@' + digest);
const cloudEvent = await request(harbor,{method:'POST',token,expected:202,data:{type:'harbor.artifact.pushed',data:{resources}}});
await checkDuplicate(harborPush, cloudEvent);
const harborScans = [...new Set([...harborPush.scanIds,...cloudEvent.scanIds])];
for (const id of harborScans) await cancelScan(id);

const rotated = await request(configPath,{method:'POST'});
assert.notEqual(rotated.token,token);
await request(ci,{method:'POST',token,data:scanTarget,expected:401});
await request(configPath,{method:'DELETE',expected:204});
await request(ci,{method:'POST',token:rotated.token,data:scanTarget,expected:401});
await request('/registries/' + registry.id,{method:'DELETE',expected:204});
await request('/settings/scanners',{method:'PUT',data:{scanners:[]},expected:204});
assert.equal((await request('/scanners/available')).defaults,null);
await request('/images/delete',{method:'POST',data:{ids:[...ciScans,...harborScans]}});

console.log('Passed: imports and redaction, report formats, image/library grouping, triage, comparison, batches, cancellation, schedules, patch dry run, Docker inventory, retention settings, scanner defaults, registry webhooks, and audit events.');
