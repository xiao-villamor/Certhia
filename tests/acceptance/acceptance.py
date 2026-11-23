"""Run from a Certhia checkout after building the Rust binary and the web UI."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import http.cookiejar
import http.server
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import shlex
import socket
import socketserver
import statistics
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

HERE = Path(__file__).resolve().parent
PROJECT = Path(os.environ.get('CERTHIA_PROJECT', '.')).resolve()
TEST_IMAGE = 'example.test/team/app:v1'
FINDINGS = ('CVE-2099-0001', 'CVE-2099-0002')


class JsonHandler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class DockerFixture(JsonHandler):
    def do_GET(self):
        if self.path == '/services':
            self.reply(*self.server.services)
        elif self.path == '/images/json':
            self.reply(200, [{'Id': 'sha256:' + '1' * 64, 'RepoTags': ['local/image:running']},
                             {'Id': 'sha256:' + '2' * 64, 'RepoTags': ['local/image:idle']}])
        elif self.path == '/containers/json':
            self.reply(200, [{'ImageID': 'sha256:' + '1' * 64, 'State': 'running'}])
        else:
            self.reply(404, {})


class GiteaFixture(JsonHandler):
    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(url.query)
        if url.path == '/api/v1/packages/team' and query.get('type') == ['container']:
            if self.server.deny_catalog or self.headers.get('Authorization') != 'token ' + self.server.token:
                self.reply(403, {})
            else:
                self.reply(200, [{'name': 'api'}] if query.get('page') == ['1'] else [])
        elif url.path == '/v2/team/api/tags/list':
            self.reply(403, {}) if self.server.deny_tags else self.reply(200, {'tags': ['v1']})
        else:
            self.reply(404, {})


@contextlib.contextmanager
def serving(server):
    with server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


@contextlib.contextmanager
def postgres(tmp):
    password = secrets.token_urlsafe(32)
    config = tmp / 'pg.env'
    config.write_text('POSTGRES_PASSWORD=' + password + '\n')
    config.chmod(0o600)
    container = subprocess.check_output(
        ['docker', 'run', '--rm', '-d', '--tmpfs', '/var/lib/postgresql/data',
         '--env-file', str(config), '-p', '127.0.0.1::5432', 'postgres:17-alpine'],
        text=True).strip()
    try:
        port = subprocess.check_output(['docker', 'port', container, '5432/tcp'], text=True).splitlines()[0].rsplit(':', 1)[1]
        for _ in range(80):
            check = subprocess.run(['docker', 'exec', container, 'pg_isready', '-h', '127.0.0.1', '-U', 'postgres'],
                                   stdout=subprocess.DEVNULL)
            if check.returncode == 0:
                break
            time.sleep(.25)
        else:
            raise RuntimeError('PostgreSQL did not become ready')
        yield f'postgresql://postgres:{password}@127.0.0.1:{port}/postgres', container
    finally:
        subprocess.run(['docker', 'stop', '--time', '2', container], stdout=subprocess.DEVNULL, check=True)


class Api:
    def __init__(self, origin):
        self.origin = origin
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, path, data=None, method=None, status=200, mime='application/json', raw=False, token=None):
        content = data if isinstance(data, bytes) else json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(self.origin + '/api' + path,
                                     data=content, headers={'Content-Type': mime, 'Origin': self.origin},
                                     method=method)
        if token:
            req.add_header('Authorization', 'Bearer ' + token)
        try:
            response = self.opener.open(req, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read()
            assert response.status == status, (path, status, response.status, body.decode()[:220])
            return response.headers, (body if raw else json.loads(body) if body else None)

    def read(self, *args, **kwargs):
        return self.call(*args, **kwargs)[1]


def write_pods(tmp, digests, *, malformed=False):
    owner = {'kind': 'StatefulSet', 'name': 'api', 'uid': 'controller', 'controller': True}
    pods = []
    for index, digest in enumerate(digests):
        pod = {'metadata': {'namespace': 'prod', 'name': 'api-' + str(index), 'ownerReferences': [owner]},
               'spec': {'containers': [{'image': 'example.test/api:v1', 'name': 'api'}]}}
        if index == 0:
            pod['spec']['initContainers'] = [{'image': 'example.test/setup:v1', 'name': 'setup'}]
        if digest:
            pod['status'] = {'containerStatuses': [{'name': 'api', 'image': 'example.test/api:v1',
                                    'imageID': 'docker-pullable://example.test/api@sha256:' + digest * 64}]}
        pods.append(pod)
    (tmp / 'fixture-pods.json').write_text(json.dumps({'items': pods}) if not malformed else '{}')


def install_kubectl(tmp):
    bindir = tmp / 'bin'
    bindir.mkdir()
    script = bindir / 'kubectl'
    write_pods(tmp, ['a', 'a'])
    script.write_text(f'''#!/bin/sh
case "$*" in
  "get namespaces -o json --request-timeout=10s") exit 1 ;;
  "get pods -o json --request-timeout=10s --namespace prod")
    /bin/cat {shlex.quote(str(tmp / 'fixture-pods.json'))} ;;
  "get pods -o json --request-timeout=10s --namespace empty") echo '{{"items":[]}}' ;;
  *) exit 1 ;;
esac
''')
    script.chmod(0o700)
    return bindir


def test_discovery(api, docker, tmp, database_container):
    assert 'permission' in api.read('/discover/kubernetes/namespaces', status=400)['error'].lower()
    pods = api.read('/discover/kubernetes?namespace=prod')
    assert [(p['reference'], p['label']) for p in pods] == [
        ('example.test/api@sha256:' + 'a' * 64, 'prod/api (StatefulSet)'),
        ('example.test/setup:v1', 'prod/api (StatefulSet)')]
    assert [workload['pod'] for workload in pods[0]['usages']] == ['api-0', 'api-1']
    assert all(use['runtimeDigest'] for use in pods[0]['usages']) and pods[1]['usages'][0]['containerType'] == 'init'
    assert api.read('/discover/kubernetes?namespace=empty') == []
    assert 'permission' in api.read('/discover/kubernetes?namespace=denied', status=400)['error'].lower()
    print('PASS Kubernetes API: pods and init containers, deduplication, empty and denied namespaces', flush=True)
    image = 'example.test/team/api@sha256:' + 'a' * 64
    docker.services = 200, [{'Spec': {'Name': 'api-service', 'TaskTemplate': {'ContainerSpec': {'Image': image}}}}]
    assert api.read('/discover/swarm') == [{'reference': image, 'label': 'api-service',
                                          'registryHost':'example.test', 'digest':'sha256:' + 'a' * 64}]
    docker.services = 200, []
    assert api.read('/discover/swarm') == []
    docker.services = 503, {}
    assert 'manager' in api.read('/discover/swarm', status=400)['error'].lower()
    assert {item['label']: item['running'] for item in api.read('/discover/docker')} == {
        'local/image:running': True, 'local/image:idle': False}
    print('PASS Swarm and Docker API: digest, manager access error, and running status', flush=True)

    form = {'name': 'Watch workload digests', 'mode': 'kubernetes', 'kubernetesNamespace': 'prod',
            'reference': '', 'platform': 'linux/amd64', 'expression': '0 3 * * *', 'enabled': False}
    schedule_id = api.read('/scheduled-scans', form, status=201)['id']
    path = '/scheduled-scans/' + schedule_id

    def expect(digests):
        scans = api.read(path + '/execute', {}, status=202)['scanIds']
        assert [api.read('/scans/' + scan)['reference'] for scan in scans] == [
            'example.test/api@sha256:' + digest * 64 for digest in digests]

    expect(['a'])
    expect([])
    write_pods(tmp, [], malformed=True)
    assert 'pod list' in api.read(path + '/execute', {}, status=400)['error']
    write_pods(tmp, [None, 'a'])
    expect([])
    write_pods(tmp, ['a', 'b'])
    expect(['b'])
    write_pods(tmp, ['b', 'b'])
    expect([])
    write_pods(tmp, ['a'])
    expect(['a'])
    write_pods(tmp, ['c'])
    subprocess.run(['docker', 'exec', database_container, 'psql', '-U', 'postgres', '-v', 'ON_ERROR_STOP=1',
                    '-c', f"UPDATE schedules SET enabled=true,due_at=now() WHERE id='{schedule_id}'"],
                   stdout=subprocess.DEVNULL, check=True)
    deadline = time.monotonic() + 26
    while time.monotonic() < deadline:
        runs = api.read('/scheduled-scans/history')
        scheduled = next((run for run in runs if run['name'] == form['name'] and run['trigger'] == 'schedule'), None)
        if scheduled and scheduled['scanId']:
            assert api.read('/scans/' + scheduled['scanId'])['reference'] == 'example.test/api@sha256:' + 'c' * 64
            break
        time.sleep(.3)
    else:
        raise AssertionError('The due Kubernetes schedule did not queue its changed digest')
    api.read(path, method='DELETE', status=204)
    print('PASS Kubernetes schedule: baseline, deduplication, incomplete status, rollout, rollback and automatic cron execution', flush=True)


def test_registries(api, gitea):
    host = '127.0.0.1:' + str(gitea.server_port)
    profile = api.read('/registries', {'name': 'Local Gitea', 'provider': 'gitea', 'host': host, 'namespace': 'team',
                                     'protocol': 'http', 'username': 'tester', 'password': gitea.token}, status=201)
    path = '/registries/' + profile['id']
    catalog = api.read(path + '/catalog', method='POST')
    assert catalog['error'] is None and catalog['images'] == ['team/api'], catalog
    assert api.read(path + '/tags?image=team/api')['tags'] == ['v1']
    gitea.deny_tags = True
    assert '403' in api.read(path + '/tags?image=team/api', status=400)['error']
    gitea.deny_catalog = True
    assert '403' in api.read(path + '/catalog', method='POST')['error']
    google_host = 'us-docker.pkg.dev'
    google = api.read('/registries', {'name': 'Test GAR', 'provider': 'gar', 'host': google_host,
                                      'namespace': 'demo-project/images', 'username': 'oauth2accesstoken',
                                      'password': secrets.token_urlsafe(24)}, status=201)
    # No external Google calls. Verify validation and storage of direct references through the real queue.
    for config, server, repo in [(profile, host, 'team/api'), (google, google_host, 'demo-project/images/api')]:
        for suffix in [':v1', '@sha256:' + 'b' * 64]:
            target = {'reference': repo + suffix, 'platform': 'linux/amd64', 'source': 'registry', 'registryId': config['id']}
            queued = api.read('/scans', target, status=202)
            record = api.read('/scans/' + queued['id'])
            assert (record['reference'], record['source'], record['platform']) == (server + '/' + repo + suffix, 'registry', 'linux/amd64'), record
    print('PASS Gitea protocol fixture: authenticated catalog, tags, denied catalog/tags; Gitea and GAR profiles: queue exact tag and digest', flush=True)


def import_report(api, reference=TEST_IMAGE, platform='linux/amd64', digest='a', extra_package=False):
    repo = reference.rsplit(':', 1)[0]
    report = {'SchemaVersion': 2, 'ArtifactType': 'container_image',
              'Metadata': {'RepoDigests': [repo + '@sha256:' + digest * 64]},
              'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Target': 'fixture',
                           'Packages': [{'Name': 'demo-package', 'Version': '1.2.3'}],
                           'Vulnerabilities': [{'VulnerabilityID': cve, 'PkgName': 'demo-package', 'InstalledVersion': '1.2.3',
                                                'FixedVersion': '1.2.4', 'Severity': 'HIGH', 'Title': 'Test finding'} for cve in FINDINGS]}]}
    if extra_package:
        result = report['Results'][0]
        result['Packages'].append({'Name': 'demo-runtime', 'Version': '1.2.3'})
        result['Vulnerabilities'].append({**result['Vulnerabilities'][0], 'PkgName': 'demo-runtime'})
    query = urllib.parse.urlencode({'reference': reference, 'platform': platform})
    return api.read('/scans/import?' + query, report, status=201)['id']


def tar_bytes(files):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as archive:
        for name, content in files.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            archive.addfile(entry, io.BytesIO(content))
    return buffer.getvalue()


def image_archive(name, version):
    dist = f'usr/local/lib/python3.12/site-packages/{name.replace("-", "_")}-{version}.dist-info/'
    layer = tar_bytes({
        dist + 'METADATA': f'Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\n'.encode(),
        dist + 'RECORD': (dist.split('/')[-2] + '/METADATA,,\n').encode(),
        'etc/os-release': b'ID=alpine\nVERSION_ID=3.22\n',
    })
    layer_id = hashlib.sha256(layer).hexdigest()
    config = json.dumps({'architecture': 'amd64', 'os': 'linux', 'config': {},
                         'history': [{'created_by': 'Certhia acceptance test'}],
                         'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + layer_id]}}).encode()
    config_name = hashlib.sha256(config).hexdigest() + '.json'
    layer_name = layer_id + '/layer.tar'
    manifest = [{'Config': config_name, 'RepoTags': ['certhia/fixture:test'], 'Layers': [layer_name]}]
    return tar_bytes({'manifest.json': json.dumps(manifest).encode(), config_name: config, layer_name: layer})


def scan_archive(api, archive, reference, engines, completed=None):
    params = urllib.parse.urlencode({'reference': reference, 'platform': 'linux/amd64', 'scanners': ','.join(engines)})
    scan = api.read('/scans/archive?' + params, archive, status=202, mime='application/x-tar')['id']
    path = '/scans/' + scan
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        detail = api.read(path)
        if detail['status'] == 'completed':
            break
        assert detail['status'] in ('queued', 'running'), (detail['status'], detail.get('error'))
        time.sleep(.25)
    else:
        raise TimeoutError('Scan did not finish: ' + ', '.join(engines))
    expected = sorted(engines if completed is None else completed)
    if sorted(detail['report']['scanners']) != expected:
        raise AssertionError(('Providers that completed', detail['report']['scanners'], 'Expected', expected, scan))
    return path


def test_real_syft(api):
    path = scan_archive(api, image_archive('certhia-fixture', '4.5.6'), 'certhia/fixture:test', ['syft'])
    for endpoint in ('/report/sbom', '/scanner-results/sbom'):
        document = api.read(path + endpoint)
        assert document['bomFormat'] == 'CycloneDX'
        assert any(p['name'] == 'certhia-fixture' and p['version'] == '4.5.6' for p in document['components']), endpoint
    native = api.read(path + '/scanner-results/syft')
    assert native['descriptor']['name'] == 'syft'
    print('PASS real Syft ' + native['descriptor']['version'] +
          ': archived image -> worker -> original and generated SBOMs with certhia-fixture 4.5.6', flush=True)


def test_providers(api, email, password, grype_binary, grype_cache):
    archive = image_archive('idna', '3.6')
    cve, ghsa = 'CVE-2024-3651', 'GHSA-jjg7-2v4v-x38h'
    repetitions = int(os.environ.get('CERTHIA_TEST_SCAN_REPETITIONS', '1'))
    if not 1 <= repetitions <= 100:
        raise ValueError('CERTHIA_TEST_SCAN_REPETITIONS must be between 1 and 100')
    timings = {}
    for engines in [['trivy'], ['grype'], ['trivy', 'grype', 'syft']]:
        samples = []
        for _ in range(repetitions):
            started = time.monotonic()
            path = scan_archive(api, archive, 'certhia/idna:test', engines)
            samples.append((time.monotonic() - started) * 1000)
        timings['+'.join(engines)] = {'samplesMs':samples, 'medianMs': statistics.median(samples),
                                     'p95Ms': sorted(samples)[(95 * len(samples) + 99) // 100 - 1]}
        report = api.read(path + '/report/json')['report']
        matches = [f for f in report['findings'] if f['package'] == 'idna' and cve in [f['id'], *f['aliases']]]
        assert len(matches) == 1 and matches[0]['id'] == cve and ghsa in matches[0]['aliases'], matches
        expected = sorted(set(engines) & {'trivy', 'grype'})
        assert matches[0]['detectedBy'] == expected, matches
        sources = api.read(path + '/finding-sources')
        assert sorted({row['scanner'] for row in sources if row['id'] == cve and row['package'] == 'idna'}) == expected
        print('PASS native providers ' + ', '.join(engines) + ': ' + cve + ' and ' + ghsa + ', findings attributed to ' + ', '.join(expected), flush=True)
    markdown = api.read(path + '/report/markdown', raw=True).decode()
    row = next(line for line in markdown.splitlines() if line.startswith('- ' + cve + ' |'))
    assert ghsa in row and 'Detected by: Grype, Trivy' in row and 'Syft' not in row, row
    vex = api.read(path + '/report/vex')
    assert any(s['vulnerability']['name'] == cve and ghsa in s['vulnerability']['aliases'] for s in vex['statements'])
    sbom = api.read(path + '/report/sbom')
    assert {tool['name'] for tool in sbom['metadata']['tools']['components']} == {'Syft', 'Trivy', 'Grype'}
    comparison = api.read(path + '/report/discrepancies')
    assert comparison['target'] in ('matching image ID', 'matching manifest digest')
    bundle = api.read(path + '/report/zip', raw=True)
    with zipfile.ZipFile(io.BytesIO(bundle)) as files:
        assert json.loads(files.read('discrepancies.json')) == comparison
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in ('trivy.json', 'grype.json'):
                (target / name).write_bytes(files.read(name))
            binary = os.environ.get('CERTHIA_BINARY', str(PROJECT / 'backend/target/debug/digestdesk'))
            cli = subprocess.check_output([binary, 'explain', '--trivy', str(target / 'trivy.json'),
                                            '--grype', str(target / 'grype.json'), '--json'], text=True)
            assert json.loads(cli) == comparison, 'The CLI and scan report should match'
            native = json.loads(files.read('grype.json'))
            match = next(m for m in native['matches'] if m['vulnerability']['id'] == cve)
            assert ghsa in [r['id'] for r in match['relatedVulnerabilities']]
            # Certhia runs Grype with --by-cve. A standalone user may supply Grype's default GHSA output.
            (target / 'image.tar').write_bytes(archive)
            subprocess.run([grype_binary, 'docker-archive:' + str(target / 'image.tar'), '--quiet', '-o', 'json',
                            '--file', str(target / 'grype-default.json')],
                           env={**os.environ, 'GRYPE_DB_CACHE_DIR':str(grype_cache), 'GRYPE_DB_AUTO_UPDATE':'false',
                                'GRYPE_CHECK_FOR_APP_UPDATE':'false'}, check=True)
            standalone = json.loads(subprocess.check_output([binary, 'explain', '--trivy', str(target/'trivy.json'),
                                    '--grype', str(target/'grype-default.json'), '--json']))
            linked = next(row for row in standalone['differences'] if row['trivy'] and row['trivy']['advisory'] == cve)
            assert linked['grype']['advisory'] == ghsa and any('aliases' in r for r in linked['reasons'])
            print('PASS default Grype advisory reconciled with Trivy; Certhia native --by-cve originals compared independently', flush=True)
        bundled = json.loads(files.read('report.json'))['report']
        assert bundled == report
        assert files.read('report.md').decode() == markdown
        pdf = files.read('report.pdf')
        for token in (cve, ghsa, 'Detected by', 'Grype, Trivy'):
            assert token.encode() in pdf, ('PDF', token)
        with zipfile.ZipFile(io.BytesIO(files.read('report.xlsx'))) as sheet:
            shared = sheet.read('xl/sharedStrings.xml')
            for token in (cve, ghsa, 'Aliases', 'Detected by', 'Grype, Trivy'):
                assert token.encode() in shared, ('XLSX', token)
    subprocess.run(['node', str(HERE / 'provider-report.cjs'), api.origin, path.rsplit('/', 1)[1]],
                   env={**os.environ, 'CERTHIA_TEST_EMAIL': email, 'CERTHIA_TEST_PASSWORD': password}, check=True)
    if output := os.environ.get('CERTHIA_TEST_OUTPUT'):
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'informe-multimotor.zip').write_bytes(bundle)
        (directory / 'tiempos-escaneo.json').write_text(json.dumps({'archiveSha256':hashlib.sha256(archive).hexdigest(),
            'pollIntervalMs':250, 'repetitions':repetitions, 'providers':timings},indent=2) + '\n')
    print('PASS native multi-engine JSON, Markdown, PDF, XLSX, ZIP and standard exports; CLI and discrepancy report agree', flush=True)
    return path.rsplit('/', 1)[1]


def test_sbom(api, bindir):
    purl = 'pkg:apk/alpine/demo-package@1.2.3'
    fixture = {
        'SchemaVersion': 2, 'ArtifactType': 'container_image',
        'Metadata': {'RepoDigests': ['example.test/team/sbom@sha256:' + 'b' * 64]},
        'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Target': 'fixture', 'Packages': [
            {'Name': 'demo-package', 'Version': '1.2.3', 'Identifier': {'PURL': purl}},
            {'Name': 'legacy-package', 'Version': '2.0.0'},
        ]}],
    }
    scanner = bindir / 'trivy'
    scanner.write_text(
        '#!/bin/sh\nwhile [ "$1" != "--output" ]; do shift; done\n'
        + "printf '%s\\n' '" + json.dumps(fixture) + "' > \"$2\"\n"
    )
    scanner.chmod(0o700)
    try:
        for enabled in (False, True):
            form = {'name': 'SBOM test', 'expression': '0 3 * * *', 'enabled': False,
                    'reference': 'example.test/team/sbom:v1', 'platform': 'linux/amd64'}
            if enabled:
                form['retainSbom'] = True
            schedule = api.read('/scheduled-scans', form, status=201)
            assert schedule['retainSbom'] is enabled
            schedule_path = '/scheduled-scans/' + schedule['id']
            scan = api.read(schedule_path + '/execute', {}, status=202)['scanIds'][0]
            api.call(schedule_path, method='DELETE', status=204)
            path = '/scans/' + scan
            for _ in range(120):
                detail = api.read(path)
                if detail['status'] not in ('queued', 'running'):
                    break
                time.sleep(.25)
            assert detail['status'] == 'completed', detail.get('error')
            sources = api.read(path + '/scanner-results')['scanners']
            assert ('scheduled-sbom' in sources) is enabled
            artifact = path + '/scanner-results/scheduled-sbom'
            if enabled:
                headers, cdx = api.call(artifact)
                assert headers.get_content_type() == 'application/vnd.cyclonedx+json'
                assert cdx['serialNumber'] == 'urn:uuid:' + scan
            else:
                api.call(artifact, status=404)
                cdx = api.read(path + '/report/cyclonedx')
            assert {c['name']: c.get('purl') for c in cdx['components']} == {
                'demo-package': purl, 'legacy-package': None,
            }
            headers, spdx = api.call(path + '/report/spdx')
            assert headers.get_content_type() == 'application/spdx+json'
            assert '.spdx.json' in headers['Content-Disposition']
            assert spdx['spdxVersion'] == 'SPDX-2.3'
            assert {p['name']: p['externalRefs'][0]['referenceLocator']
                    for p in spdx['packages'][1:] if 'externalRefs' in p} == {'demo-package': purl}
            if schema_path := os.environ.get('CERTHIA_TEST_SPDX_SCHEMA'):
                import jsonschema
                jsonschema.validate(spdx, json.loads(Path(schema_path).read_text()),
                                    format_checker=jsonschema.FormatChecker())
            if enabled:
                archive = api.read(path + '/report/zip', raw=True)
                with zipfile.ZipFile(io.BytesIO(archive)) as bundle:
                    assert json.loads(bundle.read('sbom.spdx.json'))['packages'] == spdx['packages']
                    bundled_cdx = json.loads(bundle.read('sbom.cdx.json'))
                    assert {c['name']: c for c in bundled_cdx['components']} == {c['name']: c for c in cdx['components']}
    finally:
        scanner.unlink()
    print('PASS scheduled SBOM opt-in and retrieval, CycloneDX PURLs and SPDX export', flush=True)


def test_reports(api, email, password):
    baseline = import_report(api)
    headers, sbom = api.call('/scans/' + baseline + '/report/sbom')
    assert headers.get_content_type() == 'application/vnd.cyclonedx+json'
    assert 'attachment' in headers['Content-Disposition'] and '.cdx.json' in headers['Content-Disposition']
    assert (sbom['bomFormat'], sbom['specVersion']) == ('CycloneDX', '1.6')
    assert [(c['name'], c['version']) for c in sbom['components']] == [('demo-package', '1.2.3')]
    print('PASS real Trivy JSON import and actual CycloneDX 1.6 download with package, version, filename and MIME', flush=True)
    subprocess.run(['node', str(HERE / 'triage.cjs'), api.origin, baseline],
                   env={**os.environ, 'CERTHIA_TEST_EMAIL': email, 'CERTHIA_TEST_PASSWORD': password}, check=True)
    expected = {FINDINGS[0]: 'false_positive', FINDINGS[1]: 'accepted_risk'}
    for scan in [baseline, import_report(api)]:
        classifications = api.read('/scans/' + scan + '/classifications')
        assert {row['finding']: row['status'] for row in classifications} == expected
    for scan in [import_report(api, digest='b'), import_report(api, platform='linux/arm64'),
                 import_report(api, reference='example.test/team/app:alias'), import_report(api, reference='example.test/other/app:v1')]:
        assert api.read('/scans/' + scan + '/classifications') == []
    print('PASS real PostgreSQL: same identity retains both decisions; other digest, platform, tag and repository do not inherit them', flush=True)


def test_shared_ticket(api, email, password):
    finding = FINDINGS[0]
    tracker = api.read('/settings/issue-trackers', {'name':'Security Jira','provider':'jira',
        'urlTemplate':'https://issues.example.test/browse/{id}'}, status=201)
    first = import_report(api, reference='example.test/team/multi:v1', digest='c', extra_package=True)
    other = import_report(api, reference='example.test/other/runtime:v2', platform='linux/arm64', digest='d')
    subprocess.run(['node', str(HERE / 'triage.cjs'), api.origin, first, other, tracker['id']],
        env={**os.environ,'CERTHIA_TEST_EMAIL':email,'CERTHIA_TEST_PASSWORD':password},check=True)
    def tracking(scan):
        return '/scans/' + scan + '/classifications'
    imported = api.read(tracking(other) + '?finding=' + finding)[0]
    assert imported['issue']['key'] == 'SEC-6020' and imported['issue']['scope'] == 'advisory'
    assert imported['status'] == 'open' and imported['note'] == ''
    library = api.read('/vulnerabilities?advisory=' + finding + '&q=SEC-6020&linked=true')
    affected = library[0]['affected']
    assert len([row for row in affected if row['scanId'] == first]) == 2
    assert all(row['issue']['key'] == 'SEC-6020' for row in affected)
    api.call(tracking(other), {'finding':finding,'status':'accepted_risk',
        'issue':{'trackerId':tracker['id'],'key':'SEC-OTHER'}},method='PUT',status=204)
    assert api.read(tracking(other))[0]['issue']['key'] == 'SEC-OTHER'
    api.call(tracking(first), {'finding':finding,'status':'in_progress','issueScope':'advisory',
        'issue':None},method='PUT',status=204)
    assert api.read(tracking(first))[0]['issue'] is None
    assert api.read(tracking(other))[0]['issue']['key'] == 'SEC-OTHER'
    print('PASS shared CVE ticket visible across images and packages, independently removable', flush=True)


def test_exceptions(api, email, password):
    finding = FINDINGS[0]
    first = import_report(api, reference='example.test/exception/app:v1', digest='2', extra_package=True)
    newer = import_report(api, reference='example.test/exception/app:v1', digest='3', extra_package=True)
    tag = import_report(api, reference='example.test/exception/app:v2', digest='4')
    arm = import_report(api, reference='example.test/exception/app:v1', platform='linux/arm64', digest='5')
    other = import_report(api, reference='example.test/exception/other:v1', digest='6')

    def path(scan):
        return '/scans/' + scan + '/classifications'

    def edit(scan, body, status=204):
        api.call(path(scan), {'finding': finding, 'status': 'open', 'exceptionEdit': body},
                 method='PUT', status=status)

    def policy(scan):
        rows = api.read(path(scan) + '?finding=' + finding)
        return rows[0].get('exception') if rows else None

    def affected(status):
        return [row for group in api.read('/vulnerabilities?' + urllib.parse.urlencode(
                {'advisory': finding, 'status': status, 'q': 'example.test/exception/'}))
                for row in group['affected']]

    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    policy_input = {'action': 'set', 'scope': 'reference', 'reason': '  Staging compensation  ', 'expiresAt': future}
    edit(first, {**policy_input, 'reason': '   '}, 400)
    edit(first, {**policy_input, 'expiresAt': '2000-01-01T00:00:00Z'}, 400)
    assert policy(first) is None
    edit(first, policy_input)
    assert policy(newer)['reason'] == 'Staging compensation'
    assert policy(tag) is None and policy(arm) is None and policy(other) is None
    assert [row['scanId'] for row in affected('excepted')] == [newer, newer]
    edit(tag, {**policy_input, 'scope': 'repository', 'reason': 'Temporary repository exception'})
    assert policy(tag)['scope'] == 'repository' and policy(newer)['scope'] == 'reference'
    edit(newer, {'action': 'revoke', 'scope': 'reference'})
    assert policy(newer)['reason'] == 'Temporary repository exception'
    assert {row['scanId'] for row in affected('excepted')} == {newer, tag}
    soon = (datetime.now(timezone.utc) + timedelta(seconds=2)).isoformat()
    edit(tag, {**policy_input, 'scope': 'repository', 'expiresAt': soon})
    deadline = time.monotonic() + 5
    while policy(newer) and time.monotonic() < deadline:
        time.sleep(.1)
    assert policy(newer) is None and policy(tag) is None
    assert affected('excepted') == [] and {row['scanId'] for row in affected('open')} == {newer, tag, arm, other}
    assert any(row['id'] == finding for row in api.read('/scans/' + newer + '/report/json')['report']['findings'])
    subprocess.run(['node', str(HERE / 'triage.cjs'), api.origin, newer, 'exceptions'],
        env={**os.environ, 'CERTHIA_TEST_EMAIL': email, 'CERTHIA_TEST_PASSWORD': password}, check=True)
    print('PASS expiring CVE exceptions: narrower scope wins, revocation falls back, expiry restores open findings and keeps report evidence', flush=True)


def test_ci_scan(api, bindir, tmp):
    host = 'ci.example.test'
    path = api.read('/registries', {'name': 'CI fixture', 'host': host, 'provider': 'oci'}, status=201)['id']
    config = api.read('/registries/' + path + '/webhook', method='POST')
    ci = config['ciPath'][4:]
    token = config['token']
    image = host + '/team/test@sha256:' + '9' * 64
    fixture = tmp / 'ci-report.json'
    fixture.write_text(json.dumps({
        'SchemaVersion': 2, 'ArtifactType': 'container_image', 'Metadata': {'RepoDigests': [image]},
        'Results': [{'Class': 'os-pkgs', 'Type': 'alpine', 'Target': 'fixture',
                     'Vulnerabilities': [
                         {'VulnerabilityID': FINDINGS[0], 'PkgName': name, 'InstalledVersion': '1.0',
                          'FixedVersion': '1.1', 'Severity': rating}
                         for name, rating in [('demo', 'HIGH'), ('demo-runtime', 'CRITICAL')]
                     ]}]
    }))
    trivy = bindir / 'trivy'
    trivy.write_text(f'''#!/bin/sh
for arg in "$@"; do
  if [ "$output_next" = "yes" ]; then output="$arg"; output_next=no; fi
  if [ "$arg" = "--output" ]; then output_next=yes; fi
  last="$arg"
done
[ "$last" = {shlex.quote(image)} ] || exit 1
/bin/cp {shlex.quote(str(fixture))} "$output"
''')
    trivy.chmod(0o700)
    action = PROJECT / 'integrations/github-action/scan.cjs'
    output = tmp / 'ci-output.txt'
    summary = tmp / 'ci-summary.md'
    env = {**os.environ, 'INPUT_WEBHOOK-URL': api.origin + config['ciPath'],
           'INPUT_WEBHOOK-TOKEN': token, 'INPUT_IMAGE': image, 'INPUT_TIMEOUT-SECONDS': '20',
           'GITHUB_OUTPUT': str(output), 'GITHUB_STEP_SUMMARY': str(summary)}
    try:
        subprocess.run(['node', str(action)], env=env, check=True, capture_output=True, text=True)
        result = dict(line.split('=', 1) for line in output.read_text().splitlines())
        assert result['fixable-high'] == '0' and result['fixable-critical'] == '1'
        assert result['report-url'] in summary.read_text()
        result_path = ci + '/' + result['scan-id']
        machine = Api(api.origin)
        machine.read(result_path, status=401)
        headers, report = machine.call(result_path, token=token)
        assert headers['Cache-Control'] == 'no-store'
        assert report['observationComplete'] is True and report['scanners'] == ['trivy']
        machine.read('/scans/' + result['scan-id'], token=token, status=401)
        unrelated = import_report(api, reference=host + '/team/other:v1', digest='f')
        machine.read(ci + '/' + unrelated, token=token, status=404)
        other_profile = api.read('/registries', {'name': 'Other CI', 'host': 'other-ci.example.test', 'provider': 'oci'}, status=201)
        other = api.read('/registries/' + other_profile['id'] + '/webhook', method='POST')
        machine.read(result_path, token=other['token'], status=401)
        machine.read(other['ciPath'][4:] + '/' + result['scan-id'], token=other['token'], status=404)
        failed = subprocess.run(['node', str(action)], env={**env, 'INPUT_FAIL-ON-FIXABLE': 'critical'},
                                capture_output=True, text=True, check=False)
        assert failed.returncode == 1 and 'at or above the selected severity' in failed.stderr, failed.stderr
        scanner_failure = subprocess.run(['node', str(action)], env={
            **env, 'INPUT_IMAGE': host + '/team/test@sha256:' + '8' * 64,
        }, capture_output=True, text=True, check=False)
        assert scanner_failure.returncode == 1 and 'scan did not complete' in scanner_failure.stderr, scanner_failure.stderr
        api.read('/registries/' + path + '/webhook', method='DELETE', status=204)
        machine.read(result_path, token=token, status=401)
    finally:
        trivy.unlink()
    print('PASS GitHub Action and CI API: poll a digest scan, report deduplicated fixes, enforce the gate and protect results across profiles', flush=True)


def test_vulnerability_comparison(api, binary, bindir, tmp, email, password):
    cve, ghsa = 'CVE-2099-0002', 'GHSA-2345-6789-cfgh'
    purl = 'pkg:npm/example@1.0.0'
    raw = {
        'trivy': {'SchemaVersion':2, 'ArtifactType':'container_image', 'Results':[{'Type':'node-pkg',
            'Vulnerabilities':[{'VulnerabilityID':cve,'VendorIDs':[ghsa],'PkgName':'example','InstalledVersion':'1.0.0',
                'FixedVersion':'1.1.0','Severity':'CRITICAL','PkgIdentifier':{'PURL':purl}}]}]},
        'grype': {'matches':[{'artifact':{'name':'example','version':'1.0.0','type':'npm','purl':purl},
            'vulnerability':{'id':cve,'severity':'Critical','fix':{'versions':['1.1.0']}}}]},
        'osv': json.loads((PROJECT / 'backend/src/fixtures/scanners/osv.json').read_text().replace('GHSA-fixture', ghsa))
    }
    executables = []
    try:
        for engine, name, flag in [('trivy','trivy','--output'),('grype','grype','--file'),('osv','osv-scanner','--output-file')]:
            artifact = tmp / (engine + '.json')
            artifact.write_text(json.dumps(raw[engine]))
            executable = bindir / name
            executable.write_text('#!/bin/sh\nwhile [ "$#" -gt 1 ]; do\n'
                f'  if [ "$1" = "{flag}" ]; then /bin/cp {shlex.quote(str(artifact))} "$2"; exit $?; fi\n'
                '  shift\ndone\nexit 2\n')
            executable.chmod(0o700)
            executables.append(executable)
        for engines in [['trivy','grype','osv'],['trivy','osv'],['grype','osv']]:
            shown = ['trivy','grype','osv']
            enabled = [engine for engine in shown if engine in engines]
            path = scan_archive(api, image_archive('test', '1.0.0'), 'certhia/compare:test', enabled)
            result = api.read(path + '/report/discrepancies')
            assert result['scanners'] == enabled
            assert (result['autoResolved'], result['needsReview']) == (1,0), result
            assert result['differences'][0]['osv']['advisory'] == ghsa
            assert set(api.read(path + '/scanner-results')['scanners']) == set(engines)
            with zipfile.ZipFile(io.BytesIO(api.read(path + '/report/zip', raw=True))) as report:
                assert json.loads(report.read('discrepancies.json')) == result
            args = [argument for engine in enabled for argument in ['--' + engine, str(tmp / (engine + '.json'))]]
            cli = json.loads(subprocess.check_output([str(binary),'explain','--same-input','--json',*args]))
            assert cli == result, (cli, result)
            if len(enabled) == 3:
                subprocess.run(['node',str(HERE / 'provider-report.cjs'),api.origin,path.rsplit('/',1)[1],'osv'],
                    env={**os.environ,'CERTHIA_TEST_EMAIL':email,'CERTHIA_TEST_PASSWORD':password},check=True)
        print('PASS completed comparison with OSV-Scanner in API, ZIP and CLI (scanner report fixtures)', flush=True)
    finally:
        for executable in executables:
            executable.unlink()


def main():
    binary = Path(os.environ.get('CERTHIA_BINARY', PROJECT / 'backend/target/debug/digestdesk')).resolve()
    if not binary.is_file() or not (PROJECT / 'web/build/200.html').is_file():
        raise RuntimeError('Build the Rust binary and web UI first; run from the checkout or set CERTHIA_PROJECT')
    subprocess.run(['node', str(HERE / 'browser-flows.cjs')], check=True)
    with tempfile.TemporaryDirectory(prefix='certhia-check-', dir=os.environ.get('CERTHIA_TEST_TMP')) as directory, contextlib.ExitStack() as stack:
        tmp = Path(directory)
        database, database_container = stack.enter_context(postgres(tmp))
        socket_path = str(tmp / 'swarm.sock')
        docker_fixture = stack.enter_context(serving(socketserver.UnixStreamServer(socket_path, DockerFixture)))
        gitea = stack.enter_context(serving(http.server.ThreadingHTTPServer(('127.0.0.1', 0), GiteaFixture)))
        docker_fixture.services = 200, []
        gitea.token = secrets.token_urlsafe(32)
        gitea.deny_catalog = gitea.deny_tags = False
        bindir = install_kubectl(tmp)
        binaries = {tool: os.environ.get('CERTHIA_TEST_' + tool.upper()) or shutil.which(tool)
                    for tool in ('trivy', 'grype', 'syft')}
        seeds = os.environ.get('CERTHIA_TEST_DB_CACHE')
        if seeds:
            (tmp / 'data').mkdir()
            for engine in ('trivy', 'grype'):
                seed = Path(seeds) / engine
                if seed.is_dir():
                    (tmp / 'data' / engine).symlink_to(seed.resolve())

        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            bind = '127.0.0.1:' + str(sock.getsockname()[1])
        api = Api('http://' + bind)
        email, password = 'ux@example.test', secrets.token_urlsafe(32)
        env = {'PATH': str(bindir), 'DATABASE_URL': database, 'CERTHIA_ADMIN_EMAIL': email,
               'CERTHIA_ADMIN_PASSWORD': password, 'CERTHIA_AUTH_SECURE_COOKIE': '0', 'CERTHIA_BIND': bind,
               'CERTHIA_WEB_DIR': str(PROJECT / 'web/build'), 'CERTHIA_DATA_DIR': str(tmp / 'data'),
               'KUBECONFIG': str(tmp / 'isolated-kubeconfig'), 'CERTHIA_DOCKER_SOCKET': socket_path}
        if seeds:
            env.update(TRIVY_SKIP_DB_UPDATE='true', TRIVY_SKIP_JAVA_DB_UPDATE='true',
                       GRYPE_DB_AUTO_UPDATE='false')
        env.update(GRYPE_CHECK_FOR_APP_UPDATE='false', TRIVY_SKIP_CHECK_UPDATE='true', TRIVY_OFFLINE_SCAN='true',
                   HOME=str(tmp))
        log = stack.enter_context((tmp / 'api.log').open('w'))
        app = subprocess.Popen([str(binary)], cwd=tmp, env=env, stdout=log, stderr=log)
        try:
            for _ in range(80):
                if app.poll() is not None:
                    raise RuntimeError('The test API exited on startup')
                try:
                    api.call('/ready')
                    break
                except urllib.error.URLError:
                    time.sleep(.25)
            else:
                raise RuntimeError('The test API did not become ready')
            api.call('/auth/login', {'email': email, 'password': password})
            subprocess.run(['node', str(HERE / 'workspace-sso.cjs'), api.origin],
                env={**os.environ, 'CERTHIA_TEST_EMAIL':email, 'CERTHIA_TEST_PASSWORD':password}, check=True)
            test_discovery(api, docker_fixture, tmp, database_container)
            test_sbom(api, bindir)
            test_registries(api, gitea)
            test_reports(api, email, password)
            test_shared_ticket(api, email, password)
            test_exceptions(api, email, password)
            test_ci_scan(api, bindir, tmp)
            test_vulnerability_comparison(api, binary, bindir, tmp, email, password)
            for tool, executable in binaries.items():
                if executable:
                    (bindir / tool).symlink_to(Path(executable).resolve(strict=True))
            if binaries['syft']:
                test_real_syft(api)
            else:
                print('SKIP real Syft: install syft or set CERTHIA_TEST_SYFT to its executable', flush=True)
            if all(binaries.values()):
                scan_id = test_providers(api, email, password, binaries["grype"], tmp / "data/grype")
                # Exercise the worker's partial-success path with only the Grype executable replaced for this test.
                grype_link = bindir / 'grype'
                grype_link.unlink()
                grype_link.write_text('#!/bin/sh\nexit 1\n')
                grype_link.chmod(0o700)
                try:
                    partial = scan_archive(api, image_archive('idna', '3.6'), 'certhia/partial:test', ['syft','grype'], ['syft'])
                    observed = api.read(partial + '/report/json')['report']
                    assert observed['observationComplete'] is False and observed['findings'] == []
                    api.read(partial + '/report/discrepancies', status=400)
                    print('PASS controlled Grype failure with real Syft: partial inventory and no fabricated detector or comparison', flush=True)
                finally:
                    grype_link.unlink()
                    grype_link.symlink_to(Path(binaries['grype']).resolve())
                benchmark_dir = os.environ.get('CERTHIA_TEST_BENCH_DIR')
                if benchmark_dir:
                    dest = Path(benchmark_dir)
                    dest.mkdir(parents=True, exist_ok=True)
                    cookie = urllib.request.Request(api.origin + '/api/scans/' + scan_id)
                    api.jar.add_cookie_header(cookie)
                    bench_env = {**os.environ, 'CERTHIA_BENCH_COOKIE': cookie.get_header('Cookie')}
                    baseline = os.environ.get('CERTHIA_BENCH_BASELINE')
                    variants = ([('before', baseline)] if baseline else []) + [('after', str(binary))]
                    for label, application in variants:
                        app.terminate()
                        app.wait(timeout=20)
                        app = subprocess.Popen([application], cwd=tmp, env=env, stdout=log, stderr=log)
                        for _ in range(100):
                            if app.poll() is not None: raise RuntimeError('Benchmark API did not start')
                            try:
                                api.call('/ready')
                                break
                            except urllib.error.URLError:
                                time.sleep(.15)
                        output = subprocess.check_output([str(binary), 'bench', 'report', '--base-url', api.origin,
                                     '--scan-id', scan_id, '--iterations', '40', '--warmup', '5'], env=bench_env)
                        (dest / ('api-' + label + '.json')).write_bytes(output)
                    print('PASS report API benchmarks with the same PostgreSQL scan and endpoint', flush=True)
            else:
                print('SKIP native multi-provider test: install Trivy, Grype and Syft', flush=True)
        finally:
            if app.poll() is None:
                app.terminate()
                app.wait(timeout=20)


if __name__ == '__main__':
    main()
