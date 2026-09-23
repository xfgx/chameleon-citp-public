#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
from datetime import datetime, timezone
import zipfile

os.umask(0o077)
RUN = 'vpn-adaptive-20260918-01'
WORK = Path('/root/build') / RUN
BACKUP = Path('/root/backup') / RUN
if socket.gethostname() != 'your-node.example.com':
    raise SystemExit('Wrong release host')


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


log = (WORK / 'results/acceptance-run.log').read_text()
for phase in ['unit', 'race', 'vet', 'build', 'acceptance']:
    if f'PASS phase={phase} host=your-node.example.com\n' not in log:
        raise SystemExit(f'Acceptance phase not complete: {phase}')

packages = {'chameleon/internal/chameleon', 'chameleon/cmd/chamd', 'chameleon/cmd/cham-server'}
checks = {}
for phase in ['targeted', 'unit', 'race']:
    path = WORK / f'results/{phase}.jsonl'
    events = [json.loads(line) for line in path.read_text().splitlines() if line]
    failures = [event for event in events if event.get('Action') == 'fail']
    final = {event['Package']: event['Action'] for event in events if 'Test' not in event and event.get('Action') in ('pass', 'fail', 'skip')}
    expected = packages - {'chameleon/cmd/cham-server'} if phase == 'targeted' else packages
    if failures or set(final) != expected or any(status != 'pass' for status in final.values()):
        raise SystemExit(f'Unexpected test result: {phase}')
    passed = [event for event in events if event.get('Action') == 'pass' and 'Test' in event]
    checks[phase] = {
        'packages': final,
        'top_level_tests_and_fuzz_seeds': sum('/' not in event['Test'] for event in passed),
        'passed_subtests': sum('/' in event['Test'] for event in passed),
        'log_path': str(path),
        'log_sha256': digest(path),
    }

source_hashes = {}
for line in (WORK / 'results/source-after.sha256').read_text().splitlines():
    checksum, relative = line.split('  ', 1)
    path = WORK / 'src' / relative
    if path.is_symlink() or not path.resolve().is_relative_to((WORK / 'src').resolve()) or digest(path) != checksum:
        raise SystemExit(f'Tested source changed: {relative}')
    source_hashes[relative] = checksum
if len(source_hashes) != 19:
    raise SystemExit('Unexpected source manifest size')

original_hashes = {}
with tarfile.open(BACKUP / 'source-before.tar.gz', 'r:gz') as archive:
    names = set(archive.getnames())
    for relative in source_hashes:
        if relative not in names:
            original_hashes[relative] = None
            continue
        member = archive.getmember(relative)
        if not member.isfile():
            raise SystemExit(f'Unexpected backup member: {relative}')
        with archive.extractfile(member) as source:
            original_hashes[relative] = hashlib.file_digest(source, 'sha256').hexdigest()

artifacts = {}
for line in (WORK / 'artifacts/SHA256SUMS').read_text().splitlines():
    checksum, name = line.split('  ', 1)
    path = WORK / 'artifacts' / name
    if '/' in name or path.is_symlink() or digest(path) != checksum:
        raise SystemExit(f'Artifact checksum mismatch: {name}')
    artifacts[name] = {'sha256': checksum, 'bytes': path.stat().st_size}
if len(artifacts) != 6:
    raise SystemExit('Unexpected artifact count')

services = subprocess.check_output(['systemctl', 'show', 'cham-server', 'ks-vpn-node', 'chaossync-server', '-p', 'Id', '-p', 'MainPID', '-p', 'NRestarts', '-p', 'ActiveState'], text=True)
before = (WORK / 'results/services-before.txt').read_text()
if sorted(services.splitlines()) != sorted(before.splitlines()):
    raise SystemExit('Production service state changed; inspect before release')

release = WORK / 'release'
release.mkdir(mode=0o700)
for relative in source_hashes:
    destination = release / 'src' / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(WORK / 'src' / relative, destination)
(release / 'artifacts').mkdir()
for name in [*artifacts, 'SHA256SUMS']:
    shutil.copy2(WORK / 'artifacts' / name, release / 'artifacts' / name)

report = {
    'release': RUN,
    'created_at': datetime.now(timezone.utc).isoformat(),
    'build_host': socket.gethostname(),
    'go': subprocess.check_output(['/usr/local/go/bin/go', 'version'], text=True).strip(),
    'checks': checks,
    'vet': {'linux': 'pass', 'windows_amd64': 'pass'},
    'artifacts': artifacts,
    'sources_sha256': source_hashes,
    'original_sources_sha256': original_hashes,
    'runtime_deployed': False,
    'production_service_state_unchanged': True,
    'resolution_auth_version': 2,
    'requires_coordinated_update': 'Clients and every CHAM server/upstream hop; v2 deliberately rejects legacy DNS MACs.',
    'implementation_scope': {
        'strategy_learning': 'chamd records payload-bearing session outcomes, not handshake success or exogenous labels; candidate-specific decayed estimates affect ranking with enough support.',
        'cover_traffic': 'Live Stream.Write payload and pending data gate the shared shaper/padding budget.',
        'citp_deadlines_latest_only': 'Implemented and tested in SendCITPObject. Current application traffic has no production callers of this API; no claim of deployment to ordinary UDP workloads.',
        'dns_binding': 'Canonical length-delimited v2 MAC, per-session issuance registry, and no silent fallback on auth, timeout or policy errors. Authenticated explicit cascade delegation is retained.',
    },
    'not_verified': ['Real user-side DPI/TSPU A/B effectiveness', 'Windows execution', 'Android rebuild', 'External cryptographic audit'],
    'excluded_external_test': {'test': 'TestE2EUDPRelay', 'reason': 'Hardcoded remote endpoint; isolated baseline failed with network unreachable. Local integration and cascade tests ran.'},
    'test_environment': {'private_network': True, 'cpu_quota': '100%', 'memory_max': '1100M', 'gomaxprocs': 2},
    'backup': {'directory': str(BACKUP), 'source_sha256': digest(BACKUP / 'source-before.tar.gz'), 'runtime_sha256': digest(BACKUP / 'runtime-before.tar.gz')},
}
(release / 'release.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
archive_path = WORK / f'{RUN}.zip'
with zipfile.ZipFile(archive_path, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
    for path in sorted(release.rglob('*')):
        if path.is_file():
            archive.write(path, str(path.relative_to(release)))
with zipfile.ZipFile(archive_path) as archive:
    if archive.testzip() is not None:
        raise SystemExit('Release archive integrity check failed')
(WORK / f'{RUN}.zip.sha256').write_text(f'{digest(archive_path)}  {archive_path.name}\n')
print(json.dumps({'release_directory': str(release), 'archive': str(archive_path), 'archive_sha256': digest(archive_path), 'checks': checks, 'artifacts': artifacts, 'runtime_deployed': False}, ensure_ascii=False, indent=2))
