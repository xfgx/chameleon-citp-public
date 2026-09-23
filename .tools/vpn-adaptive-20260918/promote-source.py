#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import tarfile
import tempfile

os.umask(0o077)
parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True)
parser.add_argument('--release', required=True)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
root = Path(args.root).resolve()
release = Path(args.release).resolve()
run = 'vpn-adaptive-20260918-01'
if root == Path('/root/vpn'):
    if socket.gethostname() != 'your-node.example.com':
        raise SystemExit('Wrong RU source host')
    backup = Path('/root/backup') / run / 'source-promotion'
elif root == Path('/files/VPN'):
    backup = root / '.tools/vpn-adaptive-20260918/source-promotion'
else:
    raise SystemExit('Unexpected source root')
if not backup.parent.is_dir():
    raise SystemExit('Backup parent missing')

report = json.loads((release / 'release.json').read_text())
if report.get('release') != run or report.get('runtime_deployed') is not False or report.get('resolution_auth_version') != 2:
    raise SystemExit('Unexpected release metadata')
expected = report['sources_sha256']
original_hashes = report['original_sources_sha256']
if len(expected) != 19 or set(expected) != set(original_hashes):
    raise SystemExit('Unexpected source manifest')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def atomic_write(path, data, mode):
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.vpn-update-', delete=False) as temporary:
        name = temporary.name
        try:
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
            os.fchmod(temporary.fileno(), mode)
        except BaseException:
            os.unlink(name)
            raise
    try:
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


original = {}
replacements = {}
modes = {}
for relative, checksum in expected.items():
    target = root / relative
    staged = release / 'src' / relative
    if target.is_symlink() or not target.resolve().is_relative_to(root) or not target.parent.is_dir():
        raise SystemExit(f'Unsafe target path: {relative}')
    if staged.is_symlink() or not staged.resolve().is_relative_to(release):
        raise SystemExit(f'Unsafe release path: {relative}')
    replacements[relative] = staged.read_bytes()
    if digest(replacements[relative]) != checksum:
        raise SystemExit(f'Release source checksum mismatch: {relative}')
    original[relative] = target.read_bytes() if target.exists() else None
    actual = digest(original[relative]) if original[relative] is not None else None
    if actual != original_hashes[relative]:
        raise SystemExit(f'Canonical source changed since baseline: {relative}')
    modes[relative] = target.stat().st_mode & 0o777 if target.exists() else 0o644

agent_path = root / 'agent.md'
if agent_path.is_symlink():
    raise SystemExit('Unexpected handoff symlink')
original['agent.md'] = agent_path.read_bytes()
modes['agent.md'] = agent_path.stat().st_mode & 0o777
marker = '### 2026-09-18 — adaptive session outcomes, bounded cover traffic, DNS authentication v2'
if marker in original['agent.md'].decode():
    raise SystemExit('Handoff entry already exists')
counts = report['checks']
entry = f'''

{marker}

- Source release: `{run}`. Built only on RU (`{report['go']}`); runtime binaries/services, routes and firewall were not changed.
- chamd now captures actual session flavor and pre-trial path context, learns only payload-bearing outcomes with a 45-second survival horizon, and keeps a bounded private outcome history. Handshakes, idle sessions, local cancellation and exogenous observations are not survival labels. The exposure budget is enforced before mutation, including legacy flavor rotation; zero/invalid budgets fail closed.
- Live stream traffic now gates shared shaper/PackMorph padding with a bounded budget and pending-payload priority. Expiry rechecks and latest-only coalescing are implemented on the CITP object send API; current application workloads do not yet call that API, so this is NOT proof of end-to-end deadline-aware UDP delivery.
- DNS v2 uses domain-separated, length-delimited authentication plus a bounded per-session server-issuance registry. Signature, resolution and policy errors do not silently downgrade. Explicit authenticated upstream delegation remains for cascades.
- Actual RU results: targeted {counts['targeted']['top_level_tests_and_fuzz_seeds']} top-level tests/fuzz targets, unit {counts['unit']['top_level_tests_and_fuzz_seeds']}, race {counts['race']['top_level_tests_and_fuzz_seeds']}; all selected packages passed. Linux and Windows vet passed. Six Linux/Windows artifacts and SHA-256 manifest were produced. Final logs and metadata: `/root/build/{run}/results/` and `/root/build/{run}/release/release.json`.
- Tests were isolated with PrivateNetwork=yes. Only the hardcoded remote `TestE2EUDPRelay` was excluded (its unchanged baseline cannot reach the network in that namespace). Local transport, UDP and cascade integration tests were included. Chain loopback fixtures now explicitly allow private resolution in tests only; production defaults remain restrictive.
- DNS v2 is intentionally incompatible with old MACs: coordinate updates across clients and every CHAM upstream/exit hop. DO NOT replace live binaries piecemeal. Windows runtime, Android rebuild, external audit and real subscriber-side DPI/TSPU A/B effectiveness have NOT been verified.
- RU source/runtime backups remain in `/root/backup/{run}/`; this promotion also creates a separate source-only rollback archive. Preserve all earlier backups and historical log entries.
'''
replacements['agent.md'] = original['agent.md'] + entry.encode()
replacement_hashes = {name: digest(data) for name, data in replacements.items()}
if args.check:
    if backup.exists():
        raise SystemExit('Promotion backup already exists; refusing a second promotion')
    print(json.dumps({'root': str(root), 'verified_sources': len(expected), 'canonical_sources_unchanged': True, 'backup_destination': str(backup), 'check_only': True}, indent=2))
    raise SystemExit(0)
backup.mkdir(mode=0o700)
archive_path = backup / 'source-before-promotion.tar.gz'
with tarfile.open(archive_path, 'x:gz') as archive:
    for relative, data in original.items():
        if data is not None:
            archive.add(root / relative, arcname=relative, recursive=False)
with tarfile.open(archive_path, 'r:gz') as archive:
    for relative, data in original.items():
        if data is not None:
            with archive.extractfile(relative) as source:
                if digest(source.read()) != digest(data):
                    raise SystemExit(f'Backup validation failed: {relative}')
(backup / 'rollback.json').write_text(json.dumps({'root': str(root), 'created_files': [name for name, data in original.items() if data is None], 'archive_sha256': digest(archive_path.read_bytes()), 'original_sources_sha256': original_hashes, 'original_files_sha256': {name: digest(data) if data is not None else None for name, data in original.items()}, 'promoted_files_sha256': replacement_hashes, 'file_modes': modes}, indent=2) + '\n')

touched = []
try:
    for relative, data in replacements.items():
        target = root / relative
        current = target.read_bytes() if target.exists() else None
        if current != original[relative]:
            raise RuntimeError(f'Concurrent source edit detected: {relative}')
        atomic_write(target, data, modes[relative])
        touched.append(relative)
    for relative, checksum in replacement_hashes.items():
        if digest((root / relative).read_bytes()) != checksum:
            raise RuntimeError(f'Post-promotion checksum mismatch: {relative}')
except BaseException:
    for relative in reversed(touched):
        if original[relative] is None:
            (root / relative).unlink()
        else:
            atomic_write(root / relative, original[relative], modes[relative])
    raise
print(json.dumps({'root': str(root), 'promoted_sources': len(expected), 'backup': str(archive_path), 'agent_log_appended': True, 'runtime_deployed': False}, indent=2))
