#!/usr/bin/env python3
"""Operator-controlled TLS Secret certificate manager. Python stdlib + kubectl/openssl/age."""
import argparse
import base64
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid

TYPE = 'kubernetes.io/tls'
UTC = dt.timezone.utc

class Stop(Exception):
    pass

def check(condition, why):
    if not condition:
        raise Stop(why)

def run(argv, *, payload=None):
    try:
        p = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise Stop(f'Unable to run {argv[0]}: {type(ex).__name__}') from ex
    if p.returncode:
        # External stderr can contain sensitive details; never print it.
        raise Stop(f'{argv[0]} operation failed (exit {p.returncode}); review permissions and inputs')
    return p.stdout

def k(ctx, *args, payload=None):
    return run(['kubectl', '--context', ctx, '--request-timeout=20s', *args], payload=payload)

def kube_json(ctx, *args):
    try:
        return json.loads(k(ctx, *args, '-o', 'json'))
    except (UnicodeError, ValueError) as ex:
        raise Stop('Invalid Kubernetes JSON response') from ex

def digest(content):
    return hashlib.sha256(content).hexdigest()

def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':')).encode()

def save(path, obj):
    path = Path(path)
    check(not path.is_symlink(), f'Refusing symlink output {path}')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, sort_keys=True)
        f.write('\n')
    path.chmod(0o600)

def csv_write(path, fields, rows):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8', newline='') as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        w.writeheader()
        w.writerows(rows)
    path.chmod(0o600)

def pem_leaves(data):
    chunks = re.findall(rb'-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----', data)
    check(bool(chunks), 'No PEM certificate block detected')
    return [c + b'\n' for c in chunks]

def cert_details(pem):
    chunks = pem_leaves(pem)
    leaf = chunks[0]
    with tempfile.TemporaryDirectory() as tmp:
        certfile = Path(tmp) / 'leaf.pem'
        certfile.write_bytes(leaf)
        out = run(['openssl', 'x509', '-in', str(certfile), '-noout', '-subject', '-issuer', '-startdate', '-enddate', '-ext', 'subjectAltName', '-fingerprint', '-sha256']).decode()
        pub_der = run(['openssl', 'x509', '-in', str(certfile), '-pubkey', '-noout'])
    attrs = {}
    for line in out.splitlines():
        for key in ('subject=', 'issuer=', 'notBefore=', 'notAfter=', 'sha256 Fingerprint=', 'SHA256 Fingerprint='):
            if line.startswith(key):
                attrs[key.split('=')[0].lower()] = line.split('=', 1)[1].strip()
    not_after = dt.datetime.strptime(attrs['notafter'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=UTC)
    not_before = dt.datetime.strptime(attrs['notbefore'], '%b %d %H:%M:%S %Y %Z').replace(tzinfo=UTC)
    sans = sorted(set(re.findall(r'DNS:([^,\s]+)', out)))
    fp = attrs.get('sha256 fingerprint', '').replace(':', '').lower()
    check(len(fp) == 64, 'Missing SHA256 certificate fingerprint')
    return {'subject': attrs.get('subject', ''), 'issuer': attrs.get('issuer', ''),
            'not_before': not_before.isoformat(), 'not_after': not_after.isoformat(),
            'sans': sans, 'fingerprint': fp, 'public_key_hash': digest(pub_der)}

def verify_source(certpath, keypath, cabundle=None):
    check((Path(keypath).stat().st_mode & 0o077) == 0, 'Private key file must not be accessible by group/others (chmod 600)')
    cert, key = Path(certpath).read_bytes(), Path(keypath).read_bytes()
    info = cert_details(cert)
    now = dt.datetime.now(UTC)
    check(dt.datetime.fromisoformat(info['not_before']) <= now, 'Certificate not yet valid')
    check(dt.datetime.fromisoformat(info['not_after']) > now, 'Certificate already expired')
    check(info['sans'], 'Certificate has no DNS SAN')
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / 'leaf.pem').write_bytes(pem_leaves(cert)[0])
        rest = b''.join(pem_leaves(cert)[1:])
        (base / 'intermediate.pem').write_bytes(rest)
        pub = run(['openssl', 'pkey', '-in', str(keypath), '-passin', 'pass:', '-pubout'])
        check(digest(pub) == info['public_key_hash'], 'Certificate/private key mismatch')
        cmd = ['openssl', 'verify', '-purpose', 'sslserver']
        if cabundle:
            cmd += ['-CAfile', str(cabundle)]
        if rest:
            cmd += ['-untrusted', str(base / 'intermediate.pem')]
        cmd += [str(base / 'leaf.pem')]
        run(cmd)
    return cert, key, info

def covers(pattern, hostname):
    p, h = pattern.lower().rstrip('.'), hostname.lower().rstrip('.')
    if p.startswith('*.'):
        return h.count('.') == p.count('.') and h.endswith(p[1:]) and h != p[2:]
    return p == h

def allowlist(filename):
    names = []
    for line in Path(filename).read_text().splitlines():
        val = line.strip()
        if not val or val.startswith('#'):
            continue
        check(bool(re.fullmatch(r'[a-z0-9]([-a-z0-9]*[a-z0-9])?', val)), f'Invalid namespace: {val}')
        check(val not in names, f'Duplicate namespace: {val}')
        names.append(val)
    check(names, 'Empty namespace allowlist')
    return names

def targets(filename, allowed):
    with Path(filename).open(newline='') as f:
        rows = list(csv.DictReader(f))
    check(rows, 'Target CSV is empty')
    result, seen = [], set()
    for row in rows:
        # unpack explicitly to avoid interpreting CSV input as command arguments
        ns = (row.get('namespace') or '').strip()
        name = (row.get('secret_name') or '').strip()
        mode = (row.get('mode') or 'renew').strip()
        reason = (row.get('reason') or '').strip()
        check(ns in allowed, f'Target namespace not allowlisted: {ns}')
        check(bool(re.fullmatch(r'[a-z0-9]([-a-z0-9.]*[a-z0-9])?', name)), 'Invalid secret name')
        check((ns, name) not in seen, f'Duplicate target {ns}/{name}')
        check(mode in ('renew', 'replace-identity'), f'Invalid mode {mode}')
        check(mode != 'replace-identity' or bool(reason), 'Identity replacement requires reason')
        seen.add((ns, name))
        result.append({'namespace': ns, 'secret_name': name, 'mode': mode, 'reason': reason})
    return result

def ingress_references(ctx, ns):
    ingresses = kube_json(ctx, '-n', ns, 'get', 'ingresses.networking.k8s.io')['items']
    mapping = {}
    for ing in ingresses:
        for entry in ing.get('spec', {}).get('tls', []):
            secret = entry.get('secretName', '')
            for host in entry.get('hosts', []):
                mapping.setdefault(secret, []).append({'ingress': ing['metadata']['name'], 'host': host})
    return mapping

def secret(ctx, ns, name):
    obj = kube_json(ctx, '-n', ns, 'get', 'secret', name)
    check(obj.get('type') == TYPE, f'{ns}/{name} is not kubernetes.io/tls')
    check('tls.crt' in obj.get('data', {}) and 'tls.key' in obj.get('data', {}), 'TLS Secret missing crt/key')
    return obj

def old_info(obj):
    try:
        return cert_details(base64.b64decode(obj['data']['tls.crt'], validate=True))
    except (ValueError, KeyError) as ex:
        raise Stop('Malformed existing TLS certificate') from ex

def verify_stored_pair(obj):
    """Validate stored tls.crt versus tls.key; no private-key evidence output."""
    try:
        payload = base64.b64decode(obj['data']['tls.key'], validate=True)
        check(bool(payload), 'Empty stored TLS private key')
        public = run(['openssl', 'pkey', '-inform', 'PEM', '-pubout',
                      '-passin', 'pass:'], payload=payload)
        check(digest(public) == old_info(obj)['public_key_hash'],
              'Stored TLS Secret certificate/private key mismatch')
    except (KeyError, ValueError, TypeError) as ex:
        raise Stop('Stored TLS Secret contains malformed private key') from ex


def cluster_id(ctx):
    ns = kube_json(ctx, 'get', 'namespace', 'kube-system')
    return ns['metadata']['uid']

def identity_match(old, new):
    return old['sans'] == new['sans']

def assess(obj, old, new, refs, mode):
    if any(not any(covers(s, r['host']) for s in new['sans']) for r in refs):
        return 'BLOCKED', 'Replacement does not cover existing Ingress TLS hosts'
    if old['fingerprint'] == new['fingerprint']:
        return 'SKIPPED', 'Certificate fingerprint is unchanged'
    if mode == 'renew' and not identity_match(old, new):
        return 'BLOCKED', 'Historical SAN differs; use replace-identity with reason'
    if obj.get('metadata', {}).get('ownerReferences'):
        return 'BLOCKED', 'Secret has controller ownerReferences'
    if (obj.get('metadata', {}).get('annotations') or {}).get('cert-manager.io/certificate-name'):
        return 'BLOCKED', 'Secret appears managed by cert-manager'
    return 'READY', 'No Ingress TLS references; verify external consumers' if not refs else 'Ready'


def compare_tls_identity(old, new, ingress_refs):
    """Non-secret X.509 comparison. Differences are informational unless assess blocks."""
    san_equal = old['sans'] == new['sans']
    old_subject, new_subject = old.get('subject', ''), new.get('subject', '')
    old_issuer, new_issuer = old.get('issuer', ''), new.get('issuer', '')
    old_key, new_key = old.get('public_key_hash', ''), new.get('public_key_hash', '')
    changed = old['fingerprint'] != new['fingerprint']
    flags = []
    if changed:
        flags.append('CERTIFICATE_FINGERPRINT_CHANGED')
    if not san_equal:
        flags.append('SAN_SET_CHANGED')
    if old_subject and new_subject and old_subject != new_subject:
        flags.append('SUBJECT_CHANGED')
    if old_issuer and new_issuer and old_issuer != new_issuer:
        flags.append('ISSUER_CHANGED')
    if old_key and new_key and old_key != new_key:
        flags.append('PUBLIC_KEY_ROTATED')
    if not ingress_refs:
        flags.append('NO_INGRESS_TLS_REFERENCE')
    return {
        'certificate_change': 'DIFFERENT' if changed else 'SAME',
        'san_match': san_equal,
        'subject_match': old_subject == new_subject if old_subject and new_subject else None,
        'issuer_match': old_issuer == new_issuer if old_issuer and new_issuer else None,
        'public_key_match': old_key == new_key if old_key and new_key else None,
        'old_subject': old_subject,
        'new_subject': new_subject,
        'old_issuer': old_issuer,
        'new_issuer': new_issuer,
        'old_fingerprint': old['fingerprint'],
        'new_fingerprint': new['fingerprint'],
        'old_sans': old['sans'],
        'new_sans': new['sans'],
        'ingress_hosts': sorted({r['host'] for r in ingress_refs}),
        'flags': flags,
        'review_level': 'WARNING' if any(flag in flags for flag in (
            'SAN_SET_CHANGED', 'SUBJECT_CHANGED', 'ISSUER_CHANGED',
            'NO_INGRESS_TLS_REFERENCE')) else 'INFO',
    }


def classify_existing_certificate_families(entries):
    """Detect mixed old certificates that share exactly the same SAN identity."""
    groups = {}
    for e in entries:
        group = tuple(e.get('old_sans', []))
        groups.setdefault(group, set()).add(e['old_fingerprint'])
    for e in entries:
        count = len(groups[tuple(e['old_sans'])])
        comp = e['certificate_comparison']
        comp['existing_fingerprint_variants_same_san'] = count
        if count > 1:
            comp['flags'].append('MIXED_EXISTING_CERTIFICATES_SAME_SAN')
            comp['review_level'] = 'WARNING'



def normalize_old_fp(value):
    if not value:
        return None
    fp = value.lower().replace(':', '').strip()
    check(bool(re.fullmatch(r'[0-9a-f]{64}', fp)), 'Expected-old SHA256 fingerprint must be 64 hex chars')
    return fp


def load_reviewed_holds(path, entries, *, context, cluster_uid, new_fingerprint):
    if not path:
        return {}
    known = {(e['namespace'], e['secret_name']): e for e in entries}
    approved = {}
    with Path(path).open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        check(reader.fieldnames and {'context', 'cluster_uid', 'new_fingerprint', 'namespace',
               'secret_name', 'old_fingerprint', 'reason'}.issubset(reader.fieldnames),
              'Reviewed holds CSV must include context,cluster_uid,new_fingerprint,namespace,secret_name,old_fingerprint,reason')
        for row in reader:
            check((row.get('context') or '').strip() == context and
                  (row.get('cluster_uid') or '').strip() == cluster_uid,
                  'Reviewed exception cluster/context does not match approved run')
            check(normalize_old_fp(row.get('new_fingerprint')) == new_fingerprint,
                  'Reviewed exception replacement certificate fingerprint mismatch')
            key = ((row.get('namespace') or '').strip(), (row.get('secret_name') or '').strip())
            check(key in known and key not in approved, 'Unknown or duplicate reviewed target')
            check(normalize_old_fp(row.get('old_fingerprint')) == known[key]['old_fingerprint'],
                  f'Reviewed fingerprint mismatch for {key[0]}/{key[1]}')
            reason = (row.get('reason') or '').strip()
            check(len(reason) >= 16, 'Reviewed hold requires meaningful written reason')
            scope = (row.get('approval_scope') or 'IDENTITY').strip()
            check(scope in ('IDENTITY', 'STAGED_ONLY', 'SUBJECT_ONLY'), 'Unknown exception approval scope')
            old_subject = (row.get('old_subject') or '').strip()
            new_subject = (row.get('new_subject') or '').strip()
            if scope == 'SUBJECT_ONLY':
                comparison = known[key]['certificate_comparison']
                check(bool(old_subject) and bool(new_subject),
                      f'SUBJECT_ONLY needs exact old and new Subject for {key[0]}/{key[1]}')
                check(old_subject == comparison['old_subject'] and
                      new_subject == comparison['new_subject'] and old_subject != new_subject,
                      f'SUBJECT_ONLY subject evidence mismatch for {key[0]}/{key[1]}')
            approved[key] = {'old_fingerprint': known[key]['old_fingerprint'],
                             'reason': reason, 'approval_scope': scope,
                             'old_subject': old_subject, 'new_subject': new_subject}
    check(approved, 'Reviewed holds CSV empty')
    return approved


def selective_hold(entries, baseline, approved):
    for e in entries:
        e['base_status'], e['base_message'] = e['status'], e['message']
        exception = approved.get((e['namespace'], e['secret_name']))
        e['reviewed_exception'] = exception
        if e['status'] == 'SKIPPED':
            check(not exception, 'Cannot apply reviewed override to already-installed Secret')
            continue
        if e['status'] == 'BLOCKED':
            check(not exception, 'Cannot release a blocked guardrail with reviewed-holds')
            # Per-target guards become non-executing HOLD entries; healthy peers may continue.
            # Reviewed exceptions cannot override an underlying BLOCKED assessment.
            e['status'] = 'HOLD'
            e['message'] = 'Underlying guardrail blocked this target: ' + e['message']
            e['certificate_comparison']['flags'].append('UNDERLYING_GUARDRAIL_HOLD')
            e['certificate_comparison']['review_level'] = 'WARNING'
            continue
        c = e['certificate_comparison']
        mismatches = []
        # A new leaf fingerprint and public-key rotation are normal during renewal.
        # Key-to-certificate matching is independently enforced by verify_source().
        for field, flag in [('san_match','SAN_SET_CHANGED'), ('subject_match','SUBJECT_CHANGED'),
                            ('issuer_match','ISSUER_CHANGED')]:
            if c[field] is False:
                mismatches.append(flag)
        if not e['ingress_refs']:
            mismatches.append('NO_INGRESS_TLS_REFERENCE')
        if baseline and e['old_fingerprint'] != baseline:
            mismatches.append('EXPECTED_OLD_FINGERPRINT_MISMATCH')
        if not baseline and c['existing_fingerprint_variants_same_san'] > 1:
            mismatches.append('AMBIGUOUS_OLD_CERTIFICATE_FAMILY')
        if mismatches:
            c['review_level'] = 'WARNING'
            c['flags'].extend(flag for flag in mismatches if flag not in c['flags'])
            scope = exception.get('approval_scope', 'IDENTITY') if exception else ''
            approved_for_mismatch = (
                scope == 'IDENTITY' or
                (scope == 'STAGED_ONLY' and mismatches == ['NO_INGRESS_TLS_REFERENCE']) or
                (scope == 'SUBJECT_ONLY' and mismatches == ['SUBJECT_CHANGED'] and
                 baseline is not None and e['old_fingerprint'] == baseline and
                 c['san_match'] is True and c['issuer_match'] is True and
                 bool(e['ingress_refs']))
            )
            if approved_for_mismatch:
                c['flags'].append('EXPLICITLY_REVIEWED_EXCEPTION')
                if scope == 'SUBJECT_ONLY':
                    c['flags'].append('SUBJECT_CHANGE_REVIEWED')
                e['message'] = 'Reviewed exception: ' + exception['reason']
            else:
                e['status'] = 'HOLD'
                e['message'] = 'Identity review required: ' + ','.join(mismatches)


def plan_id(plan):
    return digest(canonical({k:v for k,v in plan.items() if k != 'plan_id'}))[:20]

def build_plan(args, crt, info):
    allowed = allowlist(args.namespaces)
    rows = targets(args.targets, allowed)
    check(len(rows) <= 500, 'Maximum 500 targets per run')
    planned = []
    cache = {}
    for row in rows:
        ns, name = row['namespace'], row['secret_name']
        if ns not in cache:
            cache[ns] = ingress_references(args.context, ns)
        try:
            obj = secret(args.context, ns, name)
        except Stop as ex:
            raise Stop(f'Plan cannot read target {ns}/{name}: {ex}. '
                       'Run reconcile and check RBAC/context before retrying') from ex
        old = old_info(obj)
        verify_stored_pair(obj)
        refs = cache[ns].get(name, [])
        state, reason = assess(obj, old, info, refs, row['mode'])
        planned.append({**row, 'status': state, 'message': reason,
                        'old_fingerprint': old['fingerprint'], 'old_sans': old['sans'],
                        'certificate_comparison': compare_tls_identity(old, info, refs),
                        'uid': obj['metadata']['uid'], 'resource_version': obj['metadata']['resourceVersion'],
                        'ingress_refs': refs})
    classify_existing_certificate_families(planned)
    baseline = normalize_old_fp(getattr(args, 'expected_old_fingerprint', None))
    current_cluster_uid = cluster_id(args.context)
    reviewed = load_reviewed_holds(getattr(args, 'reviewed_holds', None), planned,
                                   context=args.context, cluster_uid=current_cluster_uid,
                                   new_fingerprint=info['fingerprint'])
    selective_hold(planned, baseline, reviewed)
    plan = {'selection_policy': {'mode': 'selective-hold', 'expected_old_fingerprint': baseline},
            'schema_version': 1, 'context': args.context, 'cluster_uid': current_cluster_uid,
            'created_utc': dt.datetime.now(UTC).isoformat(), 'source_sha256': digest(crt),
            'new_fingerprint': info['fingerprint'], 'new_sans': info['sans'],
            'allowlist_sha256': digest(Path(args.namespaces).read_bytes()), 'entries': planned}
    plan['plan_id'] = plan_id(plan)
    return plan

def assert_plan(plan, args, crt, info):
    check(plan.get('schema_version') == 1 and plan_id(plan) == plan.get('plan_id'), 'Tampered or unsupported plan')
    check(args.context == plan['context'] and cluster_id(args.context) == plan['cluster_uid'], 'Cluster/context drift')
    check(digest(Path(args.namespaces).read_bytes()) == plan['allowlist_sha256'], 'Allowlist changed')
    check(digest(crt) == plan['source_sha256'] and info['fingerprint'] == plan['new_fingerprint'], 'Source certificate changed')
    created = dt.datetime.fromisoformat(plan['created_utc'])
    check(dt.datetime.now(UTC) - created < dt.timedelta(minutes=60), 'Plan expired; regenerate')
    check(not any(e['status'] == 'BLOCKED' for e in plan['entries']), 'Plan has blocked targets')
    allowed = allowlist(args.namespaces)
    cache = {}
    for e in plan['entries']:
        ns, name = e['namespace'], e['secret_name']
        check(ns in allowed, 'Target outside allowlist')
        if e['status'] in ('HOLD', 'SKIPPED'):
            # No read/write of independent, non-mutating entries during prewrite.
            # Their current state is validated independently by verify/report.
            continue
        if ns not in cache:
            cache[ns] = ingress_references(args.context, ns)
        obj = secret(args.context, ns, name)
        old = old_info(obj)
        verify_stored_pair(obj)
        check(obj['metadata']['uid'] == e['uid'] and obj['metadata']['resourceVersion'] == e['resource_version'] and old['fingerprint'] == e['old_fingerprint'], f'Drift: {ns}/{name}')
        refs = cache[ns].get(name, [])
        check(refs == e.get('ingress_refs', []), f'Ingress TLS reference drift: {ns}/{name}')
        state, _ = assess(obj, old, info, refs, e['mode'])
        if plan.get('selection_policy', {}).get('mode') == 'selective-hold':
            check(state == e['base_status'], f'Guardrail changed: {ns}/{name}')
            check(e['status'] in ('READY', 'HOLD', 'SKIPPED', 'BLOCKED'), 'Invalid selective status')
        else:
            check(state == e['status'], f'Guardrail changed: {ns}/{name}')

def change_secret(ctx, obj, crt, key):
    obj['data']['tls.crt'] = base64.b64encode(crt).decode('ascii')
    obj['data']['tls.key'] = base64.b64encode(key).decode('ascii')
    # Kubernetes replace applies a resourceVersion precondition, including server-side conflict handling.
    k(ctx, 'replace', '-f', '-', payload=canonical(obj))
    return obj

def new_run(root):
    root = Path(root)
    check(not root.is_symlink(), 'Run root may not be a symlink')
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    directory = root / (dt.datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8])
    directory.mkdir(mode=0o700)
    return directory

def backup_age(path, snapshots, recipient):
    check(recipient.startswith('age1'), 'Recipient must be an age public recipient')
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    check(not path.exists(), 'Backup already exists')
    try:
        run(['age', '-r', recipient, '-o', str(path)], payload=canonical(snapshots))
        check(path.exists() and path.stat().st_size > 50, 'Encrypted backup not created')
        path.chmod(0o600)
    except Exception:
        path.unlink(missing_ok=True)
        raise

def read_json(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))

def update_journal(path, obj):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    check(not temp.is_symlink(), 'Unsafe journal path')
    with temp.open('w') as f:
        json.dump(obj, f, sort_keys=True, indent=2)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())
    temp.chmod(0o600)
    os.replace(temp, path)

def secret_type_index(ctx, ns):
    """Names/type only: kubectl receives but does not emit Secret payloads."""
    listing = k(ctx, '-n', ns, 'get', 'secrets', '-o',
                'custom-columns=NAME:.metadata.name,TYPE:.type', '--no-headers')
    result = {}
    for line in listing.decode('utf-8').splitlines():
        fields = line.strip().split()
        check(len(fields) == 2, 'Unexpected Secret metadata listing')
        check(fields[0] not in result, 'Duplicate Secret in metadata listing')
        result[fields[0]] = fields[1]
    return result


def tls_secret_names(ctx, ns):
    return [name for name, kind in secret_type_index(ctx, ns).items() if kind == TYPE]


def cmd_discover(args):
    names = allowlist(args.namespaces)
    rows, refs = [], []
    check(args.warn_days >= 0, 'Negative warning threshold')
    for ns in names:
        mapping = ingress_references(args.context, ns)
        for name in tls_secret_names(args.context, ns):
            try:
                obj = secret(args.context, ns, name)
                info = old_info(obj)
                verify_stored_pair(obj)
                now = dt.datetime.now(UTC)
                before = dt.datetime.fromisoformat(info['not_before'])
                end = dt.datetime.fromisoformat(info['not_after'])
                seconds = (end - now).total_seconds()
                days = int(seconds // 86400)
                state = ('NOT_YET_VALID' if now < before else
                         'EXPIRED' if seconds <= 0 else
                         'EXPIRING' if seconds <= args.warn_days * 86400 else 'VALID')
                details = {'subject': info['subject'], 'issuer': info['issuer'], 'san': ';'.join(info['sans']),
                           'not_before': info['not_before'],
                           'not_after': info['not_after'], 'days_remaining': days,
                           'fingerprint_sha256': info['fingerprint']}
            except (Stop, ValueError, KeyError):
                state = 'INVALID'
                details = dict.fromkeys(('subject', 'issuer', 'san', 'not_before',
                                         'not_after', 'days_remaining', 'fingerprint_sha256'), '')
            rows.append({'namespace': ns, 'secret_name': name, **details,
                         'ingress_count': len(mapping.get(name, [])), 'status': state})
            for r in mapping.get(name, []):
                refs.append({'namespace': ns, 'secret_name': name, **r})
    target = new_run(args.runs_dir)
    csv_write(target / 'inventory.csv', ['namespace', 'secret_name', 'subject', 'issuer',
              'san', 'not_before', 'not_after', 'days_remaining',
              'fingerprint_sha256', 'ingress_count', 'status'], rows)
    csv_write(target / 'ingress-references.csv', ['namespace', 'secret_name', 'ingress', 'host'], refs)
    print(f'DISCOVERY: {len(rows)} TLS Secrets; reports: {target}')

def cmd_reconcile(args):
    """Read-only snapshot of selected targets, for operator review after Secret retirement.

    This deliberately does not change Kubernetes, edit the source targets CSV, or
    let plan/renew silently skip a missing target. A new plan must still be built
    from the explicitly reviewed candidate file.
    """
    allowed = allowlist(args.namespaces)
    selected = targets(args.targets, allowed)
    check(len(selected) <= 500, 'Maximum 500 targets per run')
    uid = cluster_id(args.context)
    check(bool(uid), 'Unable to establish cluster identity')
    # Fetch each approved namespace once; access failures are fatal, NOT "missing".
    inventories, references = {}, {}
    for namespace in sorted({row['namespace'] for row in selected}):
        try:
            found = secret_type_index(args.context, namespace)
            ingresses = ingress_references(args.context, namespace)
            inventory = {}
            for row in (r for r in selected if r['namespace'] == namespace):
                name = row['secret_name']
                if name in found:
                    inventory[name] = (secret(args.context, namespace, name)
                                       if found[name] == TYPE else {'type': found[name]})
        except Stop as ex:
            raise Stop(f'Cannot reconcile namespace {namespace}: {ex}') from ex
        inventories[namespace] = inventory
        references[namespace] = ingresses
    rows, candidate_rows = [], []
    blockers = 0
    for requested in selected:
        namespace, name = requested['namespace'], requested['secret_name']
        obj = inventories[namespace].get(name)
        ingress_hosts = sorted({r['host'] for r in references[namespace].get(name, [])})
        if obj is None:
            if ingress_hosts:
                state, note = 'BLOCKED_MISSING_REFERENCED', 'Secret missing but Ingress still refers to it'
            else:
                state, note = 'MISSING_REVIEW', 'Absent from live Secret list; confirm deletion was authorized'
        elif obj.get('type') != TYPE:
            state, note = 'BLOCKED_TYPE', 'Existing Secret is not kubernetes.io/tls'
        elif not {'tls.crt', 'tls.key'}.issubset(obj.get('data') or {}):
            state, note = 'BLOCKED_MALFORMED', 'TLS Secret lacks tls.crt or tls.key'
        elif obj.get('metadata', {}).get('ownerReferences') or (
                (obj.get('metadata', {}).get('annotations') or {})
                .get('cert-manager.io/certificate-name')):
            state, note = 'BLOCKED_MANAGED', 'Secret is owned by another controller'
        elif not ingress_hosts:
            state, note = 'PRESENT_REVIEW_NO_INGRESS', 'Review other consumers; no Ingress reference is not proof of unused'
        else:
            state, note = 'PRESENT_TLS', 'Present; verify ownership and certificate identity in plan'
        if state.startswith('BLOCKED_'):
            blockers += 1
        if state in ('PRESENT_TLS', 'PRESENT_REVIEW_NO_INGRESS'):
            candidate_rows.append(requested)
        rows.append({
            'namespace': namespace, 'secret_name': name, 'mode': requested['mode'],
            'status': state, 'ingress_hosts': ';'.join(ingress_hosts), 'reason': note
        })
    output = new_run(args.runs_dir)
    csv_write(output / 'target-reconciliation.csv',
              ['namespace', 'secret_name', 'mode', 'status', 'ingress_hosts', 'reason'], rows)
    save(output / 'reconciliation-summary.json', {
        'schema_version': 1, 'context': args.context, 'cluster_uid': uid,
        'generated_utc': dt.datetime.now(UTC).isoformat(),
        'namespaces_sha256': digest(Path(args.namespaces).read_bytes()),
        'targets_sha256': digest(Path(args.targets).read_bytes()),
        'counts': {state: sum(row['status'] == state for row in rows)
                   for state in sorted({row['status'] for row in rows})},
        'requires_operator_review': True,
        'candidate_count': len(candidate_rows),
        'blocker_count': blockers
    })
    if blockers == 0 and candidate_rows:
        csv_write(output / 'targets-reconciled.csv',
                  ['namespace', 'secret_name', 'mode', 'reason'], candidate_rows)
    print(f'RECONCILE: {len(candidate_rows)} present candidate(s), '
          f'{len(rows) - len(candidate_rows) - blockers} missing for review, '
          f'{blockers} blocked; reports: {output}')
    if blockers:
        raise Stop(f'{blockers} unsafe target(s) blocked; review {output}/target-reconciliation.csv')
    check(candidate_rows, f'No live TLS Secret candidates remain; review {output}/target-reconciliation.csv')


def cmd_plan(args):
    cert, key, info = verify_source(args.cert, args.key, args.ca_bundle)
    plan = build_plan(args, cert, info)
    target = new_run(args.runs_dir)
    save(target / 'renewal-plan.json', plan)
    csv_write(target / 'renewal-plan.csv', ['namespace', 'secret_name', 'mode', 'status', 'message', 'old_fingerprint'], plan['entries'])
    compare_rows = []
    for entry in plan['entries']:
        c = entry['certificate_comparison']
        compare_rows.append({
            'namespace': entry['namespace'], 'secret_name': entry['secret_name'],
            'plan_status': entry['status'], 'comparison_level': c['review_level'],
            'certificate_change': c['certificate_change'],
            'san_match': c['san_match'], 'subject_match': c['subject_match'],
            'issuer_match': c['issuer_match'], 'public_key_match': c['public_key_match'],
            'existing_fingerprint_variants_same_san': c['existing_fingerprint_variants_same_san'],
            'old_fingerprint': c['old_fingerprint'], 'new_fingerprint': c['new_fingerprint'],
            'old_subject': c['old_subject'], 'new_subject': c['new_subject'],
            'old_issuer': c['old_issuer'], 'new_issuer': c['new_issuer'],
            'old_sans': ';'.join(c['old_sans']), 'new_sans': ';'.join(c['new_sans']),
            'ingress_hosts': ';'.join(c['ingress_hosts']), 'review_flags': ';'.join(c['flags'])
        })
    csv_write(target / 'certificate-comparison.csv',
              ['namespace', 'secret_name', 'plan_status', 'comparison_level',
               'certificate_change', 'san_match', 'subject_match', 'issuer_match',
               'public_key_match', 'existing_fingerprint_variants_same_san',
               'old_fingerprint', 'new_fingerprint', 'old_subject', 'new_subject',
               'old_issuer', 'new_issuer', 'old_sans', 'new_sans', 'ingress_hosts',
               'review_flags'], compare_rows)
    held = [e for e in plan['entries'] if e['status'] == 'HOLD']
    csv_write(target / 'held-targets.csv',
              ['namespace', 'secret_name', 'old_fingerprint', 'reason', 'flags'],
              [{'namespace': e['namespace'], 'secret_name': e['secret_name'],
                'old_fingerprint': e['old_fingerprint'], 'reason': e['message'],
                'flags': ';'.join(e['certificate_comparison']['flags'])} for e in held])
    counts = {status: sum(e['status'] == status for e in plan['entries'])
              for status in ('READY', 'HOLD', 'SKIPPED', 'BLOCKED')}
    warnings = [e for e in plan['entries']
                if e['certificate_comparison']['review_level'] == 'WARNING']
    print(f'CERTIFICATE COMPARISON: {len(warnings)} target(s) need review; '
          f'all details: {target / "certificate-comparison.csv"}')
    for e in plan['entries']:
        c = e['certificate_comparison']
        print(f'  [{c["review_level"]}] {e["namespace"]}/{e["secret_name"]}: '
              f'plan={e["status"]} cert={c["certificate_change"]} '
              f'SAN_match={c["san_match"]} issuer_match={c["issuer_match"]} '
              f'subject_match={c["subject_match"]} '
              f'existing_cert_variants={c["existing_fingerprint_variants_same_san"]} '
              f'flags={",".join(c["flags"]) or "NONE"}')
    # Keep the plan path on the final line for existing shell parsers.
    print(f'PLAN ID: {plan["plan_id"]} {counts} in {target}')


def verify_approval_trust_anchor(trust):
    """Do not let a user replace the trusted approver identity with their own key."""
    check(trust.is_file() and not trust.is_symlink(), 'Trusted approver key missing or unsafe')
    stat = trust.stat()
    check(stat.st_uid == 0 and stat.st_mode & 0o022 == 0,
          'Trusted approver public key must be root-owned and not group/world writable')


def verify_approval_attestation(plan, args, *, required=False, action='RENEW', target=None):
    """Verify detached operator-approval signature anchored to root-controlled trust key.

    The local PLAN ID is an integrity hash only, never a signature or approver ID.
    A signed JSON attestation binds plan, cluster, endpoint mapping, and expiry.
    """
    record = getattr(args, 'approval_record', None)
    signature = getattr(args, 'approval_signature', None)
    trust_path = getattr(args, 'approval_trust_key', '/etc/kaori/tls-approval-public.pem')
    check(not required or (record and signature),
          'Signed approval record/signature required for multi-target or external TLS renewal')
    if not record and not signature:
        return
    check(bool(record and signature), 'Both approval record and signature are required')
    trust = Path(trust_path)
    verify_approval_trust_anchor(trust)
    approved = read_json(record)
    check(approved.get('schema_version') == 1 and
          approved.get('plan_id') == plan['plan_id'] and
          approved.get('context') == plan['context'] and
          approved.get('cluster_uid') == plan['cluster_uid'] and
          approved.get('action') == action and
          approved.get('target', '') == (target or ''),
          'Signed approval does not match plan, cluster or requested action/target')
    check(len((approved.get('approver') or '').strip()) >= 3 and
          len((approved.get('change_reference') or '').strip()) >= 5,
          'Signed approval must identify approver and change ticket')
    created = dt.datetime.fromisoformat(approved['approved_utc'])
    expires = dt.datetime.fromisoformat(approved['expires_utc'])
    now = dt.datetime.now(UTC)
    check(created.tzinfo and expires.tzinfo and created <= now <= expires and
          expires - created <= dt.timedelta(hours=24),
          'Signed approval is not current or has excessive validity')
    mapping = Path(getattr(args, 'endpoints', '') or '')
    staged_path = getattr(args, 'staged_targets', None)
    check(approved.get('endpoint_sha256') ==
          (digest(mapping.read_bytes()) if getattr(args, 'endpoints', None) else ''),
          'Signed endpoint mapping checksum mismatch')
    check(approved.get('staged_sha256') ==
          (digest(Path(staged_path).read_bytes()) if staged_path else ''),
          'Signed staged-target checksum mismatch')
    check(Path(signature).is_file() and not Path(signature).is_symlink(),
          'Detached approval signature missing or unsafe')
    run(['openssl', 'dgst', '-sha256', '-verify', str(trust), '-signature',
         str(signature), str(record)])


def cmd_renew(args):
    cert, key, info = verify_source(args.cert, args.key, args.ca_bundle)
    plan = read_json(args.plan)
    assert_plan(plan, args, cert, info)
    check(args.approve == plan['plan_id'], 'Explicit --approve PLAN_ID required')
    check(not any(e['mode'] == 'replace-identity' and e['status'] == 'READY' for e in plan['entries']) or args.ack_identity_replacement, 'Identity replacement requires --ack-identity-replacement')
    target = Path(args.plan).resolve().parent
    check(not (target / 'execution-journal.json').exists(), 'Run already executed; use report/rollback')
    ready = [e for e in plan['entries'] if e['status'] == 'READY']
    check(ready, 'No changes required')
    endpoint_path = getattr(args, 'endpoints', None)
    staged_path = getattr(args, 'staged_targets', None)
    check(len(ready) <= 1 or bool(endpoint_path),
          'Multi-Secret renewal requires --endpoints: verify each target before the next write')
    staged = read_staged_targets(staged_path, plan) if staged_path else {}
    endpoints = read_endpoint_targets(endpoint_path, plan, staged) if endpoint_path else []
    requires_sig = len(ready) > 1 or any(
        ep['verification_mode'] == 'EXTERNAL_TERMINATION' for ep in endpoints)
    verify_approval_attestation(plan, args, required=requires_sig)
    deadline_seconds = int(getattr(args, 'wave_timeout_seconds', 90))
    check(10 <= deadline_seconds <= 900, 'Wave verification timeout must be 10..900 seconds')
    # Preflight read access and encrypted full-object backup across all targets.
    snapshots = [secret(args.context, e['namespace'], e['secret_name']) for e in ready]
    # A second pre-mutation snapshot is a new read: bind it to the approved plan.
    for e, obj in zip(ready, snapshots):
        check(obj['metadata']['uid'] == e['uid']
              and obj['metadata']['resourceVersion'] == e['resource_version']
              and old_info(obj)['fingerprint'] == e['old_fingerprint'],
              f'Secret changed after plan preflight: {e["namespace"]}/{e["secret_name"]}')
    backup_age(target / 'backup' / 'secrets.age', snapshots, args.backup_recipient)
    journal = {'plan_id': plan['plan_id'], 'status': 'RUNNING', 'items': []}
    update_journal(target / 'execution-journal.json', journal)
    for e, old in zip(ready, snapshots):
        item = {'namespace': e['namespace'], 'secret_name': e['secret_name'], 'status': 'UNKNOWN'}
        journal['items'].append(item)
        update_journal(target / 'execution-journal.json', journal)
        try:
            # Re-read and verify before mutation; resourceVersion in old snapshot enforces CAS.
            current = secret(args.context, e['namespace'], e['secret_name'])
            check(current['metadata']['resourceVersion'] == old['metadata']['resourceVersion'], 'Concurrent change before update')
            change_secret(args.context, old, cert, key)
            current = secret(args.context, e['namespace'], e['secret_name'])
            check(current['metadata']['uid'] == e['uid'], 'Post-update TLS Secret UID changed')
            check(current.get('type') == TYPE, 'Post-update TLS Secret type drift')
            check(old_info(current)['fingerprint'] == info['fingerprint'],
                  'Post-update certificate fingerprint mismatch')
            # Explicit per-target checkpoint is durable before any subsequent Secret write.
            item.update(status='SECRET_UPDATED_ENDPOINT_UNVERIFIED',
                        post_resource_version=current['metadata']['resourceVersion'],
                        checkpoint_utc=dt.datetime.now(UTC).isoformat(),
                        certificate_fingerprint_sha256=info['fingerprint'],
                        checkpoint_status='SECRET_POST_WRITE_VALIDATED')
            update_journal(target / 'execution-journal.json', journal)
            identity = (e['namespace'], e['secret_name'])
            wave = [ep for ep in endpoints if
                    (ep['namespace'], ep['secret_name']) == identity]
            if identity in staged:
                item['wave_verification'] = 'PENDING_ACTIVATION'
                update_journal(target / 'execution-journal.json', journal)
            elif endpoints:
                check(wave, f'No HTTPS endpoints for wave {identity[0]}/{identity[1]}')
                deadline = time.monotonic() + deadline_seconds
                while True:
                    try:
                        for ep in wave:
                            observed = probe_https_endpoint(
                                ep['hostname'], ep['connect_host'], ep['port'],
                                getattr(args, 'ca_bundle', None))
                            expected = (ep['expected_endpoint_fingerprint']
                                if ep['verification_mode'] == 'EXTERNAL_TERMINATION'
                                else plan['new_fingerprint'])
                            check(observed['fingerprint'] == expected,
                                  f'Wave HTTPS fingerprint mismatch: {ep["hostname"]}')
                        break
                    except Stop as failure:
                        if time.monotonic() >= deadline:
                            raise Stop(f'Wave HTTPS verification failed for {identity[0]}/{identity[1]}: '
                                       f'{failure}. Other READY Secrets have NOT been written') from failure
                        time.sleep(3)
                item['wave_verification'] = (
                    'EXTERNAL_TLS_VERIFIED' if any(
                        ep['verification_mode'] == 'EXTERNAL_TERMINATION'
                        for ep in wave) else 'SECRET_BOUND_ENDPOINT_VERIFIED')
                item['wave_checked_utc'] = dt.datetime.now(UTC).isoformat()
                update_journal(target / 'execution-journal.json', journal)
        except Stop:
            journal['status'] = 'STOPPED'
            update_journal(target / 'execution-journal.json', journal)
            raise
        update_journal(target / 'execution-journal.json', journal)
    journal['status'] = 'COMPLETE_ENDPOINT_UNVERIFIED'
    update_journal(target / 'execution-journal.json', journal)
    print(f'RENEW: {len(ready)} Secret(s) updated; endpoint verification required. {target}')

def cmd_verify(args):
    plan = read_json(args.plan)
    check(args.context == plan['context'] and cluster_id(args.context) == plan['cluster_uid'], 'Cluster mismatch')
    rows = []
    for e in plan['entries']:
        if e['status'] in ('HOLD', 'SKIPPED'):
            try:
                actual = old_info(secret(args.context, e['namespace'], e['secret_name']))
                status = ('HOLD_UNCHANGED_VERIFIED' if e['status'] == 'HOLD'
                          else 'SKIPPED_ALREADY_CURRENT_VERIFIED')
                if actual['fingerprint'] != e['old_fingerprint']:
                    status = e['status'] + '_DRIFT_REVIEW'
            except Stop:
                status = e['status'] + '_DRIFT_REVIEW'
            rows.append({'namespace': e['namespace'], 'secret_name': e['secret_name'],
                         'status': status})
            continue
        actual = old_info(secret(args.context, e['namespace'], e['secret_name']))
        result = ('SECRET_VERIFIED_ENDPOINT_UNVERIFIED' if
                  actual['fingerprint'] == plan['new_fingerprint'] else 'DRIFT')
        rows.append({'namespace': e['namespace'], 'secret_name': e['secret_name'],
                     'status': result})
    print(json.dumps(rows, indent=2))
    check(all(r['status'] != 'DRIFT' for r in rows),
          'READY target certificate drift detected')


def read_staged_targets(path, plan):
    """Explicit operator-reviewed staging exceptions, never inferred from missing Ingress."""
    if not path:
        return {}
    ready = {(e['namespace'], e['secret_name']): e
             for e in plan['entries'] if e['status'] == 'READY'}
    staged = {}
    with Path(path).open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        check(reader.fieldnames is not None and
              {'namespace', 'secret_name', 'reason'}.issubset(set(reader.fieldnames)),
              'Staged CSV must contain namespace,secret_name,reason')
        for row in reader:
            ns = (row.get('namespace') or '').strip()
            name = (row.get('secret_name') or '').strip()
            reason = (row.get('reason') or '').strip()
            target = (ns, name)
            check(target in ready, f'Staged target not READY in plan: {ns}/{name}')
            check(target not in staged, f'Duplicate staged target: {ns}/{name}')
            check(len(reason) >= 12, f'Staged target requires meaningful reason: {ns}/{name}')
            check(not ready[target]['ingress_refs'],
                  f'Staged exception forbidden for Ingress-referenced target: {ns}/{name}')
            staged[target] = reason
    check(staged, 'Staged CSV has no approved targets')
    return staged


def read_endpoint_targets(path, plan, staged=None):
    """Strict CSV allowlist: one SNI endpoint per required Ingress host, per Secret."""
    staged = staged or {}
    entries = {(e['namespace'], e['secret_name']): e for e in plan['entries'] if e['status'] == 'READY'}
    check(entries, 'No READY target needs endpoint verification')
    rows, seen = [], set()
    with Path(path).open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        check(reader.fieldnames is not None and
              {'namespace', 'secret_name', 'hostname'}.issubset(set(reader.fieldnames)),
              'Endpoints CSV must contain namespace,secret_name,hostname')
        for item in reader:
            ns = (item.get('namespace') or '').strip()
            secret_name = (item.get('secret_name') or '').strip()
            host = (item.get('hostname') or '').strip().lower().rstrip('.')
            port_string = (item.get('port') or '').strip() or '443'
            connect_host = (item.get('connect_host') or '').strip() or host
            check((ns, secret_name) in entries, f'Unexpected endpoint target: {ns}/{secret_name}')
            check((ns, secret_name) not in staged,
                  f'Staged target must not be declared as active endpoint: {ns}/{secret_name}')
            check(bool(re.fullmatch(
                r'(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*',
                host)), 'Invalid endpoint SNI hostname')
            check(port_string.isascii() and port_string.isdecimal(), 'Invalid TLS endpoint port')
            port = int(port_string)
            check(1 <= port <= 65535, 'TLS endpoint port out of range')
            check(bool(connect_host) and len(connect_host) <= 253 and
                  not any(c.isspace() for c in connect_host), 'Invalid connect_host')
            mode = (item.get('verification_mode') or 'SECRET_BOUND').strip().upper()
            check(mode in ('SECRET_BOUND', 'EXTERNAL_TERMINATION'),
                  'TLS verification_mode must be SECRET_BOUND or EXTERNAL_TERMINATION')
            external_fp = normalize_old_fp(item.get('expected_endpoint_fingerprint'))
            owner_review = (item.get('review_reference') or '').strip()
            if mode == 'EXTERNAL_TERMINATION':
                check(external_fp and len(owner_review) >= 16,
                      f'External TLS requires expected endpoint SHA256 and owner review: {ns}/{secret_name}')
                check(external_fp != plan['new_fingerprint'],
                      'Identical certificate needs SECRET_BOUND verification')
            else:
                check(not external_fp and not owner_review,
                      'SECRET_BOUND endpoint cannot include external exception metadata')
                check(any(covers(san, host) for san in plan['new_sans']),
                      f'Endpoint hostname outside replacement SAN: {host}')
            identity = (ns, secret_name, host)
            check(identity not in seen, f'Duplicate endpoint: {ns}/{secret_name}/{host}')
            seen.add(identity)
            rows.append({'namespace': ns, 'secret_name': secret_name, 'hostname': host,
                         'port': port, 'connect_host': connect_host,
                         'verification_mode': mode,
                         'expected_endpoint_fingerprint': external_fp,
                         'review_reference': owner_review})
    for identity, entry in entries.items():
        if identity in staged:
            continue
        configured_hosts = {r['host'].lower().rstrip('.') for r in entry['ingress_refs']}
        supplied_hosts = {r['hostname'] for r in rows
                          if (r['namespace'], r['secret_name']) == identity}
        check(supplied_hosts, f'Missing endpoint mapping for {identity[0]}/{identity[1]}')
        check(all(any(covers(configured, observed) for observed in supplied_hosts)
                  for configured in configured_hosts),
              f'Ingress TLS hosts not fully covered for {identity[0]}/{identity[1]}')
    return rows


def probe_https_endpoint(host, connect_host, port, ca_bundle=None, timeout=12):
    """TLS validation uses Python's verified SSL context: CA chain + hostname + SNI."""
    ctx = ssl.create_default_context(cafile=ca_bundle)
    try:
        with socket.create_connection((connect_host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                peer = tls.getpeercert(binary_form=True)
                check(bool(peer), 'TLS endpoint provided no certificate')
                return {'fingerprint': digest(peer), 'tls_version': tls.version()}
    except (OSError, ssl.SSLError) as ex:
        raise Stop(f'TLS endpoint verification failed for {host}:{port}: '
                   f'{type(ex).__name__}') from ex


def _cmd_verify_endpoints(args):
    plan = read_json(args.plan)
    check(plan.get('schema_version') == 1 and plan_id(plan) == plan.get('plan_id'),
          'Plan integrity mismatch')
    check(args.context == plan['context'] and cluster_id(args.context) == plan['cluster_uid'],
          'Cluster mismatch during endpoint verification')
    check(not any(e['status'] == 'BLOCKED' for e in plan['entries']), 'Plan contains BLOCKED target')
    root = Path(args.plan).resolve().parent
    journal_path = root / 'execution-journal.json'
    journal = read_json(journal_path)
    check(journal.get('plan_id') == plan['plan_id'], 'Journal/plan mismatch')
    check(journal.get('status') in (
        'COMPLETE_ENDPOINT_UNVERIFIED', 'COMPLETE_ENDPOINT_VERIFIED',
        'COMPLETE_WITH_STAGED_SECRETS', 'COMPLETE_WITH_HELD_TARGETS',
        'COMPLETE_WITH_HELD_AND_STAGED', 'COMPLETE_WITH_EXTERNAL_TLS'),
        'Execution incomplete or stopped; endpoint cannot be marked verified')
    ready = {(e['namespace'], e['secret_name']): e
             for e in plan['entries'] if e['status'] == 'READY'}
    check(len(ready) == len(journal['items']), 'Journal does not cover every READY target')
    staged = read_staged_targets(getattr(args, 'staged_targets', None), plan)
    journal_index = {}
    for item in journal['items']:
        target = (item['namespace'], item['secret_name'])
        check(target in ready and target not in journal_index, 'Unexpected or duplicated journal target')
        check(item['status'] in ('SECRET_UPDATED_ENDPOINT_UNVERIFIED', 'ENDPOINT_VERIFIED',
                                 'SECRET_VERIFIED_PENDING_ACTIVATION', 'EXTERNAL_TLS_VERIFIED'),
              'Target is not in a verifiable state')
        journal_index[target] = item
    # A re-check must never leave an old ENDPOINT_VERIFIED mark after a new failed probe.
    if journal['status'] in ('COMPLETE_ENDPOINT_VERIFIED', 'COMPLETE_WITH_STAGED_SECRETS',
                              'COMPLETE_WITH_HELD_TARGETS', 'COMPLETE_WITH_HELD_AND_STAGED', 'COMPLETE_WITH_EXTERNAL_TLS'):
        for item in journal['items']:
            item['status'] = 'SECRET_UPDATED_ENDPOINT_UNVERIFIED'
        journal['status'] = 'COMPLETE_ENDPOINT_UNVERIFIED'
        update_journal(journal_path, journal)
    endpoints = read_endpoint_targets(args.endpoints, plan, staged=staged)
    # Re-check stored fingerprint and exact post-write resourceVersion before testing endpoints.
    for target, entry in ready.items():
        obj = secret(args.context, *target)
        check(obj['metadata']['uid'] == entry['uid'] and
              obj['metadata']['resourceVersion'] == journal_index[target].get('post_resource_version'),
              f'Secret changed since renewal: {target[0]}/{target[1]}')
        check(old_info(obj)['fingerprint'] == plan['new_fingerprint'],
              f'Stored TLS certificate drift: {target[0]}/{target[1]}')
        refs_now = ingress_references(args.context, target[0]).get(target[1], [])
        check({r['host'].lower().rstrip('.') for r in refs_now} ==
              {r['host'].lower().rstrip('.') for r in entry['ingress_refs']},
              f'Ingress TLS reference drift: {target[0]}/{target[1]}')
    evidence = []
    for endpoint in endpoints:
        tls = probe_https_endpoint(endpoint['hostname'], endpoint['connect_host'], endpoint['port'],
                                   args.ca_bundle)
        expected = (endpoint['expected_endpoint_fingerprint']
                    if endpoint['verification_mode'] == 'EXTERNAL_TERMINATION'
                    else plan['new_fingerprint'])
        check(tls['fingerprint'] == expected,
              f'HTTPS certificate fingerprint mismatch at {endpoint["hostname"]}:{endpoint["port"]}')
        evidence.append({**endpoint, 'fingerprint_sha256': tls['fingerprint'],
                         'verification_status': ('EXTERNAL_TLS_VERIFIED'
                             if endpoint['verification_mode'] == 'EXTERNAL_TERMINATION'
                             else 'ENDPOINT_VERIFIED'),
                         'tls_version': tls['tls_version'], 'chain_verified': True,
                         'hostname_verified': True, 'sni_verified': True})
    staged_evidence = [
        {'namespace': ns, 'secret_name': name,
         'status': 'SECRET_VERIFIED_PENDING_ACTIVATION', 'reason': reason,
         'fingerprint_sha256': plan['new_fingerprint']}
        for (ns, name), reason in sorted(staged.items())
    ]
    held = [e for e in plan['entries'] if e['status'] == 'HOLD']
    external_targets = {(ep['namespace'], ep['secret_name'])
                        for ep in evidence if ep['verification_status'] == 'EXTERNAL_TLS_VERIFIED'}
    if held and staged:
        final_status = 'COMPLETE_WITH_HELD_AND_STAGED'
    elif held:
        final_status = 'COMPLETE_WITH_HELD_TARGETS'
    elif staged:
        final_status = 'COMPLETE_WITH_STAGED_SECRETS'
    elif external_targets:
        final_status = 'COMPLETE_WITH_EXTERNAL_TLS'
    else:
        final_status = 'COMPLETE_ENDPOINT_VERIFIED'
    record = {'schema_version': 1, 'plan_id': plan['plan_id'],
              'verified_utc': dt.datetime.now(UTC).isoformat(),
              'trust_source': 'approved-ca-bundle' if args.ca_bundle else 'system-trust-store',
              'status': final_status, 'endpoints': evidence, 'staged_secrets': staged_evidence,
              'held_targets': [{'namespace': e['namespace'],
                                'secret_name': e['secret_name'],
                                'reason': e['message']} for e in held]}
    evidence_path = root / 'endpoint-verification.json'
    update_journal(evidence_path, record)
    for item in journal['items']:
        target = (item['namespace'], item['secret_name'])
        item['status'] = ('SECRET_VERIFIED_PENDING_ACTIVATION' if target in staged else
                          'EXTERNAL_TLS_VERIFIED' if target in external_targets else
                          'ENDPOINT_VERIFIED')
    journal['status'] = final_status
    update_journal(journal_path, journal)
    if staged or held:
        print(f'{final_status}: {len(endpoints)} verified HTTPS endpoint(s), '
              f'{len(ready) - len(staged)} endpoint-verified Secret(s), '
              f'{len(staged)} staged Secret(s), '
              f'{len(held)} HELD Secret(s). Evidence: {evidence_path}')
    else:
        print(f'ENDPOINT_VERIFIED: {len(endpoints)} HTTPS endpoint(s); '
              f'{len(ready)} TLS Secret(s). Evidence: {evidence_path}')

def cmd_verify_endpoints(args):
    """Append-only attempt record; retain prior verified evidence before rechecks.

    Latest status can be revoked after a failed probe, but the earlier evidence
    is preserved in a uniquely created immutable attempt directory.
    """
    root = Path(args.plan).resolve().parent
    history = new_run(root / 'verification-history')
    previous_journal = root / 'execution-journal.json'
    previous_evidence = root / 'endpoint-verification.json'
    if previous_journal.exists():
        save(history / 'previous-journal.json', read_json(previous_journal))
    if previous_evidence.exists():
        save(history / 'previous-endpoint-evidence.json', read_json(previous_evidence))
    save(history / 'started.json', {
        'plan_path': str(Path(args.plan).resolve()),
        'started_utc': dt.datetime.now(UTC).isoformat(),
        'status': 'STARTED',
        'endpoint_mapping_sha256': digest(Path(args.endpoints).read_bytes()),
    })
    try:
        _cmd_verify_endpoints(args)
    except (Stop, OSError, ValueError, KeyError) as ex:
        save(history / 'outcome.json', {
            'status': 'FAILED', 'finished_utc': dt.datetime.now(UTC).isoformat(),
            'error_class': type(ex).__name__,
            'note': 'Latest verification not PASS; reconcile journal and endpoint evidence.',
        })
        raise
    else:
        save(history / 'outcome.json', {
            'status': 'SUCCEEDED',
            'finished_utc': dt.datetime.now(UTC).isoformat(),
            'latest_journal_status': read_json(previous_journal)['status'],
        })


def cmd_rollback(args):
    plan = read_json(args.plan)
    check(plan_id(plan) == plan.get('plan_id'), 'Plan altered')
    check(args.context == plan['context'] and cluster_id(args.context) == plan['cluster_uid'], 'Cluster mismatch')
    check(args.approve == plan['plan_id'], 'Explicit --approve PLAN_ID required')
    verify_approval_attestation(plan, args, required=True, action='ROLLBACK')
    target = Path(args.plan).resolve().parent
    journal = read_json(target / 'execution-journal.json')
    check(journal.get('plan_id') == plan['plan_id'], 'Rollback journal/plan mismatch')
    check(journal.get('status') in (
        'COMPLETE_ENDPOINT_UNVERIFIED', 'COMPLETE_ENDPOINT_VERIFIED',
        'COMPLETE_WITH_STAGED_SECRETS', 'COMPLETE_WITH_HELD_TARGETS',
        'COMPLETE_WITH_HELD_AND_STAGED', 'COMPLETE_WITH_EXTERNAL_TLS'),
        'Full rollback requires completed, unrolled journal; reconcile unknown state')
    encrypted = target / 'backup' / 'secrets.age'
    snapshots = json.loads(run(['age', '-d', '-i', args.backup_identity, str(encrypted)]))
    backup_map = {(o['metadata']['namespace'], o['metadata']['name']): o for o in snapshots}
    candidates = []
    for item in journal['items']:
        if item['status'] not in ('SECRET_UPDATED_ENDPOINT_UNVERIFIED', 'ENDPOINT_VERIFIED',
                                 'SECRET_VERIFIED_PENDING_ACTIVATION', 'EXTERNAL_TLS_VERIFIED'):
            # UNKNOWN requires manual inspection; refuse entire rollback.
            raise Stop('Journal has an unknown/failed target; inspect manually before rollback')
        ns, name = item['namespace'], item['secret_name']
        current = secret(args.context, ns, name)
        check(current['metadata']['uid'] == next(
            e['uid'] for e in plan['entries']
            if (e['namespace'], e['secret_name']) == (ns, name)),
            'Rollback Secret UID changed since plan')
        check(current['metadata']['resourceVersion'] == item['post_resource_version'], 'Secret changed since renewal')
        check(old_info(current)['fingerprint'] == plan['new_fingerprint'], 'Certificate drift since renewal')
        original = backup_map[(ns, name)]
        approved = next((e for e in plan['entries'] if e['namespace'] == ns and e['secret_name'] == name), None)
        check(approved is not None and original['metadata']['uid'] == approved['uid']
              and old_info(original)['fingerprint'] == approved['old_fingerprint'],
              'Backup Secret does not match approved plan')
        old = old_info(original)
        check(dt.datetime.fromisoformat(old['not_after']) > dt.datetime.now(UTC), 'Backup certificate already expired')
        candidates.append((item, current, original))
    for item, current, original in candidates:
        # Write-ahead UNKNOWN is durable before any mutation, matching scoped rollback.
        item['status'] = 'ROLLBACK_TARGET_UNKNOWN'
        journal['status'] = 'PARTIAL_ROLLBACK_UNCERTAIN'
        update_journal(target / 'execution-journal.json', journal)
        current['data'] = original['data']
        k(args.context, 'replace', '-f', '-', payload=canonical(current))
        verify = secret(args.context, item['namespace'], item['secret_name'])
        check(verify['metadata']['uid'] == original['metadata']['uid'] and
              old_info(verify)['fingerprint'] == old_info(original)['fingerprint'],
              'Rollback post-write fingerprint/UID mismatch; manual reconciliation required')
        item['status'] = 'ROLLED_BACK_ENDPOINT_UNVERIFIED'
        item['rollback_resource_version'] = verify['metadata']['resourceVersion']
        # Partial rollback remains non-replayable while later items are pending.
        journal['status'] = 'PARTIAL_ROLLBACK_ENDPOINT_UNVERIFIED'
        update_journal(target / 'execution-journal.json', journal)
    journal['status'] = 'ROLLED_BACK_ENDPOINT_UNVERIFIED'
    update_journal(target / 'execution-journal.json', journal)
    print('ROLLBACK: Secret data restored; live TLS endpoint verification still required')

def cmd_rollback_target(args):
    """Restore only one original TLS Secret from the encrypted renewal snapshot."""
    plan = read_json(args.plan)
    check(plan.get('schema_version') == 1 and plan_id(plan) == plan.get('plan_id'),
          'Plan integrity mismatch')
    check(args.context == plan['context'] and cluster_id(args.context) == plan['cluster_uid'],
          'Cluster/context mismatch')
    key = (args.namespace, args.secret)
    label = f'{key[0]}/{key[1]}'
    entries = [e for e in plan['entries'] if
               (e['namespace'], e['secret_name']) == key and e['status'] == 'READY']
    check(len(entries) == 1, f'Target not a unique READY plan entry: {label}')
    entry = entries[0]
    root = Path(args.plan).resolve().parent
    journal_file = root / 'execution-journal.json'
    journal = read_json(journal_file)
    check(journal.get('plan_id') == plan['plan_id'], 'Journal/plan mismatch')
    check(journal.get('status') in (
        'COMPLETE_ENDPOINT_UNVERIFIED', 'COMPLETE_ENDPOINT_VERIFIED',
        'COMPLETE_WITH_STAGED_SECRETS', 'COMPLETE_WITH_HELD_TARGETS',
        'COMPLETE_WITH_HELD_AND_STAGED', 'COMPLETE_WITH_EXTERNAL_TLS'),
        'Journal is not a completed unrolled batch; manual reconciliation required')
    items = [i for i in journal['items'] if (i['namespace'], i['secret_name']) == key]
    check(len(items) == 1, 'Target missing or duplicate in journal')
    item = items[0]
    check(item['status'] in (
        'SECRET_UPDATED_ENDPOINT_UNVERIFIED', 'ENDPOINT_VERIFIED',
        'SECRET_VERIFIED_PENDING_ACTIVATION', 'EXTERNAL_TLS_VERIFIED'),
        'Unsafe target journal status for scoped rollback')
    check(bool(item.get('post_resource_version')), 'Missing post-renewal resourceVersion')
    encrypted = root / 'backup' / 'secrets.age'
    check(encrypted.is_file() and not encrypted.is_symlink(), 'Encrypted backup missing or unsafe')
    snapshots = json.loads(run(['age', '-d', '-i', args.backup_identity, str(encrypted)]))
    check(isinstance(snapshots, list), 'Invalid backup format')
    original_rows = [obj for obj in snapshots if
                     (obj['metadata']['namespace'], obj['metadata']['name']) == key]
    check(len(original_rows) == 1, 'Backup target missing or duplicated')
    original = original_rows[0]
    check(original['metadata']['uid'] == entry['uid'] and original.get('type') == TYPE,
          'Backup UID/type differs from approved target')
    old = old_info(original)
    check(old['fingerprint'] == entry['old_fingerprint'], 'Original fingerprint differs from plan')
    check(dt.datetime.fromisoformat(old['not_after']) > dt.datetime.now(UTC),
          'Original certificate is expired; do not restore')
    current = secret(args.context, *key)
    check(current['metadata']['uid'] == entry['uid'], 'Current Secret UID drift')
    check(current['metadata']['resourceVersion'] == item['post_resource_version'],
          'Current Secret changed since renewal; rollback refused')
    check(old_info(current)['fingerprint'] == plan['new_fingerprint'],
          'Current certificate differs from approved replacement')
    if args.dry_run:
        print(f'ROLLBACK-TARGET DRY-RUN PASS: {label}; original fingerprint '
              f'{old["fingerprint"]}; expires {old["not_after"]}; '
              f'current resourceVersion {item["post_resource_version"]}; no mutation')
        return
    check(args.approve == plan['plan_id'], 'Explicit --approve PLAN_ID required')
    check(args.confirm_target == label, 'Explicit --confirm-target namespace/secret required')
    verify_approval_attestation(plan, args, required=True, action='ROLLBACK_TARGET', target=label)
    # Kubernetes CAS on resourceVersion; never overwrite concurrent writes.
    # Persist uncertainty BEFORE mutation so a crash is not mislabeled success.
    item['status'] = 'ROLLBACK_TARGET_UNKNOWN'
    journal['status'] = 'PARTIAL_ROLLBACK_UNCERTAIN'
    update_journal(journal_file, journal)
    current['data'] = original['data']
    k(args.context, 'replace', '-f', '-', payload=canonical(current))
    actual = secret(args.context, *key)
    check(actual['metadata']['uid'] == entry['uid'] and
          old_info(actual)['fingerprint'] == old['fingerprint'],
          'Rollback post-write fingerprint or UID mismatch; reconcile manually')
    item['status'] = 'ROLLED_BACK_ENDPOINT_UNVERIFIED'
    item['rollback_resource_version'] = actual['metadata']['resourceVersion']
    journal['status'] = 'PARTIAL_ROLLBACK_ENDPOINT_UNVERIFIED'
    update_journal(journal_file, journal)
    print(f'ROLLBACK-TARGET COMPLETE: {label}; original TLS data restored; '
          'other Secrets not changed; recheck HTTPS and application health')


def cmd_report(args):
    plan = read_json(args.plan)
    check(plan_id(plan) == plan.get('plan_id'), 'Plan integrity mismatch')
    j = read_json(Path(args.plan).parent / 'execution-journal.json')
    check(j.get('plan_id') == plan['plan_id'], 'Journal/plan mismatch')
    evidence_path = Path(args.plan).parent / 'endpoint-verification.json'
    final_status = j.get('status')
    terminal_states = ('COMPLETE_ENDPOINT_VERIFIED', 'COMPLETE_WITH_STAGED_SECRETS',
                       'COMPLETE_WITH_HELD_TARGETS', 'COMPLETE_WITH_HELD_AND_STAGED',
                       'COMPLETE_WITH_EXTERNAL_TLS')
    if final_status in terminal_states:
        check(evidence_path.is_file(), 'Verified endpoint evidence missing')
        ev = read_json(evidence_path)
        acceptable_evidence_status = (
            {'COMPLETE_ENDPOINT_VERIFIED', 'ENDPOINT_VERIFIED'}
            if final_status == 'COMPLETE_ENDPOINT_VERIFIED' else {final_status})
        check(ev.get('plan_id') == plan['plan_id'] and
              ev.get('status') in acceptable_evidence_status,
              'Endpoint verification evidence mismatch')
        endpoint_secrets = {(e['namespace'], e['secret_name'])
                            for e in ev.get('endpoints', [])}
        staged_secrets = {(e['namespace'], e['secret_name'])
                          for e in ev.get('staged_secrets', [])}
        actual_verified = {(i['namespace'], i['secret_name'])
                           for i in j['items'] if i['status'] in ('ENDPOINT_VERIFIED','EXTERNAL_TLS_VERIFIED')}
        actual_staged = {(i['namespace'], i['secret_name'])
                         for i in j['items'] if i['status'] == 'SECRET_VERIFIED_PENDING_ACTIVATION'}
        check(actual_verified == endpoint_secrets and actual_staged == staged_secrets and
              not (actual_verified & actual_staged) and
              len(actual_verified) + len(actual_staged) == len(j['items']),
              'Endpoint/staged evidence does not cover final journal targets')
        held = {(e['namespace'], e['secret_name']) for e in plan['entries']
                if e['status'] == 'HOLD'}
        evidence_held = {(e['namespace'], e['secret_name'])
                         for e in ev.get('held_targets', [])}
        check(held == evidence_held, 'Held targets missing or forged in evidence')
        check(bool(actual_staged) == (final_status in
              ('COMPLETE_WITH_STAGED_SECRETS', 'COMPLETE_WITH_HELD_AND_STAGED')),
              'Batch status inconsistent with staged targets')
        check(bool(held) == (final_status in
              ('COMPLETE_WITH_HELD_TARGETS', 'COMPLETE_WITH_HELD_AND_STAGED')),
              'Batch status inconsistent with held targets')
        if final_status == 'COMPLETE_ENDPOINT_VERIFIED':
            check(not any(ep.get('verification_status') == 'EXTERNAL_TLS_VERIFIED'
                          for ep in ev.get('endpoints', [])),
                  'External verification cannot claim complete Secret-bound endpoints')
    rows = [dict(namespace=i['namespace'], secret_name=i['secret_name'], status=i['status'],
                 post_resource_version=i.get('post_resource_version', '')) for i in j['items']]
    recorded = {(i['namespace'], i['secret_name']) for i in j['items']}
    for entry in plan['entries']:
        identity = (entry['namespace'], entry['secret_name'])
        if identity not in recorded and entry['status'] in ('HOLD', 'SKIPPED'):
            rows.append({'namespace': identity[0], 'secret_name': identity[1],
                         'status': ('HOLD_IDENTITY_REVIEW' if entry['status'] == 'HOLD'
                                    else 'SKIPPED_ALREADY_CURRENT'),
                         'post_resource_version': ''})
    path = Path(args.plan).parent / 'renewal-report.csv'
    if path.exists():
        check(not path.is_symlink(), 'Report cannot be a symlink')
        path.unlink()
    csv_write(path, ['namespace','secret_name','status','post_resource_version'], rows)
    print(json.dumps({'run_status': j['status'], 'items': rows, 'report': str(path),
                      'endpoint_evidence': str(evidence_path) if final_status in terminal_states else None}, indent=2))

def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', help='Explicit kubectl context (mandatory for cluster commands)')
    commands = parser.add_subparsers(dest='command', required=True)
    for cmd in ('discover', 'reconcile', 'inspect', 'verify-source', 'plan', 'renew', 'verify', 'verify-endpoints', 'rollback', 'rollback-target', 'report'):
        sp = commands.add_parser(cmd)
        if cmd in ('discover', 'reconcile', 'plan', 'renew'):
            sp.add_argument('--namespaces', required=True)
        if cmd in ('discover', 'reconcile', 'plan'):
            sp.add_argument('--runs-dir', default='./runs')
        if cmd == 'discover':
            sp.add_argument('--warn-days', type=int, default=30)
        if cmd in ('verify-source', 'plan', 'renew'):
            sp.add_argument('--cert', required=True)
            sp.add_argument('--key', required=True)
            sp.add_argument('--ca-bundle')
        if cmd in ('plan', 'reconcile'):
            sp.add_argument('--targets', required=True)
        if cmd == 'plan':
            sp.add_argument('--expected-old-fingerprint', help='Approved existing certificate SHA256 baseline')
            sp.add_argument('--reviewed-holds', help='Exact reviewed exceptions CSV with old_fingerprint and reason')
        if cmd in ('renew', 'verify', 'verify-endpoints', 'rollback', 'rollback-target', 'report'):
            sp.add_argument('--plan', required=True)
        if cmd in ('renew', 'rollback'):
            sp.add_argument('--approve', required=True)
        if cmd == 'renew':
            sp.add_argument('--backup-recipient', required=True)
            sp.add_argument('--ack-identity-replacement', action='store_true')
            sp.add_argument('--endpoints', help='Required for multi-Secret writes: preapproved HTTPS mapping')
            sp.add_argument('--staged-targets', help='Explicit preprovisioned Secret approvals')
            sp.add_argument('--wave-timeout-seconds', type=int, default=90,
                            help='Per-target HTTPS propagation timeout (10..900s); never retries Secret writes')
        if cmd in ('renew', 'rollback', 'rollback-target'):
            sp.add_argument('--approval-record', help='Signed change authorization JSON')
            sp.add_argument('--approval-signature', help='Detached OpenSSL SHA256 signature')
            sp.add_argument('--approval-trust-key', default='/etc/kaori/tls-approval-public.pem',
                            help='Root-owned trusted approver public key PEM')
        if cmd == 'verify-endpoints':
            sp.add_argument('--endpoints', required=True,
                            help='CSV with namespace,secret_name,hostname[,port,connect_host]')
            sp.add_argument('--ca-bundle', help='Approved CA bundle for private PKI endpoints')
            sp.add_argument('--staged-targets', help='Reviewed CSV: namespace,secret_name,reason for intentionally preprovisioned Secrets without Ingress')
        if cmd == 'rollback':
            sp.add_argument('--backup-identity', required=True)
        if cmd == 'rollback-target':
            sp.add_argument('--backup-identity', required=True)
            sp.add_argument('--namespace', required=True)
            sp.add_argument('--secret', required=True)
            sp.add_argument('--dry-run', action='store_true')
            sp.add_argument('--approve', help='Required PLAN ID for actual restore')
            sp.add_argument('--confirm-target', help='Exact namespace/secret required for actual restore')
        if cmd == 'inspect':
            sp.add_argument('--namespace', required=True)
            sp.add_argument('--secret', required=True)
    args = parser.parse_args()
    try:
        if args.command not in ('verify-source', 'report'):
            check(bool(args.context), '--context is required')
        if args.command == 'discover':
            cmd_discover(args)
        elif args.command == 'reconcile':
            cmd_reconcile(args)
        elif args.command == 'inspect':
            o = secret(args.context, args.namespace, args.secret)
            print(json.dumps(old_info(o), indent=2))
        elif args.command == 'verify-source':
            _, _, info = verify_source(args.cert, args.key, args.ca_bundle)
            print(json.dumps(info, indent=2))
        elif args.command == 'plan':
            cmd_plan(args)
        elif args.command == 'renew':
            cmd_renew(args)
        elif args.command == 'verify':
            cmd_verify(args)
        elif args.command == 'verify-endpoints':
            cmd_verify_endpoints(args)
        elif args.command == 'rollback':
            cmd_rollback(args)
        elif args.command == 'rollback-target':
            cmd_rollback_target(args)
        else:
            cmd_report(args)
        return 0
    except (Stop, OSError, ValueError, KeyError, IndexError) as ex:
        print(f'STOP: {ex}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())
