"""Sequential account runner. Public output is allowlisted; details are encrypted."""
import contextlib
import datetime as dt
import hashlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

from common import GitHub, KEY_RE, TZ, WORKFLOW, collect_history, cron, day, parse_time, stamp

PLANS = {'off': None, 'plan100': (100, 10), 'plan200': (200, 30), 'plan500': (500, 100)}
EXCHANGE_REJECTION_CODES = {-1, -2}
ROOT = Path('gqd-output')


def write_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(obj, ensure_ascii=False, separators=(',', ':')), encoding='utf-8')
    temp.replace(path)


def read_config():
    config = json.loads(Path('.github/glados-accounts.json').read_text(encoding='utf-8'))
    if config.get('schemaVersion') != 2 or config.get('timezone') != 'Asia/Taipei':
        raise ValueError('incompatible configuration')
    accounts = config.get('accounts')
    if not isinstance(accounts, list) or len(accounts) > 100:
        raise ValueError('invalid accounts')
    seen = set()
    for account in accounts:
        key = account.get('accountKey', '')
        if not KEY_RE.fullmatch(key) or key in seen or account.get('exchangePlan') not in PLANS or not isinstance(account.get('enabled'), bool):
            raise ValueError('invalid account configuration')
        times = account.get('times')
        if not isinstance(times, list) or not 1 <= len(times) <= 6:
            raise ValueError('invalid schedule')
        for value in times:
            cron(value)
        seen.add(key)
    return config


def select_accounts(config, event, operation, target, schedule):
    if operation not in ('checkin', 'status') or target and not KEY_RE.fullmatch(target):
        raise ValueError('invalid manual operation')
    if target and not any(a['accountKey'] == target for a in config['accounts']):
        raise ValueError('unknown account')
    selected = []
    for account in config['accounts']:
        if target and account['accountKey'] != target:
            continue
        if operation == 'checkin' and not account['enabled']:
            continue
        if event == 'schedule' and schedule not in {cron(t) for t in account['times']}:
            continue
        selected.append({'account': account['accountKey']})
    return selected


def prepare():
    config = read_config()
    event = os.environ.get('GITHUB_EVENT_NAME', '')
    operation = os.environ.get('GQD_OPERATION', '') or 'checkin'
    if event == 'schedule':
        operation = 'checkin'
    selected = select_accounts(config, event, operation, os.environ.get('GQD_TARGET_ACCOUNT', ''), os.environ.get('GQD_SCHEDULE', ''))
    history = collect_history(GitHub(), account_keys=[x['account'] for x in selected]) if selected else []
    write_json('gqd-history/history.json', history)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('matrix=' + json.dumps({'include': selected or [{'account': 'NONE'}]}) + '\n')
        output.write('has_accounts=' + ('true' if selected else 'false') + '\n')
        output.write('operation=' + operation + '\n')
    print('QUICK_DEPLOY_SELECTION=' + json.dumps({'accountCount': len(selected), 'operation': operation, 'event': event}))


def credential(raw):
    parsed = json.loads(raw)
    cookie = parsed.get('cookie', '')
    ua = parsed.get('userAgent', '')
    if not isinstance(cookie, str) or not isinstance(ua, str) or not 1 <= len(cookie) <= 32768 or not 1 <= len(ua) <= 2048:
        raise ValueError('invalid credentials')
    if parsed.get('origin', 'https://glados.cloud') != 'https://glados.cloud' or not all(32 <= ord(c) <= 126 for c in cookie + ua):
        raise ValueError('invalid credential origin')
    pairs = {}
    for item in cookie.split(';'):
        key, separator, value = item.strip().partition('=')
        if separator and key in ('gld:sess', 'gld:sess.sig'):
            if key in pairs:
                raise ValueError('duplicate session')
            pairs[key] = value
    if not pairs.get('gld:sess') or not pairs.get('gld:sess.sig'):
        raise ValueError('incomplete session')
    revision = hashlib.sha256((cookie + '\n' + ua).encode('ascii')).hexdigest()
    return cookie, ua, revision


def decide(history, account_key, revision, operation, today):
    all_records = [x for x in history if x.get('accountKey') == account_key]
    all_records.sort(key=lambda x: str(x.get('_artifactCreatedAt', x.get('observedAt', ''))), reverse=True)
    records = [x for x in all_records if x.get('businessDate') == today or x.get('checkinBusinessDate') == today]
    records.sort(key=lambda x: str(x.get('_artifactCreatedAt', x.get('observedAt', ''))), reverse=True)
    finals = [x for x in records if x.get('phase') == 'final']
    confirmed = next((x for x in finals if x.get('checkinConfirmed') is True and x.get('checkinBusinessDate') == today), None)
    recent_finals = [x for x in all_records if x.get('phase') == 'final']
    exchange = next((x for x in recent_finals if x.get('exchangeUncertain') is True
                     or x.get('exchangeConfirmedAt') and x.get('businessDate') == today), None)
    final_ids = {(str(x.get('runId')), str(x.get('runAttempt', 1))) for x in recent_finals}
    orphaned = [x for x in all_records if x.get('phase') == 'intent' and x.get('sideEffects') is True
                and (str(x.get('runId')), str(x.get('runAttempt', 1))) not in final_ids]
    # A missing final receipt may hide an accepted exchange. Its uncertainty is
    # account-wide and survives midnight or a renewed login; only check-in is daily.
    if orphaned:
        exchange = {**(exchange or {}), 'exchangeUncertain': True}
    unknown = next((x for x in records if x.get('phase') == 'intent' and x.get('credentialRevision') == revision and x.get('sideEffects') is True
                    and (str(x.get('runId')), str(x.get('runAttempt', 1))) not in final_ids), None)
    unknown = unknown or next((x for x in finals if x.get('credentialRevision') == revision and x.get('checkinUncertain') is True), None)
    latest_identity = next((x for x in recent_finals if x.get('credentialRevision') == revision and isinstance(x.get('authenticationRequired'), bool)), None)
    latest_auth = latest_identity if latest_identity and latest_identity['authenticationRequired'] else None
    if operation == 'status':
        return {'checkin': False, 'blocked': False, 'confirmed': confirmed, 'exchange': exchange, 'uncertain': bool(unknown), 'priorAuthenticationRequired': bool(latest_auth)}
    return {'checkin': not confirmed and not latest_auth and not unknown,
            'blocked': bool(latest_auth or unknown), 'reason': 'authentication' if latest_auth else 'previous_uncertain' if unknown else '',
            'confirmed': confirmed, 'exchange': exchange, 'uncertain': bool(unknown), 'priorAuthenticationRequired': bool(latest_auth)}


def number(value):
    try:
        value = float(value)
        return value if math.isfinite(value) and 0 <= value <= 1e9 else None
    except (ValueError, TypeError, OverflowError):
        return None


def rejected(response, status):
    if status in (401, 403):
        return True
    if not isinstance(response, dict):
        return False
    message = str(response.get('message', '')).lower()
    return response.get('code') == -2 or response.get('reason') == 'device-mismatch' or any(x in message for x in ('automated check-in detected', '没有权限', 'unauthorized', 'permission', 'sign in again'))


def preflight():
    if int(os.environ.get('GITHUB_RUN_ATTEMPT', '1')) != 1:
        raise ValueError('reruns are not safe for side effects; create a new idempotent manual operation instead')
    config = read_config()
    key = os.environ.get('GQD_ACCOUNT_KEY', '')
    if not KEY_RE.fullmatch(key) or not any(a['accountKey'] == key for a in config['accounts']):
        raise ValueError('unknown account')
    _, _, revision = credential(os.environ.get('GQD_ACCOUNT_JSON', ''))
    history = json.loads(Path('gqd-history/history.json').read_text(encoding='utf-8'))
    operation = os.environ.get('GQD_OPERATION', 'checkin')
    decision = decide(history, key, revision, operation, day())
    intent = {'schemaVersion': 2, 'phase': 'intent', 'repository': os.environ['GITHUB_REPOSITORY'], 'runId': os.environ['GITHUB_RUN_ID'],
              'runAttempt': os.environ.get('GITHUB_RUN_ATTEMPT', '1'), 'accountKey': key, 'businessDate': day(),
              'observedAt': stamp(), 'credentialRevision': revision, 'operation': operation, 'sideEffects': operation == 'checkin' and not decision['blocked']}
    write_json('gqd-intent/receipt.json', intent)
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        output.write('side_effects=' + ('true' if intent['sideEffects'] else 'false') + '\n')


def run_account(client, upstream, previous, operation, settings, receipt, status_probe):
    receipt.update(phase='final', stateVersion=1, outcome='unverified', checkinConfirmed=False, authenticationRequired=False, exchange='not_run')
    if previous.get('uncertain'):
        receipt['checkinUncertain'] = True
    if previous['confirmed']:
        saved = previous['confirmed']
        receipt.update(checkinConfirmed=True, checkinBusinessDate=saved['checkinBusinessDate'], checkinConfirmedAt=saved.get('checkinConfirmedAt'),
                       pointsAdded=saved.get('pointsAdded'), outcome='already_checked')
    if previous['exchange']:
        for name in ('exchangeConfirmedAt', 'exchangeUncertain'):
            if name in previous['exchange']:
                receipt[name] = previous['exchange'][name]
    details = {'email': None, 'points': None, 'leftDays': None, 'exchangePlans': [], 'statusFresh': False}
    if previous.get('priorAuthenticationRequired'):
        receipt['authenticationRequired'] = True
    if previous['blocked'] and operation != 'status':
        receipt.update(outcome='authentication_required' if previous['reason'] == 'authentication' else 'unverified',
                       authenticationRequired=previous['reason'] == 'authentication', errorKind=previous['reason'])
        return details
    status_probe['status'] = None
    raw_status = client.req('GET', '/api/user/status')
    if rejected(raw_status, status_probe['status']):
        receipt.update(authenticationRequired=True, outcome='authentication_required', errorKind='authentication')
        return details
    if isinstance(raw_status, dict) and isinstance(raw_status.get('data'), dict):
        data = raw_status['data']
        email = data.get('email')
        if isinstance(email, str) and len(email) <= 320 and re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            details['email'] = email
        details['leftDays'] = number(data.get('leftDays'))
        details['statusFresh'] = True
        receipt['authenticationRequired'] = False
    status_probe['status'] = None
    points_response = client.req('GET', '/api/user/points')
    if rejected(points_response, status_probe['status']):
        receipt.update(authenticationRequired=True, outcome='authentication_required', errorKind='authentication')
        return details
    before = number(points_response.get('points')) if isinstance(points_response, dict) else None
    details['points'] = before
    if before is not None:
        receipt['authenticationRequired'] = False
    if isinstance(points_response, dict) and isinstance(points_response.get('plans'), dict):
        for plan_key, data in points_response['plans'].items():
            if plan_key in PLANS and isinstance(data, dict):
                details['exchangePlans'].append({'id': plan_key, 'points': number(data.get('points')), 'days': number(data.get('days'))})
    if operation == 'status':
        receipt['outcome'] = 'already_checked' if receipt['checkinConfirmed'] else 'status_only'
        receipt['exchange'] = 'status_only'
        if not details['statusFresh'] and details['points'] is None:
            receipt.update(outcome='unverified', errorKind='request_failed')
        return details
    if previous['checkin']:
        status_probe['status'] = None
        receipt['checkinAttemptedAt'] = stamp()
        response = client.checkin()
        if rejected(response, status_probe['status']):
            receipt.update(authenticationRequired=True, outcome='authentication_required', errorKind='authentication')
            return details
        if not upstream.is_normal_checkin_result(response):
            receipt.update(outcome='failed' if status_probe['status'] == 429 else 'unverified',
                           errorKind='rate_limited' if status_probe['status'] == 429 else 'request_failed', checkinUncertain=status_probe['status'] != 429)
            return details
        confirmed_at = stamp()
        confirmed_day = day()
        receipt.update(checkinConfirmed=True, checkinBusinessDate=confirmed_day, checkinConfirmedAt=confirmed_at, outcome='checked')
        message = str(response.get('message', '')).lower() if isinstance(response, dict) else ''
        if any(x in message for x in ('repeats', 'already', 'try tomorrow')):
            receipt['outcome'] = 'already_checked'
        status_probe['status'] = None
        after_response = client.req('GET', '/api/user/points')
        after = number(after_response.get('points')) if isinstance(after_response, dict) else None
        details['points'] = after
        if before is not None and after is not None and 0 <= after - before <= 1e6:
            receipt['pointsAdded'] = after - before
    selected = settings['exchangePlan']
    if selected == 'off':
        receipt['exchange'] = 'disabled'
    elif previous.get('uncertain') or receipt.get('exchangeUncertain'):
        receipt['exchange'] = 'uncertain'
    elif receipt.get('exchangeConfirmedAt'):
        receipt['exchange'] = 'already_completed'
    elif not receipt['checkinConfirmed'] or receipt.get('checkinBusinessDate') != day():
        receipt['exchange'] = 'not_run'
    elif details['points'] is None:
        receipt['exchange'] = 'points_unavailable'
    elif details['points'] < PLANS[selected][0]:
        receipt['exchange'] = 'not_needed'
    else:
        receipt['exchangeAttemptedAt'] = stamp()
        receipt['exchangeUncertain'] = True
        # Persist the uncertain state locally first. The separate preflight artifact
        # protects the next run even if the runner disappears before final upload.
        write_json(ROOT / 'receipt.json', {k: v for k, v in receipt.items() if k != 'pointsAdded'})
        response = client.exchange(selected)
        code = response.get('code') if isinstance(response, dict) else None
        if type(code) is int and code == 0:
            receipt.update(exchange='completed', exchangeConfirmedAt=stamp(), exchangeUncertain=False)
            fresh = client.req('GET', '/api/user/points')
            details['points'] = number(fresh.get('points')) if isinstance(fresh, dict) else None
            fresh = client.req('GET', '/api/user/status')
            details['leftDays'] = number(fresh.get('data', {}).get('leftDays')) if isinstance(fresh, dict) and isinstance(fresh.get('data'), dict) else None
        elif type(code) is int and code in EXCHANGE_REJECTION_CODES:
            receipt.update(exchange='failed', exchangeUncertain=False, errorKind='exchange')
        else:
            receipt.update(exchange='uncertain', errorKind='exchange')
    return details


def main_run():
    config = read_config()
    key = os.environ['GQD_ACCOUNT_KEY']
    settings = next(a for a in config['accounts'] if a['accountKey'] == key)
    intent = json.loads(Path('gqd-intent/receipt.json').read_text(encoding='utf-8'))
    if intent.get('runId') != os.environ['GITHUB_RUN_ID'] or intent.get('accountKey') != key:
        raise ValueError('intent mismatch')
    receipt = dict(intent)
    receipt.update(phase='final', outcome='failed', errorKind='execution', checkinConfirmed=False, exchange='not_run')
    details = {}
    try:
        cookie, ua, revision = credential(os.environ.get('GQD_ACCOUNT_JSON', ''))
        if revision != receipt['credentialRevision']:
            raise ValueError('credential changed during run')
        history = json.loads(Path('gqd-history/history.json').read_text(encoding='utf-8'))
        previous = decide(history, key, revision, receipt['operation'], day())
        os.environ['GLADOS_USER_AGENT'] = ua
        spec = importlib.util.spec_from_file_location('upstream', 'upstream/checkin.py')
        upstream = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(upstream)
        upstream.DOMAINS = ['https://glados.cloud']
        upstream.log = lambda *args, **kwargs: None
        status_probe = {'status': None}
        def wrap(original):
            def request(*args, **kwargs):
                response = original(*args, **kwargs)
                status_probe['status'] = response.status_code
                return response
            return request
        for method in ('get', 'post'):
            setattr(upstream.requests, method, wrap(getattr(upstream.requests, method)))
        receipt.pop('errorKind', None)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            details = run_account(upstream.GLaDOS(cookie), upstream, previous, receipt['operation'], settings, receipt, status_probe)
    except Exception:
        receipt.update(outcome='unverified', errorKind='execution')
        if receipt.get('checkinAttemptedAt') and not receipt.get('checkinConfirmed'):
            receipt['checkinUncertain'] = True
    receipt['businessDate'] = day()
    receipt['observedAt'] = stamp()
    # Detailed balances/deltas belong only in the encrypted report, not public artifacts.
    def public_receipt(value):
        return {k: v for k, v in value.items() if k != 'pointsAdded'}
    details.update(accountKey=key, repository=receipt['repository'], runId=receipt['runId'], businessDate=receipt['businessDate'], observedAt=receipt['observedAt'], receipt=receipt)
    write_json(ROOT / 'receipt.json', public_receipt(receipt))
    report = config.get('reporting', {})
    if report.get('publicKey') and report.get('keyId'):
        # Plaintext goes only through a private subprocess pipe, never a file/log.
        process = subprocess.run(['node', '.github/glados/encrypt.cjs'], input=json.dumps(details, ensure_ascii=False).encode('utf-8'), capture_output=True, timeout=15)
        if process.returncode == 0 and len(process.stdout) <= 512 * 1024:
            envelope = json.loads(process.stdout)
            write_json(ROOT / 'report.json', envelope)
        else:
            receipt['reportError'] = 'encryption_failed'
            write_json(ROOT / 'receipt.json', public_receipt(receipt))
    else:
        receipt['reportError'] = 'report_key_missing'
        write_json(ROOT / 'receipt.json', public_receipt(receipt))
    public = {k: receipt[k] for k in ('accountKey', 'outcome', 'checkinConfirmed', 'checkinBusinessDate', 'checkinConfirmedAt', 'businessDate', 'observedAt', 'exchange', 'errorKind', 'authenticationRequired') if k in receipt}
    print('QUICK_DEPLOY_RESULT=' + json.dumps(public, ensure_ascii=False, separators=(',', ':')))
    if receipt.get('outcome') in ('unverified', 'failed', 'authentication_required') or receipt.get('exchange') in ('failed', 'uncertain') or receipt.get('reportError'):
        return 1
    return 0


if __name__ == '__main__':
    try:
        mode = sys.argv[1]
        if mode == 'prepare':
            prepare()
        elif mode == 'preflight':
            preflight()
        elif mode == 'run':
            sys.exit(main_run())
        else:
            raise ValueError('unknown mode')
    except Exception:
        print('GQD_ERROR=configuration_or_transport_failure; no raw credentials or responses emitted')
        sys.exit(1)
