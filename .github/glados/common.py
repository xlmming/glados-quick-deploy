"""Small, bounded GitHub API helpers. No credentials are printed or persisted."""
import datetime as dt
import io
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

UTC = dt.timezone.utc
TZ = dt.timezone(dt.timedelta(hours=8))
WORKFLOW = '.github/workflows/glados-quick-deploy.yml'
MANAGED = {WORKFLOW, '.github/workflows/glados-quick-deploy-cleanup.yml', '.github/workflows/glados-quick-deploy-keepalive.yml'}
KEY_RE = re.compile(r'^[A-F0-9]{16}$')


def stamp(now=None):
    return (now or dt.datetime.now(UTC)).isoformat()


def parse_time(value):
    try:
        result = dt.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return result if result.tzinfo else None
    except (ValueError, TypeError):
        return None


def day(now=None):
    return (now or dt.datetime.now(UTC)).astimezone(TZ).date().isoformat()


def cron(value):
    if not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', str(value)):
        raise ValueError('invalid time')
    hour, minute = map(int, value.split(':'))
    return f'{minute} {(hour + 16) % 24} * * *'


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, repository=None, token=None):
        self.repository = repository or os.environ['GITHUB_REPOSITORY']
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', self.repository):
            raise ValueError('invalid repository')
        self.token = token or os.environ['GH_TOKEN']
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, path, method='GET', missing_ok=False):
        if not re.fullmatch(r'/[A-Za-z0-9_.?=&%/+-]+', path):
            raise ValueError('invalid API path')
        request = urllib.request.Request('https://api.github.com/repos/' + self.repository + path,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'GLaDOS-Quick-Deploy/1.2.0'}, method=method)
        try:
            with self.opener.open(request, timeout=25) as response:
                body = response.read(8 * 1024 * 1024 + 1)
                if len(body) > 8 * 1024 * 1024:
                    raise ValueError('response too large')
                return json.loads(body) if body else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing_ok:
                return None
            # Never expose signed URLs, headers, response bodies or a token in errors.
            raise RuntimeError(f'GitHub HTTP {error.code}') from None

    def pages(self, path, field=None, limit=100):
        out = []
        join = '&' if '?' in path else '?'
        for page in range(1, limit + 1):
            data = self.request(f'{path}{join}per_page=100&page={page}')
            entries = data.get(field, []) if field else data
            if not isinstance(entries, list):
                raise ValueError('invalid API list')
            out.extend(entries)
            if len(entries) < 100:
                return out
        raise RuntimeError('pagination bound reached; no destructive operation performed')

    def artifact_receipt(self, artifact_id):
        if not isinstance(artifact_id, int) or artifact_id <= 0:
            raise ValueError('invalid artifact')
        request = urllib.request.Request(f'https://api.github.com/repos/{self.repository}/actions/artifacts/{artifact_id}/zip',
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'User-Agent': 'GLaDOS-Quick-Deploy/1.2.0'})
        try:
            response = self.opener.open(request, timeout=25)
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                raise RuntimeError(f'artifact HTTP {error.code}') from None
            location = error.headers.get('Location', '')
            parsed = urllib.parse.urlparse(location)
            host = (parsed.hostname or '').lower()
            if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port not in (None, 443) or not (
                    host.endswith('.blob.core.windows.net') or host.endswith('.githubusercontent.com') or host.endswith('.github.com')):
                raise RuntimeError('unexpected artifact download origin')
            # Different origin: do not forward the GitHub authorization header.
            response = self.opener.open(urllib.request.Request(location), timeout=40)
        with response:
            data = response.read(4 * 1024 * 1024 + 1)
        if len(data) > 4 * 1024 * 1024:
            raise ValueError('artifact too large')
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            candidates = [x for x in archive.infolist() if x.filename == 'receipt.json']
            if len(candidates) != 1 or candidates[0].file_size > 65536:
                raise ValueError('invalid receipt artifact')
            result = json.loads(archive.read(candidates[0]))
        if result.get('schemaVersion') != 2 or not KEY_RE.fullmatch(result.get('accountKey', '')):
            raise ValueError('invalid receipt')
        return result


def collect_history(api, now=None, account_keys=None):
    """Read newest sufficient account states, never download every historical ZIP."""
    now = now or dt.datetime.now(UTC)
    cutoff = now - dt.timedelta(hours=72)
    run_id = int(os.environ.get('GITHUB_RUN_ID', '0'))
    branch = os.environ.get('GQD_DEFAULT_BRANCH', 'main')
    pending = set(account_keys) if account_keys is not None else None
    query = urllib.parse.quote((cutoff - dt.timedelta(days=1)).isoformat(), safe='')
    runs = api.pages('/actions/workflows/glados-quick-deploy.yml/runs?created=%3E%3D' + query, 'workflow_runs')
    runs.sort(key=lambda run: str(run.get('created_at', '')), reverse=True)
    history = []
    for run in runs:
        if pending is not None and not pending:
            break
        if run['id'] == run_id or run.get('head_branch') != branch or run.get('path', '').split('@')[0] != WORKFLOW or run.get('event') not in ('schedule', 'workflow_dispatch'):
            continue
        if run.get('status') in ('queued', 'pending', 'requested', 'waiting'):
            continue
        if run.get('status') != 'completed':
            raise RuntimeError('another running check-in exists; history is not stable')
        artifacts = api.pages(f"/actions/runs/{run['id']}/artifacts", 'artifacts')
        candidates = []
        for artifact in artifacts:
            match = re.fullmatch(r'gqd-(result|intent)-([A-F0-9]{16})-(\d+)-(\d+)', artifact.get('name', ''))
            if artifact.get('expired') or not match or str(run['id']) != match[3]:
                continue
            kind, key, attempt = match[1], match[2], match[4]
            if pending is not None and key not in pending:
                continue
            created = parse_time(artifact.get('created_at'))
            if not created or created < cutoff or artifact.get('size_in_bytes', 0) > 4 * 1024 * 1024:
                continue
            candidates.append((artifact, kind, key, attempt))
        final_keys = {(key, attempt) for _, kind, key, attempt in candidates if kind == 'result'}
        for artifact, kind, key, attempt in candidates:
            if kind == 'intent' and (key, attempt) in final_keys:
                continue
            receipt = api.artifact_receipt(artifact['id'])
            if receipt.get('repository') != api.repository or str(receipt.get('runId')) != str(run['id']) or receipt.get('accountKey') != key or str(receipt.get('runAttempt', '1')) != attempt:
                raise ValueError('receipt provenance mismatch')
            if receipt.get('phase') != ('final' if kind == 'result' else 'intent'):
                raise ValueError('receipt phase mismatch')
            receipt['_artifactCreatedAt'] = artifact['created_at']
            receipt['_runEvent'] = run['event']
            history.append(receipt)
            # State-version 1 carries prior authentication, uncertainty and today's
            # accepted check-in. Older schemas are read further, never guessed.
            if kind == 'result' and receipt.get('stateVersion') == 1 and pending is not None:
                pending.discard(key)
    return history
