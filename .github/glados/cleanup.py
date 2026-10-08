"""Delete only completed, managed runs older than 72h; recheck before deletion."""
import datetime as dt
import json
import os
from pathlib import Path
import sys

from common import GitHub, MANAGED, UTC, parse_time, stamp


def expired_run(run, cutoff, current_id):
    times = [parse_time(run.get(k)) for k in ('created_at', 'updated_at', 'run_started_at')]
    return (str(run.get('id')) != str(current_id) and run.get('status') == 'completed'
            and run.get('path', '').split('@')[0] in MANAGED and all(times)
            and max(times) < cutoff)


def old_cache(cache, cutoff):
    key = cache.get('key', '')
    if not key.startswith('gqd-v2-'):
        return False
    times = [parse_time(cache.get(k)) for k in ('created_at', 'last_accessed_at')]
    return all(times) and max(times) < cutoff


def cleanup(api, now=None, current_id=None):
    now = now or dt.datetime.now(UTC)
    cutoff = now - dt.timedelta(hours=72)
    current_id = current_id or os.environ.get('GITHUB_RUN_ID', '0')
    marker = api.request('/contents/.glados-quick-deploy.json')
    import base64
    marker = json.loads(base64.b64decode(marker['content']))
    if marker.get('appId') != 'glados-quick-deploy' or marker.get('schemaVersion') != 1:
        raise ValueError('repository not managed by Quick Deploy')
    # Snapshot all pages before deleting: deleting while paging skips entries.
    runs = api.pages('/actions/runs', 'workflow_runs')
    targets = [run for run in runs if expired_run(run, cutoff, current_id)]
    report = {'schemaVersion': 1, 'observedAt': stamp(now), 'cutoff': stamp(cutoff), 'retentionHours': 72,
              'deletedRuns': 0, 'deletedArtifacts': 0, 'artifactBytes': 0, 'deletedCaches': 0, 'cacheBytes': 0, 'skippedChanged': 0, 'errors': []}
    for candidate in targets:
        run_id = candidate['id']
        try:
            current = api.request(f'/actions/runs/{run_id}', missing_ok=True)
            if current is None:
                continue
            if not expired_run(current, cutoff, current_id) or current.get('run_attempt') != candidate.get('run_attempt') or current.get('updated_at') != candidate.get('updated_at'):
                report['skippedChanged'] += 1
                continue
            artifacts = api.pages(f'/actions/runs/{run_id}/artifacts', 'artifacts')
            api.request(f'/actions/runs/{run_id}', method='DELETE', missing_ok=True)
            if api.request(f'/actions/runs/{run_id}', missing_ok=True) is not None:
                raise RuntimeError('deletion not verified')
            report['deletedRuns'] += 1
            report['deletedArtifacts'] += len(artifacts)
            report['artifactBytes'] += sum(max(0, x.get('size_in_bytes', 0)) for x in artifacts)
        except Exception:
            report['errors'].append({'kind': 'run', 'id': run_id})
    caches = api.pages('/actions/caches', 'actions_caches')
    for cache in caches:
        if not old_cache(cache, cutoff):
            continue
        try:
            # Listing by ID is not available; re-read the exact key and ref.
            from urllib.parse import quote
            fresh = api.pages('/actions/caches?key=' + quote(cache['key'], safe='') + '&ref=' + quote(cache.get('ref', ''), safe=''), 'actions_caches')
            current = next((x for x in fresh if x.get('id') == cache['id']), None)
            if not current or not old_cache(current, cutoff):
                report['skippedChanged'] += 1
                continue
            api.request(f"/actions/caches/{cache['id']}", method='DELETE', missing_ok=True)
            verified = api.pages('/actions/caches?key=' + quote(cache['key'], safe='') + '&ref=' + quote(cache.get('ref', ''), safe=''), 'actions_caches')
            if any(x.get('id') == cache['id'] for x in verified):
                raise RuntimeError('cache deletion not verified')
            report['deletedCaches'] += 1
            report['cacheBytes'] += max(0, current.get('size_in_bytes', 0))
        except Exception:
            report['errors'].append({'kind': 'cache', 'id': cache.get('id')})
    return report


if __name__ == '__main__':
    try:
        result = cleanup(GitHub())
        print('QUICK_DEPLOY_CLEANUP=' + json.dumps(result, separators=(',', ':')))
        if os.environ.get('GITHUB_STEP_SUMMARY'):
            Path(os.environ['GITHUB_STEP_SUMMARY']).write_text(
                '# 3-day cleanup\n\n' + json.dumps(result, ensure_ascii=False, indent=2), encoding='utf-8')
        sys.exit(1 if result['errors'] else 0)
    except Exception:
        print('QUICK_DEPLOY_CLEANUP_ERROR=unverified; configuration and account secrets were not changed')
        sys.exit(1)
