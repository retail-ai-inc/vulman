"""Publish verified archives with the workflow's repository-scoped GITHUB_TOKEN."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import build_opener, HTTPRedirectHandler, Request

import release


class APIError(RuntimeError):
    def __init__(self, status):
        super().__init__(f'GitHub returned HTTP {status}; publication stopped safely.')
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, repository, token):
        # Also validate the repository before placing it in authenticated URLs.
        release.check_repository(repository)
        if not token:
            raise ValueError('GITHUB_TOKEN is required for release publication.')
        self.base = 'https://api.github.com/repos/' + repository
        self.upload_base = 'https://uploads.github.com/repos/' + repository
        self.token = token

    def request(self, method, path, data=None, upload=False, content_type='application/json'):
        if not path.startswith('/'):
            raise ValueError('GitHub requests must use repository-relative paths.')
        headers = {'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                   'X-GitHub-Api-Version': '2026-03-10', 'User-Agent': 'Vulman-release-workflow'}
        if data is not None:
            headers['Content-Type'] = content_type
            if isinstance(data, dict):
                data = json.dumps(data).encode()
        request = Request((self.upload_base if upload else self.base) + path, data=data, method=method, headers=headers)

        # Authenticated requests never follow redirects to another service.
        try:
            with build_opener(NoRedirect).open(request, timeout=120) as response:
                return json.load(response) if response.status != 204 else None
        except HTTPError as error:
            raise APIError(error.code) from None


def check_tag(client, tag, commit):
    reference = client.request('GET', '/git/ref/tags/' + quote(tag, safe=''))['object']
    for _ in range(6):
        if reference['type'] != 'tag':
            break
        reference = client.request('GET', '/git/tags/' + reference['sha'])['object']
    if reference['type'] != 'commit' or reference['sha'] != commit:
        raise ValueError('The remote tag does not match the verified source commit.')


def asset_matches(asset, data):
    return asset.get('state') == 'uploaded' and asset.get('size') == len(data) and asset.get('digest') == 'sha256:' + hashlib.sha256(data).hexdigest()


def list_assets(client, release_id):
    assets = {}
    page = 1
    while True:
        batch = client.request('GET', f'/releases/{release_id}/assets?per_page=100&page={page}')
        assets.update((asset['name'], asset) for asset in batch)
        if len(batch) < 100:
            return assets
        page += 1


def find_release(client, tag):
    try:
        return client.request('GET', '/releases/tags/' + quote(tag, safe=''))
    except APIError as error:
        if error.status != 404:
            raise

    # The tag endpoint describes published releases. List authenticated releases
    # as well so an interrupted draft can always be found and resumed.
    page = 1
    while True:
        batch = client.request('GET', f'/releases?per_page=100&page={page}')
        for current in batch:
            if current['tag_name'] == tag:
                return current
        if len(batch) < 100:
            return None
        page += 1


def publish(client, tag, commit, repository, directory):
    _, prerelease = release.version(tag)
    # No remote mutation until every platform archive and checksum is verified.
    paths = release.checksums(tag, commit, directory)
    check_tag(client, tag, commit)
    notes = release.download_notes(tag, repository)

    current = find_release(client, tag)
    if current is None:
        changes = client.request('POST', '/releases/generate-notes', {'tag_name': tag, 'target_commitish': commit})
        current = client.request('POST', '/releases', {
            'tag_name': tag, 'target_commitish': commit, 'name': 'Vulman ' + tag,
            'body': notes + (changes.get('body') or ''), 'draft': True, 'prerelease': prerelease,
        })

    if current['tag_name'] != tag:
        raise ValueError('GitHub returned an unexpected release.')
    release_id = current['id']
    # Include all pages so reruns never miss an existing asset with the same name.
    assets = list_assets(client, release_id)

    # Preflight the complete set before adding anything to an existing release.
    for path in paths:
        if path.name in assets and not asset_matches(assets[path.name], path.read_bytes()):
            if not current['draft'] or current.get('immutable'):
                raise ValueError('Published asset differs and was not overwritten: ' + path.name)

    for path in paths:
        data = path.read_bytes()
        old = assets.get(path.name)
        if old and asset_matches(old, data):
            print('Already verified: ' + path.name, flush=True)
            continue
        if current.get('immutable'):
            raise ValueError('The existing release is immutable and cannot accept missing assets.')
        if old:
            # Unpublished drafts can resume after a failed build or upload. Never
            # replace a binary that has already been published to users.
            latest = client.request('GET', f'/releases/{release_id}')
            if not latest['draft']:
                raise ValueError('Release was published during upload; refusing to replace an asset.')
            client.request('DELETE', '/releases/assets/' + str(old['id']))

        content_type = 'application/zip' if path.suffix == '.zip' else 'application/gzip' if path.suffix == '.gz' else 'text/plain'
        uploaded = client.request('POST', f'/releases/{release_id}/assets?' + urlencode({'name': path.name}), data,
                                  upload=True, content_type=content_type)
        if uploaded.get('name') != path.name or not asset_matches(uploaded, data):
            raise ValueError('GitHub did not confirm the uploaded SHA-256 digest: ' + path.name)
        assets[path.name] = uploaded
        print('Uploaded and verified: ' + path.name, flush=True)

    check_tag(client, tag, commit)
    current = client.request('GET', f'/releases/{release_id}')
    # Confirm that all six assets still exist and match before publishing.
    final = list_assets(client, release_id)
    for path in paths:
        if path.name not in final or not asset_matches(final[path.name], path.read_bytes()):
            raise ValueError('The completed release is missing a verified asset: ' + path.name)

    update = {}
    if f'<!-- vulman-downloads-{tag} -->' not in (current.get('body') or ''):
        update['body'] = notes + (current.get('body') or '')
    if current['draft']:
        update.update(draft=False, prerelease=prerelease, make_latest='false' if prerelease else 'legacy')
    if update:
        if current.get('immutable'):
            raise ValueError('The existing immutable release cannot be updated.')
        current = client.request('PATCH', f'/releases/{release_id}', update)
    if current['draft']:
        raise ValueError('GitHub did not publish the completed release.')
    print('Release ready: ' + current['html_url'], flush=True)
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--repository', required=True)
    parser.add_argument('--directory', type=Path, default=release.ROOT / 'dist/release')
    args = parser.parse_args()
    client = GitHub(args.repository, os.environ.get('GITHUB_TOKEN', ''))
    publish(client, args.tag, release.source_commit(args.commit), args.repository, args.directory)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, APIError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
