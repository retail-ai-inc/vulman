import contextlib
import hashlib
import io
import json
from pathlib import Path
import plistlib
import stat
import struct
import tarfile
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit
import zipfile

import publish_release
import release

COMMIT = 'a' * 40
TAG = 'v1.3.0'
REPOSITORY = 'example/vulman'


def binary(platform, arch, tag=TAG):
    data = bytearray(256)
    if platform == 'linux':
        data[:6] = b'\x7fELF\x02\x01'
        struct.pack_into('<H', data, 18, {'amd64': 62, 'arm64': 183}[arch])
    elif platform == 'windows':
        data[:2] = b'MZ'
        struct.pack_into('<I', data, 60, 80)
        data[80:84] = b'PE\0\0'
        struct.pack_into('<H', data, 84, {'amd64': 0x8664, 'arm64': 0xAA64}[arch])
    else:
        data[:4] = b'\xca\xfe\xba\xbe'
        struct.pack_into('>I', data, 4, 2)
        struct.pack_into('>I', data, 8, 0x01000007)
        struct.pack_into('>I', data, 28, 0x0100000C)
    return bytes(data) + f'<small>{tag}</small>'.encode()


def archive(directory, platform, arch, tag=TAG, commit=COMMIT, omit=None, executable=True):
    path = directory / release.archive_name(tag, platform, arch)
    prefix = path.name.removesuffix('.tar.gz').removesuffix('.zip') + '/'
    files = {name: b'fixture' for name in release.expected_files(platform)}
    files['BUILD-INFO.json'] = json.dumps({'version': tag, 'source_commit': commit, 'os': platform, 'architecture': arch}).encode()
    for name in release.executable_files(platform):
        files[name] = binary(platform, arch, tag)
    if platform == 'macos':
        files['Vulman.app/Contents/Info.plist'] = plistlib.dumps({'CFBundleShortVersionString': release.version(tag)[0]})
    files.pop(omit, None)

    if platform == 'linux':
        with tarfile.open(path, 'w:gz') as package:
            for name, data in files.items():
                item = tarfile.TarInfo(prefix + name)
                item.size = len(data)
                item.mode = 0o755 if executable and name in release.executable_files(platform) else 0o644
                package.addfile(item, io.BytesIO(data))
    else:
        with zipfile.ZipFile(path, 'w') as package:
            for name, data in files.items():
                item = zipfile.ZipInfo(prefix + name)
                item.external_attr = (stat.S_IFREG | (0o755 if executable and name in release.executable_files(platform) else 0o644)) << 16
                package.writestr(item, data)
    return path


class FakeGitHub:
    def __init__(self, tag=TAG):
        self.tag = tag
        self.commit = COMMIT
        self.current = None
        self.assets = {}
        self.calls = []
        self.fail_name = None
        self.bad_digest = False
        self.next_asset_id = 1

    def request(self, method, path, data=None, **options):
        self.calls.append((method, path, data))
        if path.startswith('/git/ref/tags/'):
            return {'object': {'type': 'commit', 'sha': self.commit}}
        if path.startswith('/releases/tags/'):
            if self.current is None or self.current['draft']:
                raise publish_release.APIError(404)
            return dict(self.current)
        if path.startswith('/releases?'):
            return [dict(self.current)] if self.current else []
        if path == '/releases/generate-notes':
            return {'body': 'Existing changelog'}
        if path == '/releases' and method == 'POST':
            self.current = dict(data, id=7, html_url='https://github.com/example/vulman/releases/tag/' + self.tag)
            return dict(self.current)
        if path.startswith('/releases/7/assets?') and method == 'GET':
            page = int(parse_qs(urlsplit(path).query)['page'][0])
            return list(self.assets.values())[(page - 1) * 100:page * 100]
        if path.startswith('/releases/7/assets?') and method == 'POST':
            name = parse_qs(urlsplit(path).query)['name'][0]
            if name == self.fail_name:
                raise publish_release.APIError(502)
            asset = {'id': self.next_asset_id, 'name': name, 'state': 'uploaded', 'size': len(data),
                     'digest': 'sha256:' + ('0' * 64 if self.bad_digest else hashlib.sha256(data).hexdigest())}
            self.next_asset_id += 1
            self.assets[name] = asset
            return asset
        if path.startswith('/releases/assets/') and method == 'DELETE':
            identifier = int(path.rsplit('/', 1)[1])
            self.assets = {name: asset for name, asset in self.assets.items() if asset['id'] != identifier}
            return None
        if path == '/releases/7' and method == 'PATCH':
            if data.get('draft') is False:
                assert len(self.assets) >= 6, 'Publication happened before every asset was uploaded.'
            self.current.update(data)
            return dict(self.current)
        if path == '/releases/7' and method == 'GET':
            return dict(self.current)
        raise AssertionError((method, path, options))


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def all_archives(self, tag=TAG):
        for platform, arch in release.TARGETS:
            archive(self.directory, platform, arch, tag)

    def publish(self, client, tag=TAG):
        with contextlib.redirect_stdout(io.StringIO()):
            return publish_release.publish(client, tag, COMMIT, REPOSITORY, self.directory)

    def test_semver_and_prerelease_validation(self):
        self.assertEqual(release.version('v1.3.0'), ('1.3.0', False))
        self.assertEqual(release.version('v1.3.0-rc.1+build.2'), ('1.3.0', True))
        for tag in ['latest', '1.3.0', 'v01.3.0', 'v1.3', 'v1.3.0/../../data', 'v1.3.0-rc..1', 'v1.3.0-01', 'v1.3.0+.', 'v1.3.0\necho unsafe']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                release.version(tag)

    def test_tag_must_match_ui_and_macos_metadata(self):
        root = self.directory
        (root / 'cmd/vulman/ui').mkdir(parents=True)
        (root / 'packaging/macos').mkdir(parents=True)
        ui = root / 'cmd/vulman/ui/index.html'
        plist = root / 'packaging/macos/Info.plist'
        ui.write_text('<button id="help-button"><span>About</span><small>v1.3.0-rc.1</small></button>')
        plist.write_bytes(plistlib.dumps({'CFBundleShortVersionString': '1.3.0'}))
        (root / 'go.mod').write_text('module example\n\ngo 1.27.3\n')
        self.assertEqual(release.validate('v1.3.0-rc.1', root), '1.27.x')
        with self.assertRaisesRegex(ValueError, 'UI version'):
            release.validate(TAG, root)
        ui.write_text('<button id="help-button"><small>v1.3.0</small></button>')
        plist.write_bytes(plistlib.dumps({'CFBundleShortVersionString': '1.2.0'}))
        with self.assertRaisesRegex(ValueError, 'CFBundleShortVersionString'):
            release.validate(TAG, root)

    def test_all_five_formats_and_checksum_manifest(self):
        self.all_archives()
        paths = release.checksums(TAG, COMMIT, self.directory)
        self.assertEqual(len(paths), 6)
        manifest = (self.directory / 'SHA256SUMS').read_text().splitlines()
        self.assertEqual(len(manifest), 5)
        for line in manifest:
            checksum, name = line.split('  ')
            self.assertEqual(checksum, hashlib.sha256((self.directory / name).read_bytes()).hexdigest())

    def test_missing_platform_prevents_remote_mutations(self):
        archive(self.directory, 'windows', 'amd64')
        client = FakeGitHub()
        with self.assertRaisesRegex(ValueError, 'five platform'):
            self.publish(client)
        self.assertEqual(client.calls, [])

    def test_wrong_build_commit_missing_files_and_permissions_are_rejected(self):
        for options in [{'commit': 'b' * 40}, {'omit': 'README.txt'}, {'executable': False}]:
            path = archive(self.directory, 'windows', 'arm64', **options)
            with self.subTest(options=options), self.assertRaises(ValueError):
                release.verify_archive(path, TAG, COMMIT, 'windows', 'arm64')

    def test_wrong_architecture_and_version_are_rejected(self):
        for platform, arch in release.TARGETS:
            if platform != 'macos':
                with self.assertRaises(ValueError):
                    release.check_binary(binary(platform, arch), platform, 'arm64' if arch == 'amd64' else 'amd64')
        path = archive(self.directory, 'windows', 'amd64')
        prefix = path.name.removesuffix('.zip')
        with zipfile.ZipFile(path) as package:
            files = {item.filename: (item, package.read(item)) for item in package.infolist()}
        with zipfile.ZipFile(path, 'w') as package:
            for name, (item, data) in files.items():
                package.writestr(item, binary('windows', 'amd64', 'v0.0.0') if name == prefix + '/Vulman.exe' else data)
        with self.assertRaisesRegex(ValueError, 'wrong application version'):
            release.verify_archive(path, TAG, COMMIT, 'windows', 'amd64')

    def test_archive_paths_and_links_are_not_accepted(self):
        for name, mode in [('../outside', stat.S_IFREG), ('../outside/', stat.S_IFDIR), ('link', stat.S_IFLNK)]:
            path = archive(self.directory, 'windows', 'amd64')
            with zipfile.ZipFile(path, 'a') as package:
                item = zipfile.ZipInfo(name)
                item.external_attr = (mode | 0o755) << 16
                package.writestr(item, 'not an allowed release file')
            with self.subTest(name=name), self.assertRaises(ValueError):
                release.verify_archive(path, TAG, COMMIT, 'windows', 'amd64')

    def test_new_release_is_draft_until_all_checksums_are_verified(self):
        self.all_archives()
        client = FakeGitHub()
        result = self.publish(client)
        creation = next(data for method, path, data in client.calls if method == 'POST' and path == '/releases')
        self.assertTrue(creation['draft'])
        self.assertFalse(result['draft'])
        self.assertEqual(len(client.assets), 6)
        self.assertEqual(result['make_latest'], 'legacy')
        self.assertIn('Existing changelog', result['body'])

    def test_failed_upload_keeps_draft_and_rerun_finishes_without_duplicates(self):
        self.all_archives()
        client = FakeGitHub()
        client.fail_name = release.archive_name(TAG, 'windows', 'arm64')
        with self.assertRaises(publish_release.APIError):
            self.publish(client)
        self.assertTrue(client.current['draft'])
        uploaded = dict(client.assets)
        client.fail_name = None
        self.publish(client)
        for name, original in uploaded.items():
            self.assertEqual(client.assets[name], original)
        self.assertEqual(sum(method == 'POST' and path == '/releases' for method, path, _ in client.calls), 1)
        before = len(client.calls)
        self.publish(client)
        self.assertTrue(all(method == 'GET' for method, _, _ in client.calls[before:]))

    def test_unpublished_partial_asset_can_be_replaced_but_public_asset_cannot(self):
        self.all_archives()
        client = FakeGitHub()
        self.publish(client)
        damaged = next(iter(client.assets.values()))
        damaged['digest'] = 'sha256:' + '0' * 64
        before = len(client.calls)
        with self.assertRaisesRegex(ValueError, 'not overwritten'):
            self.publish(client)
        self.assertTrue(all(method == 'GET' for method, _, _ in client.calls[before:]))
        client.current['draft'] = True
        self.publish(client)
        self.assertTrue(any(method == 'DELETE' for method, _, _ in client.calls))
        self.assertFalse(client.current['draft'])

    def test_remote_tag_move_prevents_release_creation(self):
        self.all_archives()
        client = FakeGitHub()
        client.commit = 'b' * 40
        with self.assertRaisesRegex(ValueError, 'remote tag'):
            self.publish(client)
        self.assertIsNone(client.current)

    def test_tag_move_during_upload_leaves_the_release_as_a_draft(self):
        self.all_archives()
        client = FakeGitHub()
        original = client.request
        tag_reads = 0
        def request(method, path, *args, **options):
            nonlocal tag_reads
            if path.startswith('/git/ref/tags/'):
                tag_reads += 1
                if tag_reads > 1:
                    client.commit = 'b' * 40
            return original(method, path, *args, **options)
        client.request = request
        with self.assertRaisesRegex(ValueError, 'remote tag'):
            self.publish(client)
        self.assertTrue(client.current['draft'])

    def test_permission_errors_are_not_mistaken_for_a_missing_release(self):
        self.all_archives()
        client = FakeGitHub()
        original = client.request
        def request(method, path, *args, **options):
            if path.startswith('/releases/tags/'):
                raise publish_release.APIError(403)
            return original(method, path, *args, **options)
        client.request = request
        with self.assertRaises(publish_release.APIError):
            self.publish(client)
        self.assertIsNone(client.current)
        self.assertTrue(all(method == 'GET' for method, _, _ in client.calls))

    def test_digest_mismatch_never_publishes(self):
        self.all_archives()
        client = FakeGitHub()
        client.bad_digest = True
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.publish(client)
        self.assertTrue(client.current['draft'])

    def test_prerelease_is_not_marked_latest(self):
        tag = 'v1.3.0-rc.1'
        self.all_archives(tag)
        result = self.publish(FakeGitHub(tag), tag)
        self.assertTrue(result['prerelease'])
        self.assertEqual(result['make_latest'], 'false')

    def test_asset_pagination_and_existing_release_notes_are_preserved(self):
        self.all_archives()
        client = FakeGitHub()
        self.publish(client)
        client.current['body'] = 'Release notes edited by the maintainer'
        for index in range(101):
            client.assets['other-' + str(index)] = {'id': 1000 + index, 'name': 'other-' + str(index)}
        result = self.publish(client)
        self.assertIn('Release notes edited by the maintainer', result['body'])
        self.assertTrue(any('page=2' in path for _, path, _ in client.calls))

    def test_annotated_tag_resolves_to_the_verified_commit(self):
        client = FakeGitHub()
        original = client.request
        def request(method, path, *args, **options):
            if path.startswith('/git/ref/tags/'):
                return {'object': {'type': 'tag', 'sha': 'b' * 40}}
            if path.startswith('/git/tags/'):
                return {'object': {'type': 'commit', 'sha': COMMIT}}
            return original(method, path, *args, **options)
        client.request = request
        publish_release.check_tag(client, TAG, COMMIT)

    def test_notes_and_authenticated_requests_validate_the_repository(self):
        for repository in ['../other/repository', 'owner/..', './repo', 'owner/repo\nAuthorization: value', 'https://example.com/owner/repo']:
            with self.assertRaises(ValueError):
                publish_release.GitHub(repository, 'fixture')
        client = publish_release.GitHub(REPOSITORY, 'fixture')
        with self.assertRaises(ValueError):
            client.request('GET', 'https://example.com/')
        self.assertIsNone(publish_release.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://example.com/'))


if __name__ == '__main__':
    unittest.main()
