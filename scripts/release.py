"""Standard-library packaging shared by tag builds and local release checks."""

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import tempfile
from urllib.parse import quote
import zipfile

ROOT = Path(__file__).resolve().parent.parent
TARGETS = [('macos', 'universal'), ('windows', 'amd64'), ('windows', 'arm64'), ('linux', 'amd64'), ('linux', 'arm64')]
APP_FILES = {'Vulman.app/Contents/Info.plist', 'Vulman.app/Contents/MacOS/vulman',
             'Vulman.app/Contents/Resources/Vulman.icns', 'Vulman.app/Contents/_CodeSignature/CodeResources'}


def version(tag):
    match = re.fullmatch(r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?', tag)
    if not match or len(tag) > 128:
        raise ValueError('Use a version tag such as v1.3.0 or v1.3.0-rc.1.')

    for index in (4, 5):
        for identifier in (match[index] or '').split('.'):
            if match[index] is not None and (not identifier or index == 4 and identifier.isdigit() and len(identifier) > 1 and identifier.startswith('0')):
                raise ValueError('The version tag is not valid SemVer.')

    return '.'.join(match.group(1, 2, 3)), bool(match[4])


def source_commit(value=None):
    value = value or subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    if not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ValueError('A complete source commit SHA is required.')
    return value


class AppVersion(HTMLParser):
    def __init__(self):
        super().__init__()
        self.help = self.small = False
        self.values = []

    def handle_starttag(self, tag, attrs):
        if tag == 'button' and dict(attrs).get('id') == 'help-button':
            self.help = True
        if tag == 'small' and self.help:
            self.small = True

    def handle_endtag(self, tag):
        if tag == 'button':
            self.help = False
        if tag == 'small':
            self.small = False

    def handle_data(self, data):
        if self.small:
            self.values.append(data.strip())


def validate(tag, root=ROOT):
    core, _ = version(tag)
    parser = AppVersion()
    parser.feed((root / 'cmd/vulman/ui/index.html').read_text(encoding='utf-8'))
    if parser.values != [tag]:
        raise ValueError(f'Update the UI version to {tag} before creating this tag.')

    with (root / 'packaging/macos/Info.plist').open('rb') as handle:
        info = plistlib.load(handle)
    if info['CFBundleShortVersionString'] != core:
        raise ValueError(f'Update CFBundleShortVersionString to {core} before creating this tag.')

    match = re.search(r'^go ([0-9]+)\.([0-9]+)\.[0-9]+$', (root / 'go.mod').read_text(encoding='utf-8'), re.MULTILINE)
    if not match:
        raise ValueError('go.mod must specify a complete minimum Go version.')
    return f'{match[1]}.{match[2]}.x'


def archive_name(tag, platform, arch):
    version(tag)
    return f'Vulman-{tag}-{platform}-{arch}' + ('.tar.gz' if platform == 'linux' else '.zip')


def expected_files(platform):
    common = {'README.txt', 'BUILD-INFO.json'}
    if platform == 'macos':
        return common | APP_FILES | {'vulman-scan'}
    if platform == 'windows':
        return common | {'Vulman.exe', 'vulman-scan.exe'}
    return common | {'vulman', 'vulman-scan', 'com.vulman.app.desktop', 'com.vulman.app.svg'}


def executable_files(platform):
    if platform == 'macos':
        return {'Vulman.app/Contents/MacOS/vulman', 'vulman-scan'}
    return {'Vulman.exe', 'vulman-scan.exe'} if platform == 'windows' else {'vulman', 'vulman-scan'}


def check_binary(data, platform, arch):
    if platform == 'linux':
        valid = data[:6] == b'\x7fELF\x02\x01' and len(data) >= 20 and struct.unpack_from('<H', data, 18)[0] == {'amd64': 62, 'arm64': 183}[arch]
    elif platform == 'windows':
        offset = struct.unpack_from('<I', data, 60)[0] if data[:2] == b'MZ' and len(data) >= 64 else len(data)
        valid = offset + 6 <= len(data) and data[offset:offset + 4] == b'PE\0\0' and struct.unpack_from('<H', data, offset + 4)[0] == {'amd64': 0x8664, 'arm64': 0xAA64}[arch]
    else:
        magic = data[:4]
        stride = 20 if magic == b'\xca\xfe\xba\xbe' else 32
        valid = magic in {b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'} and len(data) >= 8 + 2 * stride and struct.unpack_from('>I', data, 4)[0] == 2
        valid = valid and {struct.unpack_from('>I', data, 8 + index * stride)[0] for index in range(2)} == {0x01000007, 0x0100000C}
    if not valid:
        raise ValueError(f'Wrong executable format or architecture for {platform}/{arch}.')


def readme(tag, platform, arch):
    launch = {
        'macos': 'Requires macOS 13+. Drag Vulman.app into Applications and open it.\nThis app is ad-hoc signed and not notarized. First-launch guidance:\nhttps://support.apple.com/en-us/102445',
        'windows': 'Extract All, then open Vulman.exe. Requires Microsoft WebView2 Runtime:\nhttps://developer.microsoft.com/en-us/microsoft-edge/webview2/\nThese executables are not Authenticode signed.',
        'linux': 'Extract the archive and run ./vulman. Requires glibc, GTK4 and WebKitGTK 6.0.\nThe system libraries are not bundled. Platform details:\nhttps://v3.wails.io/guides/build/linux/',
    }[platform]
    return f'''Vulman {tag} — {platform}/{arch}

{launch}

No Go installation or compilation is required. The optional vulman-scan CLI is
included; use --help for its options. External scanners require their own tools
and runtimes. The built-in PHP scanner uses the local OSV Packagist database.

Before upgrading, back up the workspace database and vulman.key together if you
may return to an older build. Existing workspace migrations commit atomically.
No workspace databases, keys, credentials, or repository code are in this package.

Compare this archive's SHA-256 digest with SHA256SUMS on the release page.
Usage: https://github.com/retail-ai-inc/vulman#readme
'''


def verify_archive(path, tag, commit, platform, arch):
    name = archive_name(tag, platform, arch)
    if path.name != name:
        raise ValueError('Unexpected archive name.')
    prefix = name.removesuffix('.tar.gz').removesuffix('.zip') + '/'
    files = {}
    directories = {prefix.rstrip('/')}
    for name in expected_files(platform):
        directories.update(prefix.rstrip('/') + '/' + str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')

    def directory(name):
        if name.rstrip('/') not in directories:
            raise ValueError('Unexpected archive directory.')

    def member(name, size, mode, data):
        if not name.startswith(prefix) or size > 128 << 20 or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts:
            raise ValueError('Unexpected archive path or size.')
        key = name[len(prefix):]
        if key not in expected_files(platform) or key in files:
            raise ValueError('Unexpected or duplicate archive member: ' + key)
        if key in executable_files(platform) and not mode & 0o111:
            raise ValueError('Executable permission missing: ' + key)
        files[key] = data()

    if platform == 'linux':
        with tarfile.open(path, 'r:gz') as package:
            for item in package.getmembers():
                if item.isdir():
                    directory(item.name)
                    continue
                if not item.isfile():
                    raise ValueError('Links and special files are not allowed in release archives.')
                member(item.name, item.size, item.mode, lambda: package.extractfile(item).read())
    else:
        with zipfile.ZipFile(path) as package:
            for item in package.infolist():
                if item.is_dir():
                    directory(item.filename)
                    continue
                if stat.S_IFMT(item.external_attr >> 16) not in {0, stat.S_IFREG}:
                    raise ValueError('Links and special files are not allowed in release archives.')
                member(item.filename, item.file_size, item.external_attr >> 16, lambda: package.read(item))

    if files.keys() != expected_files(platform):
        raise ValueError('Release archive is incomplete.')
    info = json.loads(files['BUILD-INFO.json'])
    if (info.get('version'), info.get('source_commit'), info.get('os'), info.get('architecture')) != (tag, commit, platform, arch):
        raise ValueError('Archive build information does not match the release.')
    for executable in executable_files(platform):
        check_binary(files[executable], platform, arch)
    desktop = 'Vulman.app/Contents/MacOS/vulman' if platform == 'macos' else 'Vulman.exe' if platform == 'windows' else 'vulman'
    if f'<small>{tag}</small>'.encode() not in files[desktop]:
        raise ValueError('The desktop executable contains the wrong application version.')
    if platform == 'macos' and plistlib.loads(files['Vulman.app/Contents/Info.plist'])['CFBundleShortVersionString'] != version(tag)[0]:
        raise ValueError('The packaged macOS version does not match the release.')


def package_platform(tag, commit, platform, dist, output):
    validate(tag)
    if source_commit() != commit:
        raise ValueError('Build checkout does not match the requested source commit.')
    output.mkdir(parents=True, exist_ok=True)
    for target, arch in TARGETS:
        if target != platform:
            continue
        archive = output / archive_name(tag, platform, arch)
        if archive.exists():
            raise ValueError('Refusing to overwrite a local release archive: ' + archive.name)
        with tempfile.TemporaryDirectory(prefix='vulman-release-') as temporary:
            stage = Path(temporary) / archive.name.removesuffix('.tar.gz').removesuffix('.zip')
            stage.mkdir()
            if platform == 'macos':
                subprocess.run(['ditto', '--norsrc', '--noextattr', '--noacl', '--noqtn', str(dist / 'Vulman.app'), str(stage / 'Vulman.app')], check=True)
                sources = {'vulman-scan': 'vulman-scan-macos'}
            elif platform == 'windows':
                sources = {'Vulman.exe': f'vulman-windows-{arch}.exe', 'vulman-scan.exe': f'vulman-scan-windows-{arch}.exe'}
            else:
                sources = {'vulman': f'vulman-linux-{arch}', 'vulman-scan': f'vulman-scan-linux-{arch}',
                           'com.vulman.app.desktop': 'com.vulman.app.desktop', 'com.vulman.app.svg': 'com.vulman.app.svg'}
            for destination, source in sources.items():
                shutil.copyfile(dist / source, stage / destination)
                (stage / destination).chmod(0o755 if destination in executable_files(platform) else 0o644)
            (stage / 'README.txt').write_text(readme(tag, platform, arch), encoding='utf-8')
            (stage / 'BUILD-INFO.json').write_text(json.dumps({'version': tag, 'source_commit': commit, 'os': platform, 'architecture': arch}, indent=2) + '\n', encoding='utf-8')
            if any(path.is_symlink() for path in stage.rglob('*')):
                raise ValueError('Links are not allowed in a staged release.')
            if platform == 'macos':
                subprocess.run(['codesign', '--verify', '--deep', '--strict', str(stage / 'Vulman.app')], check=True)
                subprocess.run(['codesign', '--verify', '--strict', str(stage / 'vulman-scan')], check=True)
                subprocess.run(['ditto', '-c', '-k', '--norsrc', '--noextattr', '--keepParent', str(stage), str(archive.resolve())], check=True)
                with tempfile.TemporaryDirectory(prefix='vulman-release-check-') as extracted:
                    subprocess.run(['ditto', '-x', '-k', str(archive.resolve()), extracted], check=True)
                    subprocess.run(['codesign', '--verify', '--deep', '--strict', str(Path(extracted) / stage.name / 'Vulman.app')], check=True)
                    subprocess.run(['codesign', '--verify', '--strict', str(Path(extracted) / stage.name / 'vulman-scan')], check=True)
            elif platform == 'windows':
                with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zipped:
                    for path in sorted(stage.rglob('*')):
                        if path.is_file():
                            zipped.write(path, stage.name + '/' + path.relative_to(stage).as_posix())
            else:
                def normalize(item):
                    item.uid = item.gid = 0
                    item.uname = item.gname = ''
                    return item
                with tarfile.open(archive, 'w:gz') as tar:
                    tar.add(stage, arcname=stage.name, filter=normalize)
        verify_archive(archive, tag, commit, platform, arch)
        print('Verified ' + archive.name, flush=True)


def release_assets(tag, commit, directory):
    names = {archive_name(tag, platform, arch) for platform, arch in TARGETS}
    if {path.name for path in directory.iterdir()} - {'SHA256SUMS'} != names:
        raise ValueError('Exactly five platform archives are required before publishing.')
    for platform, arch in TARGETS:
        verify_archive(directory / archive_name(tag, platform, arch), tag, commit, platform, arch)
    return sorted(directory / name for name in names)


def checksums(tag, commit, directory):
    assets = release_assets(tag, commit, directory)
    content = ''
    for path in assets:
        with path.open('rb') as handle:
            content += hashlib.file_digest(handle, 'sha256').hexdigest() + '  ' + path.name + '\n'
    (directory / 'SHA256SUMS').write_text(content, encoding='utf-8')
    return assets + [directory / 'SHA256SUMS']


def check_repository(repository):
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository) or any(part in {'.', '..'} for part in repository.split('/')):
        raise ValueError('Invalid GitHub repository.')


def download_notes(tag, repository):
    version(tag)
    check_repository(repository)
    base = f'https://github.com/{repository}/releases/download/{quote(tag, safe="")}/'
    link = lambda platform, arch, label: f'[{label}]({base}{quote(archive_name(tag, platform, arch))})'
    return f'''<!-- vulman-downloads-{tag} -->
### Download Vulman {tag}

Extract the package and launch Vulman. No Go installation or compilation is required. Each package includes the desktop app, standalone scanner, build information, and installation instructions.

| Platform | Download | Start |
| --- | --- | --- |
| macOS 13+ | {link('macos', 'universal', 'Universal — Apple Silicon + Intel')} | Drag `Vulman.app` into Applications. |
| Windows | {link('windows', 'amd64', 'x64')} · {link('windows', 'arm64', 'ARM64')} | Open `Vulman.exe`. |
| Linux | {link('linux', 'amd64', 'x64')} · {link('linux', 'arm64', 'ARM64')} | Run `./vulman`. |

[SHA-256 checksums]({base}SHA256SUMS). Windows requires WebView2 Runtime; Linux requires glibc, GTK4, and WebKitGTK 6.0 system libraries. External code scanners need their own tools and runtimes. The macOS build is ad-hoc signed and not notarized; see [Apple's first-launch guidance](https://support.apple.com/en-us/102445). Windows executables are not Authenticode signed.

'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['validate', 'package', 'checksums'])
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit')
    parser.add_argument('--platform', choices=['linux', 'windows', 'macos'])
    parser.add_argument('--dist', type=Path, default=ROOT / 'dist')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/release')
    parser.add_argument('--github-output', type=Path)
    args = parser.parse_args()
    commit = source_commit(args.commit)

    if args.command == 'validate':
        go = validate(args.tag)
        if args.github_output:
            with args.github_output.open('a', encoding='utf-8') as handle:
                handle.write(f'commit={commit}\ngo-version={go}\n')
        print(f'Validated {args.tag} at {commit}; Go {go}')
    elif args.command == 'package':
        if args.platform is None:
            parser.error('--platform is required for packaging')
        package_platform(args.tag, commit, args.platform, args.dist, args.output)
    else:
        checksums(args.tag, commit, args.output)
        print('Verified five archives and wrote SHA256SUMS.')


if __name__ == '__main__':
    main()
