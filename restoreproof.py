"""Read-only restore verification. Python 3.9+, standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import unicodedata

SCHEMA = 'restoreproof/v1'
LIMIT = 10000


def clean_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise ValueError('Invalid relative path')
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ('', '.', '..') for x in value.split('/')):
        raise ValueError('Unsafe relative path')
    if any(ord(x) < 32 for x in value):
        raise ValueError('Control character in path')
    return unicodedata.normalize('NFC', value)


def validate_manifest(data):
    if not isinstance(data, dict) or data.get('schema') != SCHEMA:
        raise ValueError('Unsupported manifest schema')
    entries = data.get('files')
    if not isinstance(entries, list) or not 0 < len(entries) <= LIMIT:
        raise ValueError('Manifest must contain 1–10000 files')
    result = {}
    for item in entries:
        if not isinstance(item, dict):
            raise ValueError('Invalid file entry')
        name = clean_path(item.get('path'))
        size, digest = item.get('bytes'), item.get('sha256')
        if name in result or type(size) is not int or size < 0:
            raise ValueError('Duplicate path or invalid byte count')
        if not isinstance(digest, str) or not re.fullmatch('[a-f0-9]{64}', digest):
            raise ValueError('Invalid SHA-256')
        result[name] = {'path': name, 'bytes': size, 'sha256': digest}
    return result


def fingerprint(path):
    """No symlink traversal; reject files changed while they are being read."""
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError('Not a regular file')
        digest = hashlib.sha256()
        total = 0
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                total += len(chunk)
                digest.update(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns) or total != after.st_size:
            raise ValueError('File changed during read')
        return {'bytes': total, 'sha256': digest.hexdigest()}
    finally:
        os.close(fd)


def scan(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError('Select a real directory, not a symlink')
    files, errors = {}, []
    def visit(directory, prefix=''):
        try:
            entries = sorted(os.scandir(directory), key=lambda x: x.name)
        except OSError as exc:
            errors.append({'path': prefix or '.', 'error': type(exc).__name__})
            return
        for entry in entries:
            raw = prefix + entry.name
            try:
                name = clean_path(raw)
                if entry.is_symlink():
                    raise ValueError('Symlink excluded; coverage incomplete')
                if entry.name.startswith('.') or entry.name.lower() in ('credentials', 'secrets', 'id_rsa', 'id_ed25519'):
                    raise ValueError('Private/hidden entry excluded; coverage incomplete')
                if entry.is_dir(follow_symlinks=False):
                    visit(entry.path, raw + '/')
                elif entry.is_file(follow_symlinks=False):
                    if name in files:
                        raise ValueError('Normalized path collision')
                    if len(files) >= LIMIT:
                        raise ValueError('File limit reached')
                    files[name] = {'path': name, **fingerprint(entry.path)}
                else:
                    raise ValueError('Special file excluded; coverage incomplete')
            except (OSError, ValueError) as exc:
                errors.append({'path': raw, 'error': str(exc) if isinstance(exc, ValueError) else type(exc).__name__})
    visit(root)
    return files, errors


def compare(expected, observed, errors):
    rows = []
    for name in sorted(set(expected) | set(observed)):
        a, b = expected.get(name), observed.get(name)
        status = 'unexpected' if a is None else 'missing' if b is None else 'matched' if (a['bytes'], a['sha256']) == (b['bytes'], b['sha256']) else 'changed'
        rows.append({'path': name, 'status': status, 'expected': a, 'observed': b})
    passed = bool(expected) and not errors and all(x['status'] == 'matched' for x in rows)
    return {'schema': 'restoreproof-report/v1', 'status': 'verified' if passed else 'attention', 'files': rows, 'errors': errors, 'scope': 'Byte equality against the provided manifest only. Not authenticity, malware detection, metadata, empty-directory or application recovery verification.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('snapshot'); p.add_argument('folder'); p.add_argument('output')
    p = sub.add_parser('verify'); p.add_argument('manifest'); p.add_argument('folder'); p.add_argument('--output')
    args = parser.parse_args()
    try:
        if args.command == 'snapshot':
            files, errors = scan(args.folder)
            if errors or not files:
                print(json.dumps({'status': 'incomplete', 'errors': errors, 'file_count': len(files)}))
                return 2
            output = Path(args.output)
            if output.resolve().is_relative_to(Path(args.folder).resolve()):
                raise ValueError('Save manifest outside the scanned folder')
            with output.open('x', encoding='utf-8') as stream:
                json.dump({'schema': SCHEMA, 'files': list(files.values())}, stream, indent=2)
            print(json.dumps({'status': 'snapshot_created', 'files': len(files)}))
            return 0
        manifest_path = Path(args.manifest)
        if manifest_path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Manifest exceeds 8 MiB')
        expected = validate_manifest(json.loads(manifest_path.read_text(encoding='utf-8')))
        observed, errors = scan(args.folder)
        report = compare(expected, observed, errors)
        if args.output:
            if Path(args.output).resolve().is_relative_to(Path(args.folder).resolve()):
                raise ValueError('Save report outside the scanned folder')
            with Path(args.output).open('x', encoding='utf-8') as stream:
                json.dump(report, stream, indent=2)
        print(json.dumps(report, ensure_ascii=False))
        return 0 if report['status'] == 'verified' else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({'status': 'error', 'error': str(exc)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
