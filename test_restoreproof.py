import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from restoreproof import scan, compare, validate_manifest


class IntegrityScenarios(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'source'; self.source.mkdir()
        self.copy = self.base / 'copy'; self.copy.mkdir()
        for name, value in [('brief.txt', b'original'), ('nested/mix.wav', b'RIFFdemo'), ('notes.txt', b'keep')]:
            for folder in [self.source, self.copy]:
                p = folder / name; p.parent.mkdir(exist_ok=True); p.write_bytes(value)
        files, errors = scan(self.source)
        self.assertFalse(errors)
        self.expected = validate_manifest({'schema': 'restoreproof/v1', 'files': list(files.values())})

    def report(self):
        files, errors = scan(self.copy)
        return compare(self.expected, files, errors)

    def test_exact_copy_passes(self):
        self.assertEqual(self.report()['status'], 'verified')

    def test_equal_size_corruption_missing_and_extra_are_distinct(self):
        (self.copy / 'brief.txt').write_bytes(b'corrupt!')
        (self.copy / 'notes.txt').unlink()
        (self.copy / 'extra.txt').write_text('unexpected')
        r = self.report()
        self.assertEqual(r['status'], 'attention')
        self.assertEqual({x['path']: x['status'] for x in r['files']}, {'brief.txt': 'changed', 'extra.txt': 'unexpected', 'nested/mix.wav': 'matched', 'notes.txt': 'missing'})

    def test_symlink_to_external_file_never_passes(self):
        outside = self.base / 'outside'; outside.write_text('do not read')
        (self.copy / 'link').symlink_to(outside)
        r = self.report()
        self.assertEqual(r['status'], 'attention')
        self.assertIn('Symlink', r['errors'][0]['error'])

    def test_hidden_file_is_explicit_incomplete_coverage(self):
        (self.copy / '.env').write_text('synthetic fixture, not a credential')
        self.assertTrue(self.report()['errors'])
        self.assertEqual(self.report()['status'], 'attention')

    def test_untrusted_manifest_rejects_traversal_duplicates_and_empty(self):
        item = next(iter(self.expected.values()))
        cases = [[], [item, item], [{**item, 'path': '../outside'}], [{**item, 'bytes': True}], [{**item, 'sha256': 'bad'}]]
        for files in cases:
            with self.subTest(files=files), self.assertRaises(ValueError):
                validate_manifest({'schema': 'restoreproof/v1', 'files': files})

    def test_unicode_filename_matches(self):
        for folder in [self.source, self.copy]:
            (folder / '한글-音楽.txt').write_text('synthetic')
        expected, errors = scan(self.source)
        observed, errors = scan(self.copy)
        self.assertEqual(compare(expected, observed, errors)['status'], 'verified')

    def run_verify(self, manifest):
        output = self.base / 'report.json'
        result = subprocess.run(
            [sys.executable, str(Path(__file__).with_name('restoreproof.py')),
             'verify', str(manifest), str(self.copy), '--output', str(output)],
            capture_output=True, text=True, timeout=3)
        return result, output

    def test_cli_valid_manifest_creates_matching_report(self):
        manifest = self.base / 'reference.json'
        manifest.write_text(json.dumps({'schema': 'restoreproof/v1',
                                        'files': list(self.expected.values())}))
        result, output = self.run_verify(manifest)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(output.read_text())['status'], 'verified')

    def test_manifest_special_files_and_symlink_are_refused_without_waiting(self):
        fifo = self.base / 'manifest.fifo'; os.mkfifo(fifo)
        normal = self.base / 'reference.json'; normal.write_text('{}')
        link = self.base / 'manifest-link'; link.symlink_to(normal)
        for path in [fifo, self.source, link, Path('/dev/zero')]:
            with self.subTest(path=path):
                result, output = self.run_verify(path)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(json.loads(result.stderr)['status'], 'error')
                self.assertFalse(output.exists())

    def test_oversized_manifest_does_not_create_report(self):
        manifest = self.base / 'oversized.json'
        manifest.write_bytes(b' ' * (8 * 1024 * 1024 + 1))
        result, output = self.run_verify(manifest)
        self.assertEqual(result.returncode, 2)
        self.assertIn('8 MiB', json.loads(result.stderr)['error'])
        self.assertFalse(output.exists())

    def test_deeply_nested_manifest_returns_clean_error(self):
        manifest = self.base / 'nested.json'
        manifest.write_text('[' * 2000 + '0' + ']' * 2000)
        result, output = self.run_verify(manifest)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stderr)['status'], 'error')
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
