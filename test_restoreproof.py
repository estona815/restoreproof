import json
from pathlib import Path
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


if __name__ == '__main__':
    unittest.main()
