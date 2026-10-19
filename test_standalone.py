import base64
import hashlib
from pathlib import Path
import re
import unittest
from build_standalone import build


class PortableArtifactTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).parent / 'web'
        self.html = build(self.root)

    def test_csp_pins_the_exact_inline_bytes(self):
        script = re.search(r'<script type="module">(.*?)</script>', self.html, re.S).group(1)
        style = re.search(r'<style>(.*?)</style>', self.html, re.S).group(1)
        for text in [script, style]:
            digest = base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()
            self.assertIn("'sha256-" + digest + "'", self.html)
        self.assertIn("connect-src 'none'", self.html)
        self.assertNotIn("'unsafe-inline'", self.html)

    def test_no_external_assets_and_no_directory_navigation(self):
        self.assertNotIn('src="app.mjs"', self.html)
        self.assertNotIn('href="style.css"', self.html)
        self.assertNotIn("from './engine.mjs'", self.html)
        self.assertIn('<a class="wordmark" href="#">', self.html)

    def test_reproducible_for_identical_sources(self):
        self.assertEqual(self.html, build(self.root))


if __name__ == '__main__':
    unittest.main()
