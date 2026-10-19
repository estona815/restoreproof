"""Build a self-contained HTML artifact from the reviewed static source.

No minifier, dependencies, telemetry or remote assets. Inline source is pinned
by exact CSP hashes. Output is exclusive: no existing artifact is overwritten.
"""
import base64
import hashlib
from pathlib import Path
import re
import sys


def csp_hash(text):
    return base64.b64encode(hashlib.sha256(text.encode('utf-8')).digest()).decode('ascii')


def build(source):
    html = (source / 'index.html').read_text(encoding='utf-8')
    css = (source / 'style.css').read_text(encoding='utf-8')
    engine = (source / 'engine.mjs').read_text(encoding='utf-8')
    app = (source / 'app.mjs').read_text(encoding='utf-8')
    engine = re.sub(r'^export ', '', engine, flags=re.MULTILINE)
    app = re.sub(r"^import .*?;\n", '', app, count=1)
    # Modules execute after the document has been parsed, including file://.
    script = engine + '\n' + app
    if '</script' in script.lower() or '</style' in css.lower():
        raise ValueError('Source contains an HTML closing-tag sequence')
    policy = "default-src 'none'; connect-src 'none'; img-src data:; object-src 'none'; base-uri 'none'; form-action 'none'; script-src 'sha256-" + csp_hash(script) + "'; style-src 'sha256-" + csp_hash(css) + "'"
    html = re.sub(r'<meta http-equiv="Content-Security-Policy" content="[^"]*">', '<meta http-equiv="Content-Security-Policy" content="' + policy + '">', html)
    html = html.replace('<link rel="stylesheet" href="style.css">', '<style>' + css + '</style>')
    html = html.replace('<script type="module" src="app.mjs"></script>', '<script type="module">' + script + '</script>')
    html = html.replace('<a class="wordmark" href="./">', '<a class="wordmark" href="#">')
    return html


if __name__ == '__main__':
    if len(sys.argv) != 2:
        raise SystemExit('Usage: python3 build_standalone.py /new/path/restoreproof.html')
    output = Path(sys.argv[1])
    with output.open('x', encoding='utf-8') as stream:
        stream.write(build(Path(__file__).parent / 'web'))
    print(f'{output}: {output.stat().st_size} bytes')
