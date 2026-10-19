# RestoreProof

A local, read-only recovery check for people who have a folder called “backup” but have never compared a restored copy against trusted source bytes.

## Run the browser tool

The self-contained release HTML is designed for compatible browsers without a local server. It contains the same engine, UI and styles, pinned by Content Security Policy hashes. Direct local-file execution was not verified in the current embedded browser because its security policy blocks file URLs; this limit was not bypassed. If a browser does not expose Web Crypto for local files, the app shows an explicit error. The original localhost route below has been exercised. Build the HTML reproducibly with `python3 build_standalone.py /new/path/restoreproof.html`. Existing output files are never overwritten.

Requires a current browser with Web Crypto and folder upload support. No accounts, installs, API keys or paid service.

```sh
python3 -m http.server 8765 --bind 127.0.0.1 --directory web
```

Open `http://127.0.0.1:8765`. Choose a source folder, export its snapshot somewhere separate, then choose the restored folder and verify. Or use the labeled synthetic broken/repaired demos. The page has no analytics or upload endpoint; its content security policy forbids network connections. Selected files and results live only in tab memory until the user downloads a report. Closing or resetting clears app state; this does not erase browser caches or disk copies.

Browser limits: 64 MiB per file, 256 MiB total, 10,000 files. The browser hashes each selected file's entire bytes using SHA-256, one file at a time. A folder picker may omit empty/hidden directories or dereference links, so a browser pass covers selected file bytes, not the whole filesystem. The CLI exposes excluded entries and streams larger files.

## Streaming CLI

Python 3.9+; standard library only. Use explicit non-sensitive test folders. Source media is never changed.

```sh
python3 restoreproof.py snapshot /path/to/source /separate/path/snapshot.json
python3 restoreproof.py verify /separate/path/snapshot.json /path/to/restored --output /separate/path/report.json
```

Outputs refuse overwrite. Exit 0 = selected bytes match; 1 = differences or incomplete inspection; 2 = invalid input/read error. Snapshot generation refuses incomplete coverage and empty file sets. CLI skips symlinks, hidden entries, common secret filenames and special files, recording incomplete coverage rather than silently passing. Do not run against actively changing trees: the scanner rejects observed file mutations but is not an atomic filesystem snapshot and does not protect against hostile concurrent directory replacement. It is a personal verification tool, not a sandbox.

## What is and is not proved

Missing, changed and unexpected paths are separate outcomes; same-size corruption is detected. Evidence includes byte counts and expected/observed SHA-256 values. A file-read error blocks a pass. A manifest is an untrusted input and is validated before use.

The reference manifest must already be trusted. If an attacker replaces both the files and the manifest, this tool cannot authenticate them. Byte equality does not prove absence of malware, preservation of permissions/extended attributes, backup independence, cloud durability, hardware health or successful application recovery. Filesystem metadata, empty directories and application dependencies are outside scope. Filename-only inventory is an intentionally weaker comparison, not a claimed replacement for restic or rclone.

## Tests

```sh
python3 -m unittest -v test_restoreproof.py
python3 -m unittest -v test_standalone.py
node test_engine.mjs
```

Synthetic fixtures only. No user media, credentials, external accounts or live backup deletion are involved.

## Provenance

New prototype authored with Codex assistance on 2026-10-19 for consideration under SafeSpace Hacks. Codex generated implementation, tests and documentation; Image Gen generated a visual reference, not the functioning UI. No user testing, field deployment, time savings or win is claimed. No prior contest project code was copied. Only standard-library/browser APIs are used. The reference image is review material and is not required by the application.

Local preparation is not Devpost registration, publication or final submission. Current participant facts, exact final terms, complete historical dedupe and the single final sender's submission checks remain separate.
