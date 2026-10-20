export const SCHEMA = 'restoreproof/v1';
export const MAX_FILE = 64 * 1024 * 1024;
export const MAX_TOTAL = 256 * 1024 * 1024;
export function cleanPath(path) {
  if (typeof path !== 'string' || !path || path.includes('\\') || path.startsWith('/') || /[\x00-\x1f]/.test(path) || path.split('/').some(x => !x || x === '.' || x === '..')) throw Error('Unsafe relative file path');
  return path.normalize('NFC');
}
export function validateManifest(data) {
  if (!data || data.schema !== SCHEMA || !Array.isArray(data.files) || !data.files.length || data.files.length > 10000) throw Error('Select a RestoreProof manifest with 1–10,000 files.');
  const seen = new Set();
  return data.files.map(file => {
    const path = cleanPath(file.path);
    if (seen.has(path) || !Number.isSafeInteger(file.bytes) || file.bytes < 0 || typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256)) throw Error('Manifest contains duplicate paths or invalid file evidence.');
    seen.add(path); return { path, bytes: file.bytes, sha256: file.sha256 };
  });
}
export async function sha256(buffer) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256', buffer))].map(x => x.toString(16).padStart(2, '0')).join('');
}
export async function scanFiles(input, progress = () => {}) {
  const files = [...input];
  if (!files.length) throw Error('No files selected. Empty directories cannot be verified.');
  if (files.length > 10000 || files.reduce((sum, f) => sum + f.size, 0) > MAX_TOTAL) throw Error('Browser limit: 10,000 files / 256 MiB total. Use the streaming CLI for larger copies.');
  const results = [], errors = [], seen = new Set();
  for (const [index, file] of files.entries()) {
    let path = file.webkitRelativePath ? file.webkitRelativePath.split('/').slice(1).join('/') : file.name;
    try {
      path = cleanPath(path);
      if (seen.has(path)) throw Error('Normalized path collision');
      seen.add(path);
      if (path.split('/').some(x => x.startsWith('.') || /^(credentials|secrets|id_rsa|id_ed25519)$/i.test(x))) throw Error('Private/hidden entry excluded; coverage incomplete');
      if (file.size > MAX_FILE) throw Error('File exceeds 64 MiB browser limit; use CLI');
      const bytes = await file.arrayBuffer();
      if (bytes.byteLength !== file.size) throw Error('Read was incomplete');
      results.push({path, bytes: file.size, sha256: await sha256(bytes)});
    } catch (error) { errors.push({path, error: error.message}); }
    progress(index + 1, files.length);
  }
  return {files: results.sort((a,b) => a.path.localeCompare(b.path)), errors};
}
export function compare(expected, observed, errors = []) {
  const a = new Map(expected.map(x => [x.path, x])), b = new Map(observed.map(x => [x.path, x]));
  const rows = [...new Set([...a.keys(), ...b.keys()])].sort().map(path => {
    const left = a.get(path), right = b.get(path);
    const status = !left ? 'unexpected' : !right ? 'missing' : left.bytes === right.bytes && left.sha256 === right.sha256 ? 'matched' : 'changed';
    return {path, status, expected: left ?? null, observed: right ?? null};
  });
  return {schema:'restoreproof-report/v1', status:expected.length > 0 && !errors.length && rows.every(x => x.status === 'matched') ? 'verified' : 'attention', files:rows, errors, scope:'Byte equality against the provided manifest only. Not authenticity, malware detection, metadata, empty-directory or application recovery verification.'};
}
export function demoFiles(repaired = false) {
  const original = [new File(['approved brief'], 'brief.txt'), new File(['RIFFsynthetic-audio'], 'mix.wav'), new File(['v1 release notes'], 'release-notes.txt')];
  const restored = repaired ? original.map(f => new File([f], f.name)) : [new File(['approved brief'], 'brief.txt'), new File(['RIFFsynthetic-Xudio'], 'mix.wav'), new File(['extra data'], 'extra.txt')];
  return {original, restored};
}
