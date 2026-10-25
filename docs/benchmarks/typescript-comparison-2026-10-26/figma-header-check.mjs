import { createRequire } from 'node:module';
import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const require = createRequire(import.meta.url);
const { getRawHeader } = require('/Users/tihan-nico/Developer/rea-rust-ghidra-prism/node_modules/@electron/asar/lib/asar.js');
const { readAsarListing } = await import('file:///Users/tihan-nico/Developer/rea-rust-ghidra-prism/.cache/runtime-benchmark-20261024-v2/typescript/dist/artifacts/AsarListing.js');
const target = '/Applications/Figma.app/Contents/Resources/app.asar';
const targetBytes = await readFile(target);
const targetSha256 = createHash('sha256').update(targetBytes).digest('hex');
const raw = getRawHeader(target);
const root = JSON.parse(raw.headerString);
const matches = [];
function walk(files, parent='') {
  for (const [name, value] of Object.entries(files ?? {})) {
    const path = parent ? `${parent}/${name}` : name;
    if (name === '.codesign' || path.endsWith('/.codesign')) matches.push({ path, metadata: value });
    if (value && typeof value === 'object' && value.files) walk(value.files, path);
  }
}
walk(root.files);
let schemaError = null;
try { await readAsarListing(root); }
catch (error) { schemaError = { name: error?.name, message: error?.message }; }
const evidence = {
  runtime: { node: process.version, nodePath: process.execPath,
    asarModule: '/Users/tihan-nico/Developer/rea-rust-ghidra-prism/node_modules/@electron/asar/lib/asar.js',
    asarModuleSha256: createHash('sha256').update(await readFile('/Users/tihan-nico/Developer/rea-rust-ghidra-prism/node_modules/@electron/asar/lib/asar.js')).digest('hex'),
    asarListingSha256: createHash('sha256').update(await readFile('/Users/tihan-nico/Developer/rea-rust-ghidra-prism/.cache/runtime-benchmark-20261024-v2/typescript/dist/artifacts/AsarListing.js')).digest('hex') },
  target: { path: target, size: targetBytes.length, sha256: targetSha256,
    header: { headerSize: raw.headerSize, headerStringLength: raw.headerString.length, topLevelEntries: Object.keys(root.files ?? {}).length } },
  codesignEntries: matches,
  typescriptListingProjection: { result: schemaError ? 'rejected' : 'accepted', error: schemaError }
};
await writeFile('/tmp/rea-ts-figma-header-evidence-20261026.json', JSON.stringify(evidence, null, 2)+'\n');
console.log(JSON.stringify(evidence, null, 2));
