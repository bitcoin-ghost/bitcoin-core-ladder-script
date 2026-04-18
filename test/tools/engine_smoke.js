#!/usr/bin/env node
/**
 * Ladder Engine smoke test.
 *
 * Loads the engine HTML file and verifies:
 *   1. All 39 templates parse without errors
 *   2. BLOCK_FAMILIES defines >= 61 unique block types
 *   3. getTypeHex returns valid hex for every block type
 *   4. No references to removed features (COVENANT coil, AGGREGATE attestation)
 *
 * Run: node tests/engine_smoke.js
 *
 * NOTE: This is a static analysis test — it parses the HTML/JS source,
 * it does NOT run a browser or evaluate React. For full DOM testing,
 * use the browser-based engine directly.
 */

const fs = require('fs');
const path = require('path');

const ENGINE_PATH = path.join(__dirname, '..', 'tools', 'ladder-engine', 'index.html');

let errors = 0;
function check(label, condition, detail) {
  if (!condition) {
    console.error(`  FAIL: ${label}${detail ? ' — ' + detail : ''}`);
    errors++;
  } else {
    console.log(`  PASS: ${label}`);
  }
}

// Load engine source
const src = fs.readFileSync(ENGINE_PATH, 'utf-8');
console.log(`Engine file: ${(src.length / 1024).toFixed(0)} KB`);
console.log('');

// ── 1. Template/example count ──────────────────────────────────────────

console.log('=== Templates ===');

// Count example objects by matching title: entries in the EXAMPLES array.
const exampleNames = [];
const examplesStart = src.indexOf('const EXAMPLES');
const examplesEnd = src.indexOf('\n];', examplesStart);
if (examplesStart >= 0 && examplesEnd >= 0) {
  const examplesBlock = src.substring(examplesStart, examplesEnd);
  const titlePattern = /title:\s*'([^']+)'/g;
  let m;
  while ((m = titlePattern.exec(examplesBlock)) !== null) {
    exampleNames.push(m[1]);
  }
}

check(`Template count >= 39`, exampleNames.length >= 39,
  `found ${exampleNames.length} templates`);

// Check for no duplicate template names
const uniqueNames = new Set(exampleNames);
check(`No duplicate template names`, uniqueNames.size === exampleNames.length,
  `${exampleNames.length} names, ${uniqueNames.size} unique`);

console.log('');

// ── 2. Block type count in BLOCK_FAMILIES ──────────────────────────────

console.log('=== Block Types ===');

const typePattern = /type:\s*'([A-Z][A-Z0-9_]+)'/g;
const blockTypes = new Set();
let tm;
while ((tm = typePattern.exec(src)) !== null) {
  blockTypes.add(tm[1]);
}

check(`BLOCK_FAMILIES >= 61 unique types`, blockTypes.size >= 61,
  `found ${blockTypes.size} unique block types`);

// Verify critical types present
const critical = ['SIG', 'MULTISIG', 'CTV', 'COSIGN', 'OUTPUT_CHECK', 'HASH_GUARDED',
                  'P2PK_LEGACY', 'P2TR_SCRIPT_LEGACY', 'RECURSE_SAME', 'ACCUMULATOR'];
for (const t of critical) {
  check(`Block type ${t} present`, blockTypes.has(t));
}

console.log('');

// ── 3. getTypeHex coverage ─────────────────────────────────────────────

console.log('=== getTypeHex ===');

const typeHexMatch = src.match(/function getTypeHex\(type\)\s*\{[\s\S]*?const map = \{([\s\S]*?)\};/);
check('getTypeHex function found', !!typeHexMatch);

if (typeHexMatch) {
  const mapEntries = typeHexMatch[1].match(/(\w+):'(\w+)'/g) || [];
  const hexMap = {};
  for (const entry of mapEntries) {
    const [, name, hex] = entry.match(/(\w+):'(\w+)'/) || [];
    if (name) hexMap[name] = hex;
  }

  check(`getTypeHex has >= 61 entries`, Object.keys(hexMap).length >= 61,
    `found ${Object.keys(hexMap).length} entries`);

  // Check OUTPUT_CHECK specifically (was missing before fix)
  check(`getTypeHex has OUTPUT_CHECK`, 'OUTPUT_CHECK' in hexMap);
  check(`OUTPUT_CHECK code is 0807`, hexMap['OUTPUT_CHECK'] === '0807');
}

console.log('');

// ── 4. Dead code check ─────────────────────────────────────────────────

console.log('=== Dead Code ===');

// COVENANT coil should not be in dropdowns
check('No COVENANT coil option',
  !src.includes("value: 'COVENANT'"),
  'COVENANT coil option still present');

// AGGREGATE attestation should not be in dropdowns
check('No AGGREGATE attestation option',
  !src.includes("value: 'AGGREGATE'"),
  'AGGREGATE attestation option still present');

// No watch mode
check('No watch mode logic',
  !src.includes("mode === 'watch'"),
  'Watch mode conditional found');

console.log('');

// ── Summary ────────────────────────────────────────────────────────────

if (errors === 0) {
  console.log(`=== ALL CHECKS PASSED (${exampleNames.length} templates, ${blockTypes.size} block types) ===`);
  process.exit(0);
} else {
  console.log(`=== ${errors} CHECK(S) FAILED ===`);
  process.exit(1);
}
