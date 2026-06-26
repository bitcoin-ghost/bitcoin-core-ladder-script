#!/usr/bin/env node
// Pre-transpile the JSX in the React-in-HTML pages so PRODUCTION never loads
// Babel in the browser. Source pages (tools/<page>/index.html) keep the
// `<script type="text/babel">` + pinned Babel CDN for local authoring; this
// build emits tools/dist/ — a full mirror of tools/ with the 3 pages rewritten
// to: (a) no @babel/standalone, (b) React/ReactDOM served from same-origin
// /vendor/, (c) the JSX transpiled to plain JS inline. Deploy ships tools/dist/.
const fs = require('fs');
const path = require('path');
const babel = require('@babel/core');

const TOOLS = path.resolve(__dirname, '..');
const DIST = path.join(TOOLS, 'dist');
const PAGES = ['ladder-engine', 'qabio-playground', 'pq-batch-playground'];

// 1. Mirror tools/ -> tools/dist/ (skip dist itself + build tooling).
fs.rmSync(DIST, { recursive: true, force: true });
fs.mkdirSync(DIST, { recursive: true });
for (const entry of fs.readdirSync(TOOLS)) {
  if (entry === 'dist' || entry === 'build') continue;
  fs.cpSync(path.join(TOOLS, entry), path.join(DIST, entry), { recursive: true });
}

const BABEL_TAG = /\s*<script[^>]*@babel\/standalone[^>]*><\/script>/;
const REACT_SRC = /https:\/\/unpkg\.com\/react@[^/]+\/umd\/react\.production\.min\.js/;
const REACTDOM_SRC = /https:\/\/unpkg\.com\/react-dom@[^/]+\/umd\/react-dom\.production\.min\.js/;
const BABEL_SCRIPT = /<script type="text\/babel">([\s\S]*?)<\/script>/;

let failed = false;
for (const page of PAGES) {
  const file = path.join(DIST, page, 'index.html');
  let html = fs.readFileSync(file, 'utf8');

  const m = html.match(BABEL_SCRIPT);
  if (!m) { console.error(`✗ ${page}: no <script type="text/babel"> block`); failed = true; continue; }

  let compiled;
  try {
    compiled = babel.transformSync(m[1], {
      presets: [['@babel/preset-react', { runtime: 'classic' }]],
      // block-scoping (const/let -> var) mirrors what the in-browser Babel did
      // and is required: the engine source has a benign forward-reference that
      // relies on var hoisting (TDZ would otherwise throw). async/spread/etc.
      // stay native — modern browsers run them, so no regenerator runtime.
      plugins: ['@babel/plugin-transform-block-scoping'],
      compact: false, comments: false, babelrc: false, configFile: false,
      filename: `${page}.jsx`,
    }).code;
  } catch (e) { console.error(`✗ ${page}: transpile failed — ${e.message}`); failed = true; continue; }

  if (/<\/script>/i.test(compiled)) { console.error(`✗ ${page}: compiled output contains </script> — would break inlining`); failed = true; continue; }

  html = html.replace(BABEL_TAG, '');                               // drop Babel CDN
  html = html.replace(REACT_SRC, '/vendor/react.production.min.js'); // vendor React same-origin
  html = html.replace(REACTDOM_SRC, '/vendor/react-dom.production.min.js');
  html = html.replace(BABEL_SCRIPT, () => `<script>\n${compiled}\n</script>`);

  if (/@babel\/standalone/.test(html) || /unpkg\.com\/react/.test(html)) {
    console.error(`✗ ${page}: external React/Babel reference still present after rewrite`); failed = true; continue;
  }
  fs.writeFileSync(file, html);
  console.log(`✓ ${page}: transpiled (${(compiled.length/1024).toFixed(0)} KB JS inline), Babel removed, React vendored`);
}

if (failed) { console.error('BUILD FAILED'); process.exit(1); }
console.log(`\nBuilt to ${DIST}`);
