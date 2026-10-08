#!/usr/bin/env node
// Adds the component surface to the wasm-pack output in pkg/: copies
// dist/pqc-subtle.wasm, the WIT package, and component/index.{js,d.ts} into
// pkg/component/, and extends pkg/package.json with the `./component` export
// and a `component` manifest that consuming build tools read to compose it.
//
//   make component && wasm-pack build --target web --release
//   node scripts/package-component.mjs
import { cpSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = join(root, 'pkg');
const wasm = join(root, 'dist', 'pqc-subtle.wasm');
for (const required of [join(pkg, 'package.json'), wasm, join(root, 'wit', 'world.wit')]) {
  if (!existsSync(required)) {
    console.error(`package-component: missing ${required}`);
    process.exit(1);
  }
}

const out = join(pkg, 'component');
mkdirSync(join(out, 'wit'), { recursive: true });
cpSync(wasm, join(out, 'pqc-subtle.wasm'));
cpSync(join(root, 'wit', 'world.wit'), join(out, 'wit', 'world.wit'));
cpSync(join(root, 'component', 'index.js'), join(out, 'index.js'));
cpSync(join(root, 'component', 'index.d.ts'), join(out, 'index.d.ts'));

const manifestPath = join(pkg, 'package.json');
const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
const main = manifest.main ?? 'wasm_pqc_subtle.js';
const types = manifest.types ?? 'wasm_pqc_subtle.d.ts';
manifest.exports = {
  '.': { types: `./${types}`, default: `./${main}` },
  './component': { types: './component/index.d.ts', default: './component/index.js' },
  './component/pqc-subtle.wasm': './component/pqc-subtle.wasm',
  './component/wit/world.wit': './component/wit/world.wit',
  './package.json': './package.json',
};
// Read by build tools that compose components (for example di-framework's
// platform CLI plugin): the provider binary, its WIT package directory, and the
// WIT package name whose interfaces `./component` imports.
manifest.component = {
  package: 'pqc-subtle:crypto@0.1.0',
  wasm: 'component/pqc-subtle.wasm',
  wit: 'component/wit',
  world: 'pqc-subtle',
  interfaces: ['ml-kem', 'ml-dsa', 'argon2'],
};
manifest.files = [
  ...new Set([...(manifest.files ?? []), 'component/']),
];
writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`package-component: added ./component to ${manifestPath}`);
