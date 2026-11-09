#!/usr/bin/env node
// Checks the Feature-Sliced Design rules of the UI (see ../ARCHITECTURE.md):
//   node app/ui/tools/check-imports.mjs
// - a layer imports only from the layers below it;
// - slices of one layer do not import each other;
// - another slice is imported only through its public index.js;
// - every slice has an index.js;
// - only relative imports (no npm), and the Tauri globals only in shared/api.
// Exits with 1 and the list of violations.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LAYERS = ["shared", "entities", "features", "widgets", "pages", "app"];
// Layers without slices: their files may import each other freely.
const FLAT = new Set(["app"]);

const rel = (p) => path.relative(ROOT, p).split(path.sep).join("/");

function walk(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== "tools" && e.name !== "node_modules") walk(p, out);
    } else if (e.name.endsWith(".js") || e.name.endsWith(".mjs")) out.push(p);
  }
  return out;
}

// "features/ping/index.js" -> { layer: "features", slice: "features/ping" }
function place(file) {
  const parts = rel(file).split("/");
  const layer = parts[0];
  if (!LAYERS.includes(layer)) return { layer: null, slice: null };
  if (FLAT.has(layer) || parts.length < 3) return { layer, slice: layer };
  return { layer, slice: `${parts[0]}/${parts[1]}` };
}

const IMPORT_RE = /(?:^|[\s;])(?:import|export)\s*(?:[\w$*{}\s,]*?\s*from\s*)?["']([^"']+)["']|import\(\s*["']([^"']+)["']\s*\)/g;

const errors = [];
const files = walk(ROOT);
const slices = new Set();

for (const file of files) {
  const src = fs.readFileSync(file, "utf8");
  const from = place(file);
  const name = rel(file);
  if (!from.layer) {
    errors.push(`${name}: outside the layers (${LAYERS.join(", ")})`);
    continue;
  }
  if (from.slice !== from.layer) slices.add(from.slice);
  if (/__TAURI__/.test(src) && !name.startsWith("shared/api/")) {
    errors.push(`${name}: Tauri globals outside shared/api`);
  }
  for (const m of src.matchAll(IMPORT_RE)) {
    const spec = m[1] || m[2];
    if (!spec.startsWith(".")) {
      errors.push(`${name}: "${spec}" is not a relative import`);
      continue;
    }
    const target = path.resolve(path.dirname(file), spec);
    const to = place(target);
    const tname = rel(target);
    if (!fs.existsSync(target)) errors.push(`${name}: "${spec}" does not exist`);
    if (!to.layer) {
      errors.push(`${name}: "${spec}" is outside the layers`);
      continue;
    }
    if (from.slice === to.slice) continue;
    const up = LAYERS.indexOf(to.layer) > LAYERS.indexOf(from.layer);
    if (up) {
      errors.push(`${name}: imports "${tname}" from the higher layer ${to.layer}`);
    } else if (to.layer === from.layer && to.layer !== "shared") {
      errors.push(`${name}: imports "${tname}" from another slice of ${to.layer}`);
    } else if (tname !== `${to.slice}/index.js`) {
      errors.push(`${name}: imports "${tname}" past the public ${to.slice}/index.js`);
    }
  }
}

for (const s of slices) {
  if (!fs.existsSync(path.join(ROOT, s, "index.js"))) errors.push(`${s}: no public index.js`);
}

if (errors.length) {
  console.error(errors.join("\n"));
  console.error(`\n${errors.length} violation(s) of the FSD import rules`);
  process.exit(1);
}
console.log(`FSD imports OK: ${files.length} files, ${slices.size} slices`);
