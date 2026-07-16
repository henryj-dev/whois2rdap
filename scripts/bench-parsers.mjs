#!/usr/bin/env node
/**
 * Scores the parsers against the corpus of real responses captured by
 * probe-whois-formats.mjs (.whois-probe/*.txt). No network — pure replay, so it
 * runs in a second and can drive a tight edit/measure loop.
 *
 * Requires a build first (imports ../dist): npm run build
 *
 * Usage:
 *   node scripts/bench-parsers.mjs           # summary + per-field coverage
 *   node scripts/bench-parsers.mjs -v         # list every TLD with its score
 *   node scripts/bench-parsers.mjs at be jp   # only these TLDs, verbose
 */
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { whoisToRdap } from "../dist/index.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "..", ".whois-probe");
const FIELDS = ["ldhName", "status", "registration", "expiration", "registrar", "nameservers"];

const args = process.argv.slice(2);
const verbose = args.includes("-v") || args.some((a) => a !== "-v");
const only = args.filter((a) => a !== "-v");

function score(rdap) {
  const events = new Set((rdap.events ?? []).map((e) => e.eventAction));
  const roles = new Set((rdap.entities ?? []).flatMap((e) => e.roles ?? []));
  return {
    ldhName: Boolean(rdap.ldhName),
    status: (rdap.status ?? []).length > 0,
    registration: events.has("registration"),
    expiration: events.has("expiration"),
    registrar: roles.has("registrar"),
    nameservers: (rdap.nameservers ?? []).length > 0,
  };
}

const rows = [];
for (const file of readdirSync(DIR).filter((f) => f.endsWith(".txt")).sort()) {
  const tld = file.replace(/\.txt$/, "");
  if (only.length && !only.includes(tld)) continue;
  const body = readFileSync(join(DIR, file), "utf8");
  let fields, error;
  try {
    fields = score(whoisToRdap(body, { domain: `probe.${tld}`, sourceServer: `whois.${tld}` }));
  } catch (e) {
    error = String(e);
  }
  rows.push({ tld, fields, filled: fields ? FIELDS.filter((f) => fields[f]).length : -1, error });
}

const ok = rows.filter((r) => !r.error);
const totals = Object.fromEntries(FIELDS.map((f) => [f, ok.filter((r) => r.fields[f]).length]));
const bucket = (lo, hi) => ok.filter((r) => r.filled >= lo && r.filled <= hi);

if (verbose) {
  for (const r of rows.sort((a, b) => a.filled - b.filled || a.tld.localeCompare(b.tld))) {
    if (r.error) { console.log(`  ERR  .${r.tld}  ${r.error.slice(0, 60)}`); continue; }
    const marks = FIELDS.map((f) => (r.fields[f] ? f[0].toUpperCase() : "·")).join("");
    console.log(`  ${r.filled}/6  ${marks}  .${r.tld}`);
  }
  console.log("");
}

console.log(`corpus: ${rows.length} responses  (${ok.length} parsed, ${rows.length - ok.length} threw)`);
console.log(`  5-6/6  ${bucket(5, 6).length}\n  3-4/6  ${bucket(3, 4).length}\n  1-2/6  ${bucket(1, 2).length}\n  0/6    ${bucket(0, 0).length}`);
console.log("field coverage:");
for (const f of FIELDS) {
  const n = totals[f];
  const pct = ok.length ? Math.round((n / ok.length) * 100) : 0;
  console.log(`  ${f.padEnd(13)} ${String(n).padStart(3)}/${ok.length}  ${"█".repeat(Math.round(pct / 4)).padEnd(25)} ${pct}%`);
}
const avg = ok.length ? (ok.reduce((s, r) => s + r.filled, 0) / ok.length).toFixed(2) : 0;
console.log(`mean fields/response: ${avg} / 6`);
