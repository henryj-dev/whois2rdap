#!/usr/bin/env node
/**
 * Probes every WHOIS-only TLD with a real apex domain and reports how well the
 * bundled parsers cope with what actually comes back.
 *
 * Two ideas keep this cheap:
 *
 *   1. TLDs share servers. ~179 WHOIS-only TLDs sit behind ~132 distinct hosts
 *      (India's 15 IDN TLDs all answer from whois.nixiregistry.in). A server
 *      speaks one format, so one query per *server* covers every TLD on it.
 *   2. The apex is enough. A registry's own domain — nic.<tld>, or the whois
 *      host minus its "whois." prefix — is registered almost everywhere, so a
 *      short candidate ladder finds a live record without hand-curating 132
 *      entries. scripts/representative-domains.json covers the rest.
 *
 * Classifying the response matters as much as fetching it — a thin result can
 * mean the server blocked us (.ch), the name we picked is unregistered (nic.om
 * is reserved), or the parser fell short, and only the last is a parser
 * problem. That logic lives in src/whois-response.ts, so this probe and
 * lookupRdap judge responses identically.
 *
 * Requires a build first (imports ../dist): npm run build
 *
 * Usage:
 *   node scripts/probe-whois-formats.mjs            # every distinct server
 *   node scripts/probe-whois-formats.mjs se kr cn   # only these TLDs
 */
import { createConnection } from "node:net";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  WHOIS_AVAILABILITY,
  classifyWhoisResponse,
  loadIanaRdapBootstrap,
  loadIanaTlds,
  whoisResponseHint,
  whoisToRdap,
} from "../dist/index.js";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = join(ROOT, ".whois-probe");
const CONCURRENCY = 8;
const TIMEOUT_MS = 20_000;

const REPRESENTATIVE = JSON.parse(
  readFileSync(join(ROOT, "scripts", "representative-domains.json"), "utf8"),
);


// ── plumbing ────────────────────────────────────────────────────────────────

function whoisAsk(host, query) {
  return new Promise((resolve) => {
    let body = "";
    const socket = createConnection({ host, port: 43 }, () => socket.write(`${query}\r\n`));
    socket.setTimeout(TIMEOUT_MS, () => {
      socket.destroy();
      resolve({ error: "timeout" });
    });
    socket.on("data", (d) => (body += d));
    socket.on("end", () => resolve({ body }));
    socket.on("error", (e) => resolve({ error: e.code ?? String(e) }));
  });
}

async function ianaWhoisServer(tld) {
  const { body } = await whoisAsk("whois.iana.org", tld);
  return body?.match(/^whois:[ \t]*(\S+)[ \t]*\r?$/im)?.[1]?.toLowerCase();
}

async function mapAll(items, fn, limit = CONCURRENCY) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i], i);
      }
    }),
  );
  return out;
}

// ── domain candidates ───────────────────────────────────────────────────────

/** Apex domains to try for a TLD, best guess first. */
function candidates(tld, server) {
  const out = [];
  if (REPRESENTATIVE[tld]) out.push(REPRESENTATIVE[tld]);
  out.push(`nic.${tld}`);
  const stripped = server.replace(/^whois[0-9]*\./, "");
  if (stripped.endsWith(`.${tld}`) && stripped.split(".").length === 2) out.push(stripped);
  out.push(`google.${tld}`);
  return [...new Set(out)];
}

/** The TLD that best represents a group sharing one server: prefer ASCII, then short. */
function representativeTld(tlds) {
  return [...tlds].sort((a, b) => {
    const ai = a.startsWith("xn--") ? 1 : 0;
    const bi = b.startsWith("xn--") ? 1 : 0;
    return ai - bi || a.length - b.length || a.localeCompare(b);
  })[0];
}

// ── scoring ─────────────────────────────────────────────────────────────────

const FIELDS = ["ldhName", "status", "registration", "expiration", "registrar", "nameservers"];

/** Which core RDAP fields the parser managed to fill from this response. */
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

// ── main ────────────────────────────────────────────────────────────────────

const only = process.argv.slice(2).map((s) => s.toLowerCase());

console.error("discovering WHOIS servers…");
const [tlds, bootstrap] = await Promise.all([loadIanaTlds(), loadIanaRdapBootstrap()]);
const whoisOnly = [...tlds].filter((t) => !bootstrap.has(t));

const discovered = (
  await mapAll(whoisOnly, async (tld) => {
    const fromIana = await ianaWhoisServer(tld);
    if (fromIana) return { tld, server: fromIana };
    const entry = WHOIS_AVAILABILITY[tld];
    return entry?.kind === "server" ? { tld, server: entry.host } : null;
  })
).filter(Boolean);

// One representative per distinct server — the whole point of the exercise.
const byServer = new Map();
for (const d of discovered) {
  if (!byServer.has(d.server)) byServer.set(d.server, []);
  byServer.get(d.server).push(d.tld);
}

let groups = [...byServer].map(([server, tlds]) => ({
  server,
  tlds: tlds.sort(),
  tld: representativeTld(tlds),
}));
if (only.length) groups = groups.filter((g) => g.tlds.some((t) => only.includes(t)));

console.error(
  `${discovered.length} WHOIS-only TLDs → ${groups.length} distinct servers to probe\n`,
);

mkdirSync(OUT_DIR, { recursive: true });

/**
 * Domains to try for a server, best first. When the representative TLD has no
 * live apex, fall through to its siblings on the same server — .xn--2scrj9c has
 * nothing registered under nic./google., but its 14 co-tenants on
 * whois.nixiregistry.in do. Capped so a 15-TLD group cannot fan out unbounded.
 */
function groupCandidates(g, cap = 6) {
  const order = [g.tld, ...g.tlds.filter((t) => t !== g.tld)];
  const out = [];
  for (const tld of order) {
    for (const d of candidates(tld, g.server)) if (!out.includes(d)) out.push(d);
    if (out.length >= cap) break;
  }
  return out.slice(0, cap);
}

const results = await mapAll(groups, async (g) => {
  const tried = [];
  for (const domain of groupCandidates(g)) {
    const { body, error } = await whoisAsk(g.server, domain);
    tried.push(domain);
    if (error) return { ...g, domain, outcome: "unreachable", detail: error, tried };
    if (!body?.trim()) return { ...g, domain, outcome: "empty", tried };

    const verdict = classifyWhoisResponse(body, domain);
    if (verdict === "not-found") continue; // the name is free — try the next candidate
    writeFileSync(join(OUT_DIR, `${g.tld}.txt`), body);
    if (verdict === "refused" || verdict === "unknown") {
      return { ...g, domain, outcome: verdict, tried, hint: whoisResponseHint(body) };
    }
    let rdap;
    try {
      rdap = whoisToRdap(body, { domain, sourceServer: g.server });
    } catch (e) {
      return { ...g, domain, outcome: "parse-threw", detail: String(e), tried };
    }
    const fields = score(rdap);
    return {
      ...g,
      domain,
      outcome: "parsed",
      fields,
      filled: FIELDS.filter((f) => fields[f]).length,
      bytes: body.length,
      tried,
    };
  }
  return { ...g, outcome: "not-found", tried };
});

writeFileSync(join(OUT_DIR, "report.json"), JSON.stringify(results, null, 1));

// ── report ──────────────────────────────────────────────────────────────────

const by = (o) => results.filter((r) => r.outcome === o);
const parsed = by("parsed");
const tldsOf = (rs) => rs.reduce((n, r) => n + r.tlds.length, 0);

console.log("=== 서버별 조회 결과 ===");
for (const outcome of ["parsed", "refused", "unknown", "not-found", "unreachable", "empty", "parse-threw"]) {
  const rs = by(outcome);
  if (rs.length)
    console.log(`  ${outcome.padEnd(13)} 서버 ${String(rs.length).padStart(3)}  (TLD ${tldsOf(rs)})`);
}

console.log(`\n=== 파싱된 ${parsed.length}개 응답의 필드 추출률 ===`);
for (const f of FIELDS) {
  const n = parsed.filter((r) => r.fields[f]).length;
  const pct = parsed.length ? Math.round((n / parsed.length) * 100) : 0;
  console.log(
    `  ${f.padEnd(13)} ${String(n).padStart(3)}/${parsed.length}  ${"█".repeat(Math.round(pct / 4)).padEnd(25)} ${pct}%`,
  );
}

const bucket = (lo, hi) => parsed.filter((r) => r.filled >= lo && r.filled <= hi);
console.log("\n=== 파싱 품질 분포 (핵심 6필드 기준) ===");
console.log(`  5-6/6 (양호)   서버 ${String(bucket(5, 6).length).padStart(3)}  TLD ${tldsOf(bucket(5, 6))}`);
console.log(`  3-4/6 (부분)   서버 ${String(bucket(3, 4).length).padStart(3)}  TLD ${tldsOf(bucket(3, 4))}`);
console.log(`  1-2/6 (미흡)   서버 ${String(bucket(1, 2).length).padStart(3)}  TLD ${tldsOf(bucket(1, 2))}`);

const weak = bucket(1, 2).sort((a, b) => a.filled - b.filled || a.tld.localeCompare(b.tld));
console.log(`\n=== 전용 파서 후보 (실제 레코드를 받았지만 2필드 이하) ===`);
for (const r of weak) {
  console.log(`  ${r.filled}/6  ${r.domain.padEnd(22)} ${r.server.padEnd(28)} [${r.tlds.join(" ")}]`);
}

for (const [outcome, title] of [
  ["refused", "서버가 조회를 거부 (IP 차단/rate limit — 포맷 문제 아님)"],
  ["unknown", "응답은 왔으나 레코드로 인식 불가 (분류기 점검 필요)"],
  ["not-found", "대표 도메인 미발견 (representative-domains.json 에 추가 필요)"],
  ["unreachable", "port 43 도달 불가"],
]) {
  const rs = by(outcome);
  if (!rs.length) continue;
  console.log(`\n=== ${title}: ${rs.length}개 ===`);
  for (const r of rs) {
    const note = r.hint ? ` — ${r.hint}` : r.detail ? ` — ${r.detail}` : ` — tried: ${r.tried.join(", ")}`;
    console.log(`  ${r.tld.padEnd(16)} ${r.server.padEnd(28)}${note}`);
  }
}

console.log(`\n원문: ${OUT_DIR}/<tld>.txt   리포트: ${OUT_DIR}/report.json`);
