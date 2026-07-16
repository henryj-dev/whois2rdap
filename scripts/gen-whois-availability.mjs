#!/usr/bin/env node
/**
 * Regenerates src/whois-availability.ts.
 *
 * The IANA root database is authoritative when it lists a WHOIS server, but it
 * leaves the `whois:` field blank for many TLDs — including some that do run a
 * server. This script records what to do for those blanks, merging:
 *
 *   1. IANA root DB (whois.iana.org)      — which TLDs have no `whois:` value
 *   2. rfc1036/whois `tld_serv_list`      — NONE / WEB / server classification
 *   3. VERIFIED_OVERRIDES below           — cases where (2) disagrees with reality
 *
 * TLDs in the RDAP bootstrap are skipped: the RDAP path handles them, so they
 * never reach the WHOIS fallback this table serves.
 *
 * Usage: node scripts/gen-whois-availability.mjs
 */
import { createConnection } from "node:net";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const TLD_LIST_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";
const RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";
const TLD_SERV_LIST_URL = "https://raw.githubusercontent.com/rfc1036/whois/next/tld_serv_list";

const OUT = join(dirname(fileURLToPath(import.meta.url)), "..", "src", "whois-availability.ts");

/**
 * Entries where tld_serv_list is contradicted by a live port-43 probe.
 * Re-verify with: printf 'nic.ps\r\n' | nc whois.registry.ps 43
 */
const VERIFIED_OVERRIDES = {
  // tld_serv_list says "WEB https://www.pnina.ps/", but the port-43 server
  // answers with a normal WHOIS record. Verified 2026-07-16.
  ps: { kind: "server", host: "whois.registry.ps" },
};

function whoisAsk(host, query, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    let body = "";
    const socket = createConnection({ host, port: 43 }, () => socket.write(`${query}\r\n`));
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      resolve(null);
    });
    socket.on("data", (d) => (body += d));
    socket.on("end", () => resolve(body));
    socket.on("error", () => resolve(null));
  });
}

/** The `whois:` value for a TLD, or null when IANA leaves it blank. */
async function ianaWhoisServer(tld) {
  for (let attempt = 1; attempt <= 3; attempt++) {
    const body = await whoisAsk("whois.iana.org", tld);
    if (body !== null) {
      // Anchored to the same line: a blank `whois:` field must not swallow the
      // newline and capture the next line's value.
      const m = body.match(/^whois:[ \t]*(\S+)[ \t]*\r?$/im);
      return m ? m[1].toLowerCase() : null;
    }
    await new Promise((r) => setTimeout(r, 1000 * attempt));
  }
  throw new Error(`whois.iana.org unreachable for "${tld}"`);
}

function parseTldServList(text) {
  const top = new Map();
  for (const line of text.split("\n")) {
    const l = line.replace(/#.*$/, "").trim();
    if (!l.startsWith(".")) continue;
    const [key, ...rest] = l.split(/\s+/);
    const name = key.slice(1).toLowerCase();
    if (name.includes(".")) continue; // second-level entries (co.za …) are out of scope
    const value = rest.join(" ");
    if (!value) continue;
    if (value === "NONE") top.set(name, { kind: "none" });
    else if (value.startsWith("WEB ")) top.set(name, { kind: "web", url: value.slice(4).trim() });
    else if (value.startsWith("RECURSIVE ")) top.set(name, { kind: "server", host: value.slice(10).trim() });
    else if (/^[a-z0-9.-]+$/i.test(value)) top.set(name, { kind: "server", host: value.toLowerCase() });
    // VERISIGN / ARPA / other markers imply a working server discoverable via IANA.
  }
  return top;
}

const text = async (url) => {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return res.text();
};

const [tldText, bootstrapText, servListText] = await Promise.all([
  text(TLD_LIST_URL),
  text(RDAP_BOOTSTRAP_URL),
  text(TLD_SERV_LIST_URL),
]);

const version = tldText.split("\n")[0].trim();
const tlds = tldText
  .split("\n")
  .filter((l) => l && !l.startsWith("#"))
  .map((l) => l.trim().toLowerCase())
  .filter(Boolean);

const bootstrap = JSON.parse(bootstrapText);
const rdapTlds = new Set();
for (const [keys] of bootstrap.services ?? []) {
  for (const k of keys) if (typeof k === "string") rdapTlds.add(k.toLowerCase());
}

const servList = parseTldServList(servListText);
const candidates = tlds.filter((t) => !rdapTlds.has(t));
console.error(`TLDs: ${tlds.length} | RDAP: ${tlds.length - candidates.length} | probing ${candidates.length}`);

const table = {};
const stats = { server: 0, none: 0, web: 0, unclassified: [] };

for (let i = 0; i < candidates.length; i += 5) {
  const batch = candidates.slice(i, i + 5);
  const found = await Promise.all(batch.map(ianaWhoisServer));
  batch.forEach((tld, n) => {
    if (found[n]) return; // IANA has a server — discovery handles it, no entry needed.
    const entry = VERIFIED_OVERRIDES[tld] ?? servList.get(tld);
    if (!entry) {
      stats.unclassified.push(tld);
      return;
    }
    table[tld] = entry;
    stats[entry.kind]++;
  });
  process.stderr.write(".");
}
process.stderr.write("\n");

const body = Object.keys(table)
  .sort()
  .map((tld) => {
    const e = table[tld];
    const val =
      e.kind === "server"
        ? `{ kind: "server", host: ${JSON.stringify(e.host)} }`
        : e.kind === "web"
          ? `{ kind: "web", url: ${JSON.stringify(e.url)} }`
          : `{ kind: "none" }`;
    return `  ${/^[a-z][a-z0-9]*$/.test(tld) ? tld : JSON.stringify(tld)}: ${val},`;
  })
  .join("\n");

writeFileSync(
  OUT,
  `// Generated by scripts/gen-whois-availability.mjs — do not edit by hand.
// IANA TLD list: ${version}
// RDAP bootstrap publication: ${bootstrap.publication ?? "unknown"}
//
// Only TLDs that IANA leaves without a \`whois:\` value appear here. IANA stays
// authoritative: consult this table only after IANA discovery comes back empty.

/** What a TLD offers when the IANA root database lists no WHOIS server. */
export type WhoisAvailability =
  /** A port-43 server IANA does not advertise. */
  | { kind: "server"; host: string }
  /** The registry publishes no WHOIS at all — permanent, do not retry. */
  | { kind: "none" }
  /** WHOIS exists only as a web form; there is nothing to query on port 43. */
  | { kind: "web"; url: string };

export const WHOIS_AVAILABILITY: Readonly<Record<string, WhoisAvailability>> = {
${body}
};

/** The fallback entry for a TLD, or undefined when nothing is known about it. */
export function whoisAvailabilityForTld(tld: string): WhoisAvailability | undefined {
  return WHOIS_AVAILABILITY[tld.toLowerCase()];
}
`,
);

console.error(
  `wrote ${OUT}\n  server: ${stats.server}  none: ${stats.none}  web: ${stats.web}` +
    `\n  unclassified (omitted): ${stats.unclassified.length}${stats.unclassified.length ? ` — ${stats.unclassified.join(" ")}` : ""}`,
);
