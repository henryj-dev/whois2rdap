import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { whoisToRdap, parseGenericWhois, normalizeGenericStatus } from "../src/index.js";

const DIR = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "generic-formats");
const fixture = (name: string) => readFileSync(join(DIR, `${name}.txt`), "utf8");

/** eventAction → eventDate for quick assertions. */
function events(rdap: ReturnType<typeof whoisToRdap>) {
  return Object.fromEntries((rdap.events ?? []).map((e) => [e.eventAction, e.eventDate]));
}
const hasRole = (rdap: ReturnType<typeof whoisToRdap>, role: string) =>
  (rdap.entities ?? []).some((e) => (e.roles ?? []).includes(role));
const nsHosts = (rdap: ReturnType<typeof whoisToRdap>) =>
  (rdap.nameservers ?? []).map((n) => n.ldhName);

describe("normalizeGenericStatus", () => {
  it("maps a bare EPP status and strips the ICANN URL", () => {
    expect(normalizeGenericStatus("clientTransferProhibited https://icann.org/epp#x")).toEqual([
      "client transfer prohibited",
    ]);
  });

  it("keeps a free-text status as one phrase, not shattered words", () => {
    expect(normalizeGenericStatus("NOT AVAILABLE")).toEqual(["NOT AVAILABLE"]);
    expect(normalizeGenericStatus("Registered until cancelled")).toEqual([
      "Registered until cancelled",
    ]);
  });

  it("splits a comma-separated list", () => {
    expect(normalizeGenericStatus("busy, active")).toEqual(["busy", "active"]);
  });

  it("expands a space-separated EPP list", () => {
    expect(normalizeGenericStatus("clientHold clientTransferProhibited")).toEqual([
      "client hold",
      "client transfer prohibited",
    ]);
  });
});

describe("dot-padded keys (.ax/.kz/.tn)", () => {
  it("reads keys padded out with dots", () => {
    const rdap = whoisToRdap(fixture("ax-dotpad"), { domain: "nic.ax" });
    expect(rdap.status).toContain("Registered");
    expect(events(rdap).registration).toBe("2016-09-05T00:00:00Z");
    expect(events(rdap).expiration).toBe("2026-09-05T00:00:00Z");
  });
});

describe("multilingual labels (.ga French)", () => {
  it("reads 'Nom de domaine' / 'Date de création'", () => {
    const data = parseGenericWhois(fixture("ga-french"));
    expect(data.domain).toBe("nic.ga");
    expect(data.registeredDate).toBe("2023-06-05T00:00:00Z");
    expect(data.registrar).toBeTruthy();
  });
});

describe("block format (.eu EURid)", () => {
  const rdap = whoisToRdap(fixture("eu-block"), { domain: "europa.eu" });

  it("collects nameservers from the indented block", () => {
    expect(nsHosts(rdap)).toContain("ns1bru.europa.eu");
  });

  it("takes the registrar name from the nested 'Name:' sub-field", () => {
    expect(hasRole(rdap, "registrar")).toBe(true);
  });

  it("routes the DNSKEY 'Keys:' block to DNSSEC, not status", () => {
    // Regression: "flags:KSK protocol:3 pubKey:…" used to land in status.
    expect(rdap.secureDNS).toEqual({ delegationSigned: true });
    expect(rdap.status ?? []).not.toContain("KSK");
    expect((rdap.status ?? []).some((s) => /pubKey|protocol:/i.test(s))).toBe(false);
  });
});

describe("block format (.be DNS Belgium)", () => {
  const rdap = whoisToRdap(fixture("be-block"), { domain: "nic.be" });

  it("parses a weekday date (Wed Apr 1 1998)", () => {
    expect(events(rdap).registration).toBe("1998-04-01T00:00:00Z");
  });

  it("maps the EPP flag from the 'Flags:' block", () => {
    expect(rdap.status).toContain("client transfer prohibited");
  });

  it("collects nameservers", () => {
    expect(nsHosts(rdap)).toEqual(expect.arrayContaining(["ns3.combell.net", "ns4.combell.net"]));
  });
});

describe("UK ordinal dates (.gg CentralNic)", () => {
  it("parses 'Registered on 24th April 1997'", () => {
    const rdap = whoisToRdap(fixture("gg-uk-dates"), { domain: "nic.gg" });
    expect(events(rdap).registration).toBe("1997-04-24T00:00:00Z");
    expect(nsHosts(rdap)).toContain("ns1.livedns.co.uk");
  });
});

describe("date embedded in key (.mo)", () => {
  it("reads 'Record created on <date>' despite the time's colons", () => {
    // The FIELD split breaks on the time's colon; the parser must re-read the
    // whole line as a date phrase.
    const data = parseGenericWhois(fixture("mo-date-in-key"));
    expect(data.registeredDate).toBe("1993-01-01T08:00:00Z");
  });
});

describe("bullet-prefixed keys and YYYY-Mon-DD dates (.tr TRABIS)", () => {
  it("strips the '**' bullet and parses '2024-Aug-26'", () => {
    const rdap = whoisToRdap(fixture("tr-bullet"), { domain: "google.tr" });
    expect(rdap.status).toContain("active");
    expect(events(rdap).registration).toBe("2024-08-26T00:00:00Z");
    expect(events(rdap).expiration).toBe("2026-08-25T00:00:00Z");
  });
});

describe("RIPE block style (.at)", () => {
  it("collects nserver: fields", () => {
    const rdap = whoisToRdap(fixture("at-ripe"), { domain: "nic.at" });
    expect(nsHosts(rdap)).toContain("ns1.nic.at");
  });
});
