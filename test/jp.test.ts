import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { whoisToRdap, parseJpWhois } from "../src/index.js";

const FIXTURE = join(
  dirname(fileURLToPath(import.meta.url)),
  "fixtures",
  "generic-formats",
  "jp-jprs.txt",
);
const jp = readFileSync(FIXTURE, "utf8");

describe("parseJpWhois (JPRS bracket format)", () => {
  const data = parseJpWhois(jp);

  it("reads the bracketed domain name", () => {
    expect(data.domain).toBe("jprs.jp");
  });

  it("reads dates whose keys are only in Japanese", () => {
    // [登録年月日] / [有効期限] have no English equivalent in the record — an
    // English-only key map would miss every date.
    expect(data.registeredDate).toBe("2001-02-02T00:00:00Z");
    expect(data.expirationDate).toBe("2027-02-28T00:00:00Z");
    expect(data.lastUpdatedDate).toBe("2026-03-01T00:00:00Z");
  });

  it("reads the status from [状態]", () => {
    expect(data.status).toContain("active");
  });

  it("collects every [Name Server] line", () => {
    expect(data.nameservers).toEqual(["ns1.jprs.jp", "ns2.jprs.jp", "ns3.jprs.jp", "ns4.jprs.jp"]);
  });

  it("treats a [Signing Key] as a signed delegation", () => {
    expect(data.dnssec).toBe("signed");
  });
});

describe("whoisToRdap JPRS dispatch", () => {
  it("routes a .jp domain to the JPRS parser", () => {
    const rdap = whoisToRdap(jp, { domain: "jprs.jp" });
    expect(rdap.ldhName).toBe("jprs.jp");
    expect(rdap.secureDNS).toEqual({ delegationSigned: true });
    expect((rdap.events ?? []).map((e) => e.eventAction)).toEqual(
      expect.arrayContaining(["registration", "expiration"]),
    );
  });

  it("routes on the JPRS banner even without a .jp domain hint", () => {
    const rdap = whoisToRdap(jp);
    expect(rdap.nameservers?.length).toBe(4);
  });
});
