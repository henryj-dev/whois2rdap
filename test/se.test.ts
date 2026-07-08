import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parseSeWhois, seWhoisToRdap, whoisToRdap } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(resolve(here, "fixtures/se-tinyuniver.txt"), "utf8");

describe("parseSeWhois", () => {
  const data = parseSeWhois(fixture);

  it("extracts domain, dates, registrar and status", () => {
    expect(data.domain).toBe("tinyuniver.se");
    expect(data.registeredDate).toBe("2025-02-27T00:00:00Z");
    expect(data.lastUpdatedDate).toBe("2026-02-25T00:00:00Z");
    expect(data.expirationDate).toBe("2027-02-27T00:00:00Z");
    expect(data.registrar).toBe("1 Api GmbH");
    expect(data.status).toEqual(["active"]);
    expect(data.dnssec).toBe("signed delegation");
  });

  it("extracts nameservers", () => {
    expect(data.nameservers.map((n) => n.host)).toEqual([
      "cody.ns.cloudflare.com",
      "gabriella.ns.cloudflare.com",
    ]);
  });

  it("omits the GDPR-redacted holder", () => {
    expect(data.holder).toBeUndefined();
  });
});

describe("seWhoisToRdap", () => {
  const rdap = seWhoisToRdap(fixture, { sourceServer: "whois.iis.se" });

  it("produces an RDAP domain object", () => {
    expect(rdap.objectClassName).toBe("domain");
    expect(rdap.ldhName).toBe("tinyuniver.se");
    expect(rdap.port43).toBe("whois.iis.se");
  });

  it("maps events (registration/last changed/expiration)", () => {
    const byAction = Object.fromEntries(
      (rdap.events ?? []).map((e) => [e.eventAction, e.eventDate]),
    );
    expect(byAction.registration).toBe("2025-02-27T00:00:00Z");
    expect(byAction["last changed"]).toBe("2026-02-25T00:00:00Z");
    expect(byAction.expiration).toBe("2027-02-27T00:00:00Z");
  });

  it("emits the registrar entity", () => {
    const registrar = (rdap.entities ?? []).find((e) => e.roles?.includes("registrar"));
    expect(registrar).toBeDefined();
    const fn = registrar?.vcardArray?.[1].find((p) => p[0] === "fn")?.[3];
    expect(fn).toBe("1 Api GmbH");
  });

  it("maps signed delegation to secureDNS", () => {
    expect(rdap.secureDNS).toEqual({ delegationSigned: true });
  });

  it("maps EPP status ok -> active", () => {
    expect(rdap.status).toEqual(["active"]);
  });
});

describe("whoisToRdap dispatch", () => {
  it("routes .se domains to the SE parser", () => {
    const rdap = whoisToRdap(fixture, { domain: "tinyuniver.se" });
    expect(rdap.ldhName).toBe("tinyuniver.se");
    expect(rdap.status).toEqual(["active"]);
    expect(rdap.secureDNS).toEqual({ delegationSigned: true });
  });

  it("detects the IIS banner without a domain hint", () => {
    const rdap = whoisToRdap(fixture);
    expect((rdap.entities ?? []).some((e) => e.roles?.includes("registrar"))).toBe(true);
  });

  it("maps unsigned delegation to delegationSigned false", () => {
    const unsigned = fixture.replace("signed delegation", "unsigned delegation");
    const rdap = seWhoisToRdap(unsigned, { domain: "example.se" });
    expect(rdap.secureDNS).toEqual({ delegationSigned: false });
  });
});
