import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { krWhoisToRdap, parseKrWhois, whoisToRdap } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(resolve(here, "fixtures/kr-naver.txt"), "utf8");
const oupFixture = readFileSync(resolve(here, "fixtures/kr-oup.txt"), "utf8");

describe("parseKrWhois", () => {
  const data = parseKrWhois(fixture);

  it("extracts domain and dates from the English section", () => {
    expect(data.domain).toBe("naver.kr");
    expect(data.registeredDate).toBe("2007-03-02T00:00:00+09:00");
    expect(data.lastUpdatedDate).toBe("2024-02-14T00:00:00+09:00");
    expect(data.expirationDate).toBe("2026-03-02T00:00:00+09:00");
  });

  it("extracts registrant, admin, and registrar", () => {
    expect(data.registrant).toBe("NAVER Corp.");
    expect(data.registrantZip).toBe("13561");
    expect(data.adminEmail).toBe("dnsmaster@navercorp.com");
    expect(data.adminPhone).toBe("1588-3820");
    expect(data.registrar).toBe("Gabia, Inc.(http://www.gabia.com)");
  });

  it("extracts both nameservers with IPs", () => {
    expect(data.nameservers).toEqual([
      { host: "ns1.naver.com", ip: "125.209.234.151" },
      { host: "ns2.naver.com", ip: "125.209.234.152" },
    ]);
  });

  it("extracts DNSSEC status", () => {
    expect(data.dnssec).toBe("unsigned");
  });
});

describe("krWhoisToRdap", () => {
  const rdap = krWhoisToRdap(fixture);

  it("produces an RDAP domain object", () => {
    expect(rdap.objectClassName).toBe("domain");
    expect(rdap.ldhName).toBe("naver.kr");
    expect(rdap.rdapConformance).toEqual(["rdap_level_0"]);
  });

  it("maps events with KST offset", () => {
    expect(rdap.events).toEqual([
      { eventAction: "registration", eventDate: "2007-03-02T00:00:00+09:00" },
      { eventAction: "last changed", eventDate: "2024-02-14T00:00:00+09:00" },
      { eventAction: "expiration", eventDate: "2026-03-02T00:00:00+09:00" },
    ]);
  });

  it("maps nameservers to RDAP form with IPv4 addresses", () => {
    expect(rdap.nameservers).toEqual([
      {
        objectClassName: "nameserver",
        ldhName: "ns1.naver.com",
        ipAddresses: { v4: ["125.209.234.151"] },
      },
      {
        objectClassName: "nameserver",
        ldhName: "ns2.naver.com",
        ipAddresses: { v4: ["125.209.234.152"] },
      },
    ]);
  });

  it("emits registrant, administrative, and registrar entities", () => {
    const roles = rdap.entities?.map((e) => e.roles?.[0]);
    expect(roles).toEqual(["registrant", "administrative", "registrar"]);
  });

  it("marks DNSSEC as unsigned", () => {
    expect(rdap.secureDNS).toEqual({ delegationSigned: false });
  });

  it("honours sourceServer when called directly", () => {
    const r = krWhoisToRdap(fixture, { sourceServer: "whois.kr" });
    expect(r.port43).toBe("whois.kr");
    expect(r.notices?.some((n) => n.title === "Source")).toBe(true);
  });
});

describe("whoisToRdap dispatch", () => {
  it("routes .kr domain to the KR parser", () => {
    const rdap = whoisToRdap(fixture, { domain: "naver.kr" });
    expect(rdap.events?.length).toBe(3);
    expect(rdap.nameservers?.length).toBe(2);
  });

  it("auto-detects KR via KRNIC banner when domain is unknown", () => {
    const rdap = whoisToRdap(fixture);
    expect(rdap.ldhName).toBe("naver.kr");
  });
});

describe("whoisToRdap finalize hooks", () => {
  it("emits port43 + Source notice and lowercases ldhName when sourceServer provided", () => {
    const upper = fixture.replace("Domain Name                 : naver.kr", "Domain Name                 : NAVER.KR");
    const r = whoisToRdap(upper, { domain: "NAVER.KR", sourceServer: "whois.kr" });
    expect(r.port43).toBe("whois.kr");
    expect(r.ldhName).toBe("naver.kr");
    expect(r.nameservers?.[0]?.ldhName).toBe("ns1.naver.com");
    expect(r.notices?.some((n) => n.title === "Source")).toBe(true);
  });

  it("includes raw WHOIS notice when requested", () => {
    const r = whoisToRdap(fixture, { sourceServer: "whois.kr", includeRawWhoisNotice: true });
    const raw = r.notices?.find((n) => n.title === "Raw WHOIS data");
    expect(raw?.description.length).toBeGreaterThan(10);
  });
});

describe("krWhoisToRdap with status and signed DNSSEC", () => {
  const rdap = krWhoisToRdap(oupFixture);

  it("maps EPP Domain Status to RDAP status (RFC 8056)", () => {
    expect(rdap.status).toEqual(["client transfer prohibited"]);
  });

  it("marks DNSSEC as signed", () => {
    expect(rdap.secureDNS).toEqual({ delegationSigned: true });
  });

  it("emits nameservers without IP addresses when WHOIS omits them", () => {
    expect(rdap.nameservers).toEqual([
      { objectClassName: "nameserver", ldhName: "adel.ns.cloudflare.com" },
      { objectClassName: "nameserver", ldhName: "trey.ns.cloudflare.com" },
    ]);
  });
});

describe("krWhoisToRdap status accumulation", () => {
  it("accumulates multiple Domain Status lines", () => {
    const raw = `
# ENGLISH

Domain Name                 : multi.kr
Domain Status               : clientDeleteProhibited
Domain Status               : clientTransferProhibited
Registered Date             : 2020. 01. 01.
`;
    const data = parseKrWhois(raw);
    expect(data.status).toEqual([
      "client delete prohibited",
      "client transfer prohibited",
    ]);
  });
});
