import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { cnWhoisToRdap, parseCnWhois, whoisToRdap } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(resolve(here, "fixtures/cn-example.txt"), "utf8");

describe("parseCnWhois", () => {
  const data = parseCnWhois(fixture);

  it("extracts domain and ROID", () => {
    expect(data.domain).toBe("example.cn");
    expect(data.roid).toBe("20050501s10011s00000001-cn");
  });

  it("parses dates with CST offset (+08:00)", () => {
    expect(data.registeredDate).toBe("2005-05-01T08:00:00+08:00");
    expect(data.expirationDate).toBe("2026-05-01T08:00:00+08:00");
    expect(data.lastUpdatedDate).toBe("2024-03-15T14:30:00+08:00");
  });

  it("accumulates multiple Domain Status lines", () => {
    expect(data.status).toEqual([
      "client delete prohibited",
      "client transfer prohibited",
    ]);
  });

  it("extracts registrant and registrar", () => {
    expect(data.registrant).toBe("Example Corp.");
    expect(data.registrantEmail).toBe("hostmaster@example.cn");
    expect(data.registrar).toBe("Example Registrar Co., Ltd.");
  });

  it("extracts nameservers", () => {
    expect(data.nameservers).toEqual(["ns1.example.com", "ns2.example.com"]);
  });

  it("extracts DNSSEC", () => {
    expect(data.dnssec).toBe("unsigned");
  });
});

describe("cnWhoisToRdap", () => {
  const rdap = cnWhoisToRdap(fixture);

  it("produces an RDAP domain object", () => {
    expect(rdap.objectClassName).toBe("domain");
    expect(rdap.ldhName).toBe("example.cn");
    expect(rdap.rdapConformance).toEqual(["rdap_level_0"]);
  });

  it("sets handle from ROID", () => {
    expect(rdap.handle).toBe("20050501s10011s00000001-cn");
  });

  it("maps events with CST offset", () => {
    expect(rdap.events).toEqual([
      { eventAction: "registration", eventDate: "2005-05-01T08:00:00+08:00" },
      { eventAction: "last changed", eventDate: "2024-03-15T14:30:00+08:00" },
      { eventAction: "expiration", eventDate: "2026-05-01T08:00:00+08:00" },
    ]);
  });

  it("maps status", () => {
    expect(rdap.status).toEqual([
      "client delete prohibited",
      "client transfer prohibited",
    ]);
  });

  it("maps nameservers", () => {
    expect(rdap.nameservers).toEqual([
      { objectClassName: "nameserver", ldhName: "ns1.example.com" },
      { objectClassName: "nameserver", ldhName: "ns2.example.com" },
    ]);
  });

  it("emits registrant and registrar entities", () => {
    const roles = rdap.entities?.map((e) => e.roles?.[0]);
    expect(roles).toEqual(["registrant", "registrar"]);
  });

  it("marks DNSSEC as unsigned", () => {
    expect(rdap.secureDNS).toEqual({ delegationSigned: false });
  });

  it("honours sourceServer when called directly", () => {
    const r = cnWhoisToRdap(fixture, { sourceServer: "whois.cnnic.cn" });
    expect(r.port43).toBe("whois.cnnic.cn");
    expect(r.notices?.some((n) => n.title === "Source")).toBe(true);
  });
});

describe("whoisToRdap dispatch to CN parser", () => {
  it("routes .cn domain to the CN parser", () => {
    const rdap = whoisToRdap(fixture, { domain: "example.cn" });
    expect(rdap.handle).toBe("20050501s10011s00000001-cn");
    expect(rdap.events?.length).toBe(3);
  });

  it("auto-detects CN via ROID field when domain is unknown", () => {
    const rdap = whoisToRdap(fixture);
    expect(rdap.ldhName).toBe("example.cn");
  });
});

describe("cnWhoisToRdap signed DNSSEC", () => {
  it("marks DNSSEC as signed", () => {
    const raw = fixture.replace("DNSSEC: unsigned", "DNSSEC: signed");
    expect(cnWhoisToRdap(raw).secureDNS).toEqual({ delegationSigned: true });
  });

  it("marks signedDelegation as signed", () => {
    const raw = fixture.replace("DNSSEC: unsigned", "DNSSEC: signedDelegation");
    expect(cnWhoisToRdap(raw).secureDNS).toEqual({ delegationSigned: true });
  });
});
