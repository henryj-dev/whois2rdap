import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
  clearIanaTldsCache,
  genericWhoisToRdap,
  parseGenericWhois,
  setIanaTldsCache,
  whoisToRdap,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = readFileSync(resolve(here, "fixtures/generic-com.txt"), "utf8");

describe("parseGenericWhois", () => {
  const data = parseGenericWhois(fixture);

  it("extracts domain name (lowercased)", () => {
    expect(data.domain).toBe("example.com");
  });

  it("accumulates multiple Domain Status lines and strips ICANN URLs", () => {
    expect(data.status).toEqual([
      "client delete prohibited",
      "client transfer prohibited",
    ]);
  });

  it("extracts registrant and email", () => {
    expect(data.registrant).toBe("IANA Example");
    expect(data.registrantEmail).toBe("admin@example.com");
  });

  it("extracts registrar (first occurrence wins over sub-fields)", () => {
    expect(data.registrar).toBe("RESERVED-Internet Assigned Numbers Authority");
  });

  it("parses ISO 8601 dates with Z as-is", () => {
    expect(data.registeredDate).toBe("1995-08-14T04:00:00Z");
    expect(data.lastUpdatedDate).toBe("2023-08-14T07:01:36Z");
    expect(data.expirationDate).toBe("2024-08-13T04:00:00Z");
  });

  it("extracts nameservers (lowercased, hostname only)", () => {
    expect(data.nameservers).toEqual([
      "a.iana-servers.net",
      "b.iana-servers.net",
    ]);
  });

  it("extracts DNSSEC", () => {
    expect(data.dnssec).toBe("unsigned");
  });
});

describe("parseGenericWhois — date formats", () => {
  function parse(line: string) {
    return parseGenericWhois(`Creation Date: ${line}`).registeredDate;
  }

  it("handles ISO 8601 with sub-seconds", () => {
    expect(parse("2024-01-15T00:00:00.000Z")).toBe("2024-01-15T00:00:00Z");
  });

  it("handles ISO 8601 with +HH:MM offset", () => {
    expect(parse("2024-01-15T00:00:00+09:00")).toBe("2024-01-15T00:00:00+09:00");
  });

  it("handles date+time without timezone (assumes Z)", () => {
    expect(parse("2024-01-15 10:30:00")).toBe("2024-01-15T10:30:00Z");
  });

  it("handles date only", () => {
    expect(parse("2024-01-15")).toBe("2024-01-15T00:00:00Z");
  });

  it("handles dot-separated date", () => {
    expect(parse("2024.01.15")).toBe("2024-01-15T00:00:00Z");
  });

  it("handles DD-Mon-YYYY", () => {
    expect(parse("15-Jan-2024")).toBe("2024-01-15T00:00:00Z");
  });

  it("handles Mon-DD-YYYY", () => {
    expect(parse("Jan-15-2024")).toBe("2024-01-15T00:00:00Z");
  });
});

describe("genericWhoisToRdap", () => {
  const rdap = genericWhoisToRdap(fixture);

  it("produces a valid RDAP domain object", () => {
    expect(rdap.objectClassName).toBe("domain");
    expect(rdap.ldhName).toBe("example.com");
    expect(rdap.rdapConformance).toEqual(["rdap_level_0"]);
  });

  it("maps status", () => {
    expect(rdap.status).toEqual([
      "client delete prohibited",
      "client transfer prohibited",
    ]);
  });

  it("maps events", () => {
    expect(rdap.events).toEqual([
      { eventAction: "registration", eventDate: "1995-08-14T04:00:00Z" },
      { eventAction: "last changed", eventDate: "2023-08-14T07:01:36Z" },
      { eventAction: "expiration", eventDate: "2024-08-13T04:00:00Z" },
    ]);
  });

  it("maps nameservers", () => {
    expect(rdap.nameservers).toEqual([
      { objectClassName: "nameserver", ldhName: "a.iana-servers.net" },
      { objectClassName: "nameserver", ldhName: "b.iana-servers.net" },
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
    const r = genericWhoisToRdap(fixture, { sourceServer: "whois.example.com" });
    expect(r.port43).toBe("whois.example.com");
    expect(r.notices?.some((n) => n.title === "Source")).toBe(true);
  });
});

describe("whoisToRdap dispatches to generic parser for unknown TLDs", () => {
  it("routes .com WHOIS through the generic parser", () => {
    const rdap = whoisToRdap(fixture, { domain: "example.com" });
    expect(rdap.ldhName).toBe("example.com");
    expect(rdap.events?.length).toBe(3);
    expect(rdap.nameservers?.length).toBe(2);
  });

  it("auto-detects domain from WHOIS body", () => {
    const rdap = whoisToRdap(fixture);
    expect(rdap.ldhName).toBe("example.com");
  });
});

describe("isValidTld with IANA TLD cache", () => {
  it("returns true for known TLDs", async () => {
    setIanaTldsCache(new Set(["com", "net", "kr", "cn"]));
    const { isValidTld } = await import("../src/index.js");
    expect(await isValidTld("com")).toBe(true);
    expect(await isValidTld("KR")).toBe(true);
    clearIanaTldsCache();
  });

  it("returns false for unknown TLDs", async () => {
    setIanaTldsCache(new Set(["com", "net"]));
    const { isValidTld } = await import("../src/index.js");
    expect(await isValidTld("faketld")).toBe(false);
    clearIanaTldsCache();
  });
});
