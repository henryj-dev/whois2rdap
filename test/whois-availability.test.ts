import { afterEach, describe, expect, it, vi } from "vitest";
import {
  WHOIS_AVAILABILITY,
  WhoisUnavailableError,
  clearIanaRdapBootstrapCache,
  clearWhoisServerCache,
  lookupRdap,
  parseIanaWhoisServer,
  setIanaRdapBootstrapCache,
  whoisAvailabilityForTld,
} from "../src/index.js";

afterEach(() => {
  clearIanaRdapBootstrapCache();
  clearWhoisServerCache();
  vi.restoreAllMocks();
});

// Verbatim shape of a whois.iana.org record for a TLD with no WHOIS server.
// The blank `whois:` line directly above `status:` is the whole point.
const IANA_GB_RESPONSE = `% IANA WHOIS server
domain:       GB

organisation: Reserved Domain - IANA
created:      1985-07-24

whois:

status:       ACTIVE
remarks:      This domain is not available for registration.
`;

const IANA_DE_RESPONSE = `% IANA WHOIS server
domain:       DE

whois:        whois.denic.de

status:       ACTIVE
`;

describe("parseIanaWhoisServer", () => {
  it("reads the server from a populated record", () => {
    expect(parseIanaWhoisServer(IANA_DE_RESPONSE)).toBe("whois.denic.de");
  });

  it("returns undefined for a blank whois: field rather than the next line", () => {
    // Regression: an unanchored /^whois:\s*(\S+)/im captured "status:" here and
    // handed it downstream as a hostname.
    expect(parseIanaWhoisServer(IANA_GB_RESPONSE)).toBeUndefined();
  });

  it("tolerates CRLF line endings", () => {
    expect(parseIanaWhoisServer(IANA_DE_RESPONSE.replace(/\n/g, "\r\n"))).toBe("whois.denic.de");
    expect(parseIanaWhoisServer(IANA_GB_RESPONSE.replace(/\n/g, "\r\n"))).toBeUndefined();
  });
});

describe("whoisAvailabilityForTld", () => {
  it("marks registries that publish no WHOIS at all", () => {
    expect(whoisAvailabilityForTld("gb")).toEqual({ kind: "none" });
  });

  it("carries the form URL for web-only registries", () => {
    const gr = whoisAvailabilityForTld("gr");
    expect(gr?.kind).toBe("web");
    expect(gr).toHaveProperty("url", expect.stringMatching(/^https?:\/\//));
  });

  it("supplies servers the IANA root database omits", () => {
    expect(whoisAvailabilityForTld("bz")).toEqual({
      kind: "server",
      host: "whois.identitydigital.services",
    });
  });

  it("is case-insensitive", () => {
    expect(whoisAvailabilityForTld("GB")).toEqual({ kind: "none" });
  });

  it("has no entry for TLDs IANA already serves", () => {
    expect(whoisAvailabilityForTld("de")).toBeUndefined();
    expect(whoisAvailabilityForTld("com")).toBeUndefined();
  });

  it("contains only well-formed entries", () => {
    for (const [tld, entry] of Object.entries(WHOIS_AVAILABILITY)) {
      expect(tld, `${tld} should be a lowercase LDH label`).toMatch(/^[a-z0-9-]+$/);
      if (entry.kind === "server") expect(entry.host).toMatch(/^[a-z0-9.-]+$/);
      else if (entry.kind === "web") expect(entry.url).toMatch(/^https?:\/\//);
      else expect(entry.kind).toBe("none");
    }
  });
});

describe("lookupRdap when no WHOIS source exists", () => {
  // No RDAP for these TLDs, and discovery is off so nothing touches the network.
  const offline = { useIanaWhoisDiscovery: false as const, useIanaBootstrap: true as const };
  const emptyBootstrap = () => setIanaRdapBootstrapCache(new Map());

  it("reports a server-less registry as permanent", async () => {
    emptyBootstrap();
    const err = await lookupRdap("example.gb", offline).catch((e) => e);
    expect(err).toBeInstanceOf(WhoisUnavailableError);
    expect(err.reason).toBe("no-whois-server");
    expect(err.permanent).toBe(true);
    expect(err.tld).toBe("gb");
    expect(err.webUrl).toBeUndefined();
  });

  it("points web-only registries at their form", async () => {
    emptyBootstrap();
    const err = await lookupRdap("example.gr", offline).catch((e) => e);
    expect(err).toBeInstanceOf(WhoisUnavailableError);
    expect(err.reason).toBe("web-only");
    expect(err.permanent).toBe(true);
    expect(err.webUrl).toMatch(/^https?:\/\//);
    expect(err.message).toContain(err.webUrl);
  });

  it("falls back to a table server for TLDs IANA omits", async () => {
    emptyBootstrap();
    // Reaches the WHOIS query with the table's host, then fails on the network —
    // proving the host was resolved from the table rather than rejected outright.
    const err = await lookupRdap("example.bz", { ...offline, timeoutMs: 1 }).catch((e) => e);
    expect(err).not.toBeInstanceOf(WhoisUnavailableError);
    expect(err.message).toContain("whois.identitydigital.services");
  });

  it("reports an unknown TLD as no-source", async () => {
    emptyBootstrap();
    const err = await lookupRdap("example.invalidtld", offline).catch((e) => e);
    expect(err).toBeInstanceOf(WhoisUnavailableError);
    expect(err.reason).toBe("no-source");
  });

  it("skips the table when useWhoisAvailabilityTable is false", async () => {
    emptyBootstrap();
    const err = await lookupRdap("example.gr", {
      ...offline,
      useWhoisAvailabilityTable: false,
    }).catch((e) => e);
    expect(err).toBeInstanceOf(WhoisUnavailableError);
    expect(err.reason).toBe("no-source");
    expect(err.webUrl).toBeUndefined();
  });
});
