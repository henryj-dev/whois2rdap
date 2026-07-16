import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DomainNotFoundError,
  WhoisNoRecordError,
  classifyWhoisResponse as classify,
  lookupRdap,
  whoisEchoesDomain as echoesDomain,
  whoisFieldLines as fieldLines,
  whoisHasRecord as hasRecord,
} from "../src/index.js";

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), "fixtures", "whois-response");
const fixture = (name: string) => readFileSync(join(FIXTURES, `${name}.txt`), "utf8");

describe("classifyWhoisResponse", () => {
  it("reads a record whose legal notice announces rate limiting", () => {
    // Registries append boilerplate that trips every refusal pattern going —
    // this .co record ends with "Access to the Whois and RDAP services is rate
    // limited." It is still a perfectly good record, and reading it as a
    // rejection is exactly the mistake `meat` exists to prevent.
    const body = fixture("co-boilerplate");
    expect(body).toMatch(/rate limited/i);
    expect(classify(body, "nic.co")).toBe("record");
  });

  it("reads DENIC's two-field answer as a record", () => {
    // .de publishes almost nothing: "Domain: denic.de / Status: connect".
    expect(classify(fixture("de-denic"), "denic.de")).toBe("record");
  });

  it("reads JPRS bracket-key fields as a record", () => {
    // JPRS marks data as "[Domain Name]  JPRS.JP" but banners as "[ text ]";
    // dropping every bracket line would discard the whole record.
    expect(classify(fixture("jp-jprs"), "jprs.jp")).toBe("record");
  });

  it("detects an outright refusal", () => {
    expect(classify(fixture("ch-blocked"), "nic.ch")).toBe("refused");
  });

  it("detects a reserved name reported inside a record-shaped response", () => {
    // .bw answers nic.bw with real-looking fields plus "Domain Cannot Be
    // Registered" — the unregistered check has to win over the record check.
    expect(classify(fixture("bw-reserved"), "nic.bw")).toBe("not-found");
  });

  it("detects a registry's non-standard unregistered wording", () => {
    // CNNIC: "the Domain Name you apply can not be registered online."
    expect(classify(fixture("cn-reserved"), "nic.cn")).toBe("not-found");
  });

  it("reads a record that follows a leading legal notice", () => {
    // EDUCAUSE prints its notice *above* the record. Stopping at the first
    // notice line — as an earlier version did — threw the record away.
    const body = fixture("edu-header-notice");
    expect(body.split("\n").findIndex((l) => /Domain Name:/i.test(l))).toBeGreaterThan(3);
    expect(classify(body, "mit.edu")).toBe("record");
  });

  it("reads a JWhoisServer record behind its banner", () => {
    expect(classify(fixture("tg-jwhoisserver"), "nic.tg")).toBe("record");
  });

  it("reads a record carrying a single field line", () => {
    expect(classify(fixture("im-sparse"), "nic.im")).toBe("record");
  });

  it("detects a restricted name flagged behind a '>>>' marker", () => {
    // NIXI answers with a normal "Domain Name:" field and puts the verdict on
    // a ">>> This name is not available for registration:" line below it.
    expect(classify(fixture("in-idn-restricted"), "nic.xn--2scrj9c")).toBe("not-found");
  });

  it("does not call an unrelated record a match for our domain", () => {
    expect(classify(fixture("de-denic"), "example.de")).toBe("unknown");
  });
});

describe("lookupRdap response handling", () => {
  /** A throwaway WHOIS server on localhost that answers with `body`. */
  async function serving(body: string) {
    const server = createServer((socket) => {
      socket.once("data", () => socket.end(body));
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const { port } = server.address() as AddressInfo;
    return {
      port,
      close: () => new Promise<void>((r) => server.close(() => r())),
    };
  }

  const pin = (port: number) => ({
    server: "127.0.0.1",
    port,
    useIanaBootstrap: false as const,
    useIanaWhoisDiscovery: false as const,
  });

  it("raises DomainNotFoundError instead of an empty record", async () => {
    const s = await serving(fixture("cn-reserved"));
    try {
      const err = await lookupRdap("nic.cn", pin(s.port)).catch((e) => e);
      expect(err).toBeInstanceOf(DomainNotFoundError);
      expect(err.permanent).toBe(true);
      expect(err.domain).toBe("nic.cn");
    } finally {
      await s.close();
    }
  });

  it("raises WhoisNoRecordError when the server rejects the query", async () => {
    // Before this check, .ch's "Requests of this client are not permitted"
    // parsed into a clean-looking {ldhName: "nic.ch"} — a rejection dressed up
    // as an answer.
    const s = await serving(fixture("ch-blocked"));
    try {
      const err = await lookupRdap("nic.ch", pin(s.port)).catch((e) => e);
      expect(err).toBeInstanceOf(WhoisNoRecordError);
      expect(err.reason).toBe("refused");
      expect(err.permanent).toBe(true);
      expect(err.hint).toMatch(/not permitted/i);
    } finally {
      await s.close();
    }
  });

  it("still returns a registry's sparse-but-real record", async () => {
    // DENIC publishes two fields for a live domain. That must not be mistaken
    // for one of the cases above.
    const s = await serving(fixture("de-denic"));
    try {
      const rdap = await lookupRdap("denic.de", pin(s.port));
      expect(rdap.ldhName).toBe("denic.de");
    } finally {
      await s.close();
    }
  });

  it("parses regardless when classifyResponse is off", async () => {
    const s = await serving(fixture("ch-blocked"));
    try {
      const rdap = await lookupRdap("nic.ch", { ...pin(s.port), classifyResponse: false });
      expect(rdap.ldhName).toBe("nic.ch");
    } finally {
      await s.close();
    }
  });
});

describe("whoisFieldLines", () => {
  it("keeps JPRS data lines while dropping its banner", () => {
    const lines = fieldLines(fixture("jp-jprs")).join("\n");
    expect(lines).toMatch(/\[Domain Name\]/);
    expect(lines).not.toMatch(/JPRS database provides information/);
  });

  it("does not mistake a prose sentence ending in a colon for a field", () => {
    expect(fieldLines("We provide this data under the following terms: none.")).toHaveLength(0);
  });

  it("reads dot-padded keys", () => {
    // .tg and .ax pad keys out with dots: "Domain:.............nic.tg"
    expect(fieldLines("Domain:.............nic.tg")).toHaveLength(1);
  });

  it("reads bullet-prefixed keys", () => {
    // TRABIS (.tr) writes "** Domain Name: google.tr".
    expect(fieldLines("** Domain Name: google.tr")).toHaveLength(1);
  });
});

describe("whoisEchoesDomain", () => {
  it("matches a plain echo", () => {
    expect(echoesDomain("Domain Name: nic.im", "nic.im")).toBe(true);
  });

  it("matches a punycode query echoed back in Unicode", () => {
    // TWNIC answers a query for nic.xn--kprw13d with "Domain Name: nic.台灣".
    expect(echoesDomain("Domain Name: nic.台灣", "nic.xn--kprw13d")).toBe(true);
  });

  it("does not match an unrelated domain", () => {
    expect(echoesDomain("Domain Name: other.im", "nic.im")).toBe(false);
  });
});

describe("whoisHasRecord", () => {
  it("requires the queried domain to appear", () => {
    expect(hasRecord("Domain: a.de\nStatus: connect", "a.de")).toBe(true);
    expect(hasRecord("Domain: a.de\nStatus: connect", "b.de")).toBe(false);
  });

  it("accepts a lone field line", () => {
    // .im answers with one field above unkeyed prose sections.
    expect(hasRecord("Domain Name:\tnic.im", "nic.im")).toBe(true);
  });
});
