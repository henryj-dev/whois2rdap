import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearIanaRdapBootstrapCache,
  loadIanaRdapBootstrap,
  lookupRdap,
  setIanaRdapBootstrapCache,
} from "../src/index.js";

afterEach(() => {
  clearIanaRdapBootstrapCache();
  vi.restoreAllMocks();
});

describe("loadIanaRdapBootstrap", () => {
  it("flattens services into a TLD → URL map", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({
          version: "1.0",
          services: [
            [["com", "net"], ["https://rdap.verisign.example/com/v1/"]],
            [["org"], ["https://rdap.publicinterestregistry.example/"]],
          ],
        }),
        { status: 200 },
      ),
    );
    const map = await loadIanaRdapBootstrap({ fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(map.get("com")).toEqual(["https://rdap.verisign.example/com/v1/"]);
    expect(map.get("net")).toEqual(["https://rdap.verisign.example/com/v1/"]);
    expect(map.get("org")).toEqual(["https://rdap.publicinterestregistry.example/"]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("caches across calls within TTL", async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ version: "1.0", services: [] }), { status: 200 }),
    );
    await loadIanaRdapBootstrap({ fetchImpl: fetchImpl as unknown as typeof fetch });
    await loadIanaRdapBootstrap({ fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

describe("lookupRdap with IANA bootstrap", () => {
  it("hits the RDAP endpoint when the TLD is in the bootstrap", async () => {
    setIanaRdapBootstrapCache(new Map([["com", ["https://rdap.example.test/"]]]));

    const rdapPayload = {
      objectClassName: "domain",
      ldhName: "example.com",
      handle: "EXAMPLE-COM",
    };
    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      expect(String(input)).toBe("https://rdap.example.test/domain/example.com");
      return new Response(JSON.stringify(rdapPayload), {
        status: 200,
        headers: { "content-type": "application/rdap+json" },
      });
    });

    const result = await lookupRdap("example.com", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    expect(result.handle).toBe("EXAMPLE-COM");
    expect(result.ldhName).toBe("example.com");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("tries the next mirror on 5xx but fails fast on 404", async () => {
    setIanaRdapBootstrapCache(
      new Map([["com", ["https://primary.example.test/", "https://backup.example.test/"]]]),
    );

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("https://primary")) return new Response("boom", { status: 503 });
      return new Response(
        JSON.stringify({ objectClassName: "domain", ldhName: "x.com" }),
        { status: 200 },
      );
    });

    const ok = await lookupRdap("x.com", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(ok.ldhName).toBe("x.com");
    expect(fetchImpl).toHaveBeenCalledTimes(2);

    const fetch404 = vi.fn(async () => new Response("nope", { status: 404 }));
    setIanaRdapBootstrapCache(
      new Map([["com", ["https://primary.example.test/", "https://backup.example.test/"]]]),
    );
    await expect(
      lookupRdap("y.com", { fetchImpl: fetch404 as unknown as typeof fetch }),
    ).rejects.toThrow(/404/);
    expect(fetch404).toHaveBeenCalledTimes(1);
  });

  it("follows the registrar referral to enrich thin data with a reseller", async () => {
    setIanaRdapBootstrapCache(new Map([["com", ["https://registry.example.test/"]]]));

    const thin = {
      objectClassName: "domain",
      ldhName: "example.com",
      links: [
        { rel: "self", type: "application/rdap+json", href: "https://registry.example.test/domain/example.com" },
        { rel: "related", type: "application/rdap+json", href: "https://rdap.registrar.test/domain/example.com" },
      ],
      entities: [{ objectClassName: "entity", roles: ["registrar"] }],
    };
    const thick = {
      objectClassName: "domain",
      ldhName: "example.com",
      entities: [
        { objectClassName: "entity", roles: ["registrar"] },
        {
          objectClassName: "entity",
          roles: ["reseller"],
          vcardArray: ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Reseller"]]],
        },
      ],
    };

    const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.startsWith("https://registry.example.test")) return new Response(JSON.stringify(thin), { status: 200 });
      if (url.startsWith("https://rdap.registrar.test")) return new Response(JSON.stringify(thick), { status: 200 });
      return new Response("nope", { status: 404 });
    });

    const result = await lookupRdap("example.com", {
      fetchImpl: fetchImpl as unknown as typeof fetch,
      followRegistrarReferral: true,
    });
    const reseller = (result.entities ?? []).find((e) => e.roles?.includes("reseller"));
    expect(reseller).toBeDefined();
    const fn = reseller?.vcardArray?.[1].find((p) => p[0] === "fn")?.[3];
    expect(fn).toBe("Acme Reseller");
    expect(fetchImpl).toHaveBeenCalledTimes(2); // registry + referral
  });

  it("does not follow the referral unless enabled", async () => {
    setIanaRdapBootstrapCache(new Map([["com", ["https://registry.example.test/"]]]));
    const thin = {
      objectClassName: "domain",
      ldhName: "example.com",
      links: [{ rel: "related", type: "application/rdap+json", href: "https://rdap.registrar.test/domain/example.com" }],
    };
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify(thin), { status: 200 }));
    await lookupRdap("example.com", { fetchImpl: fetchImpl as unknown as typeof fetch });
    expect(fetchImpl).toHaveBeenCalledTimes(1); // registry only
  });

  it("throws when neither bootstrap nor WHOIS knows the TLD", async () => {
    setIanaRdapBootstrapCache(new Map());
    const fetchImpl = vi.fn();
    await expect(
      lookupRdap("example.unknownnonsensezz", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
      }),
    ).rejects.toThrow(/no IANA RDAP entry and no WHOIS server/);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("skips the bootstrap when an explicit WHOIS server is provided", async () => {
    setIanaRdapBootstrapCache(new Map([["com", ["https://should-not-be-called.example/"]]]));
    const fetchImpl = vi.fn();
    // Connection to a closed local port fails fast; we only want to assert HTTP wasn't tried.
    await expect(
      lookupRdap("example.com", {
        fetchImpl: fetchImpl as unknown as typeof fetch,
        server: "127.0.0.1",
        port: 1,
        timeoutMs: 200,
      }),
    ).rejects.toThrow();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});
