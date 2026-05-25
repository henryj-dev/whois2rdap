/**
 * IANA RDAP bootstrap loader (RFC 7484).
 * Source: https://data.iana.org/rdap/dns.json
 */

export interface IanaRdapBootstrap {
  version: string;
  publication?: string;
  description?: string;
  services: Array<[string[], string[]]>;
}

export const IANA_RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";

export interface BootstrapLoadOptions {
  url?: string;
  force?: boolean;
  fetchImpl?: typeof fetch;
  ttlMs?: number;
  signal?: AbortSignal;
}

interface BootstrapCacheEntry {
  fetchedAt: number;
  map: Map<string, string[]>;
  etag?: string;
  lastModified?: string;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
let cache: BootstrapCacheEntry | null = null;
let pendingFetch: Promise<Map<string, string[]>> | null = null;

function buildMap(json: IanaRdapBootstrap): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const entry of json.services ?? []) {
    const [tlds, urls] = entry;
    if (!Array.isArray(tlds) || !Array.isArray(urls)) continue;
    for (const tld of tlds) {
      if (typeof tld === "string") map.set(tld.toLowerCase(), urls.slice());
    }
  }
  return map;
}

export async function loadIanaRdapBootstrap(
  options: BootstrapLoadOptions = {},
): Promise<Map<string, string[]>> {
  const ttl = options.ttlMs ?? DEFAULT_TTL_MS;
  if (!options.force && cache && Date.now() - cache.fetchedAt < ttl) {
    return cache.map;
  }

  // Deduplicate concurrent fetches when no special overrides are active.
  if (!options.force && pendingFetch) return pendingFetch;

  const doFetch = async (): Promise<Map<string, string[]>> => {
    try {
      const fetchImpl = options.fetchImpl ?? fetch;
      const headers: Record<string, string> = {};
      if (!options.force) {
        if (cache?.etag) headers["If-None-Match"] = cache.etag;
        if (cache?.lastModified) headers["If-Modified-Since"] = cache.lastModified;
      }

      const res = await fetchImpl(options.url ?? IANA_RDAP_BOOTSTRAP_URL, {
        signal: options.signal,
        headers,
      });

      // Conditional GET — server says nothing changed; refresh TTL.
      if (res.status === 304 && cache) {
        cache = { ...cache, fetchedAt: Date.now() };
        return cache.map;
      }
      if (!res.ok) {
        throw new Error(`IANA RDAP bootstrap fetch failed: HTTP ${res.status}`);
      }

      const json = (await res.json()) as IanaRdapBootstrap;
      const map = buildMap(json);
      cache = {
        fetchedAt: Date.now(),
        map,
        etag: res.headers.get("ETag") ?? undefined,
        lastModified: res.headers.get("Last-Modified") ?? undefined,
      };
      return map;
    } finally {
      pendingFetch = null;
    }
  };

  pendingFetch = doFetch();
  return pendingFetch;
}

export async function rdapBaseUrlsForTld(
  tld: string,
  options?: BootstrapLoadOptions,
): Promise<string[] | undefined> {
  const map = await loadIanaRdapBootstrap(options);
  return map.get(tld.toLowerCase());
}

/** Replace the cached bootstrap map (useful for tests). */
export function setIanaRdapBootstrapCache(map: Map<string, string[]>): void {
  cache = { fetchedAt: Date.now(), map };
  pendingFetch = null;
}

export function clearIanaRdapBootstrapCache(): void {
  cache = null;
  pendingFetch = null;
}
