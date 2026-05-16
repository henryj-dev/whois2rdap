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
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
let cache: BootstrapCacheEntry | null = null;

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
  const fetchImpl = options.fetchImpl ?? fetch;
  const res = await fetchImpl(options.url ?? IANA_RDAP_BOOTSTRAP_URL, {
    signal: options.signal,
  });
  if (!res.ok) {
    throw new Error(`IANA RDAP bootstrap fetch failed: HTTP ${res.status}`);
  }
  const json = (await res.json()) as IanaRdapBootstrap;
  const map = buildMap(json);
  cache = { fetchedAt: Date.now(), map };
  return map;
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
}

export function clearIanaRdapBootstrapCache(): void {
  cache = null;
}
