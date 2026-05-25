/**
 * IANA Top-Level Domain list loader.
 * Source: https://data.iana.org/TLD/tlds-alpha-by-domain.txt
 */

export const IANA_TLD_LIST_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt";

export interface TldLoadOptions {
  url?: string;
  force?: boolean;
  fetchImpl?: typeof fetch;
  ttlMs?: number;
  signal?: AbortSignal;
}

interface TldCacheEntry {
  fetchedAt: number;
  tlds: Set<string>;
  etag?: string;
  lastModified?: string;
}

const DEFAULT_TTL_MS = 24 * 60 * 60 * 1000;
let cache: TldCacheEntry | null = null;
let pendingFetch: Promise<Set<string>> | null = null;

function parseList(text: string): Set<string> {
  const tlds = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || l.startsWith("#")) continue;
    tlds.add(l.toLowerCase());
  }
  return tlds;
}

export async function loadIanaTlds(options: TldLoadOptions = {}): Promise<Set<string>> {
  const ttl = options.ttlMs ?? DEFAULT_TTL_MS;
  if (!options.force && cache && Date.now() - cache.fetchedAt < ttl) {
    return cache.tlds;
  }
  if (!options.force && pendingFetch) return pendingFetch;

  const doFetch = async (): Promise<Set<string>> => {
    try {
      const fetchImpl = options.fetchImpl ?? fetch;
      const headers: Record<string, string> = {};
      if (!options.force) {
        if (cache?.etag) headers["If-None-Match"] = cache.etag;
        if (cache?.lastModified) headers["If-Modified-Since"] = cache.lastModified;
      }

      const res = await fetchImpl(options.url ?? IANA_TLD_LIST_URL, {
        signal: options.signal,
        headers,
      });

      if (res.status === 304 && cache) {
        cache = { ...cache, fetchedAt: Date.now() };
        return cache.tlds;
      }
      if (!res.ok) throw new Error(`IANA TLD list fetch failed: HTTP ${res.status}`);

      const text = await res.text();
      const tlds = parseList(text);
      cache = {
        fetchedAt: Date.now(),
        tlds,
        etag: res.headers.get("ETag") ?? undefined,
        lastModified: res.headers.get("Last-Modified") ?? undefined,
      };
      return tlds;
    } finally {
      pendingFetch = null;
    }
  };

  pendingFetch = doFetch();
  return pendingFetch;
}

export async function isValidTld(tld: string, options?: TldLoadOptions): Promise<boolean> {
  const tlds = await loadIanaTlds(options);
  return tlds.has(tld.toLowerCase());
}

export function setIanaTldsCache(tlds: Set<string>): void {
  cache = { fetchedAt: Date.now(), tlds };
  pendingFetch = null;
}

export function clearIanaTldsCache(): void {
  cache = null;
  pendingFetch = null;
}
