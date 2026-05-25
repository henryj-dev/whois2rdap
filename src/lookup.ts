import { createConnection } from "node:net";
import type { ConvertOptions, RdapDomain } from "./types.js";
import { whoisToRdap } from "./convert.js";
import { normalizeLdhCase } from "./normalize.js";
import { rdapBaseUrlsForTld, type BootstrapLoadOptions } from "./iana.js";
import { isValidTld, type TldLoadOptions } from "./tld.js";

export interface WhoisQueryOptions {
  host: string;
  query: string;
  port?: number;
  timeoutMs?: number;
  /** Maximum response size in bytes. Default: 65536 (64 KiB). */
  maxBytes?: number;
}

export function whoisQuery({
  host,
  query,
  port = 43,
  timeoutMs = 10_000,
  maxBytes = 64 * 1024,
}: WhoisQueryOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const settle = (fn: () => void) => {
      if (!settled) {
        settled = true;
        fn();
      }
    };

    const chunks: Buffer[] = [];
    let totalBytes = 0;

    const socket = createConnection({ host, port }, () => {
      socket.write(`${query}\r\n`);
    });

    // socket.setTimeout is an idle timeout (resets on each data event), not
    // a wall-clock deadline. For typical WHOIS servers this is sufficient.
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`whois query to ${host}:${port} timed out after ${timeoutMs}ms`));
    });

    socket.on("data", (chunk) => {
      totalBytes += chunk.length;
      if (totalBytes > maxBytes) {
        socket.destroy(
          new Error(`whois response from ${host} exceeded ${maxBytes} bytes`),
        );
        return;
      }
      chunks.push(chunk);
    });

    socket.on("end", () =>
      settle(() => resolve(Buffer.concat(chunks).toString("utf8"))),
    );
    // Handle abrupt closes (e.g. RST) where 'end' may not fire.
    socket.on("close", (hadError) => {
      if (!hadError) settle(() => resolve(Buffer.concat(chunks).toString("utf8")));
    });
    socket.on("error", (err) => settle(() => reject(err)));
  });
}

// Static WHOIS server map for TLDs with dedicated parsers.
const TLD_TO_WHOIS_SERVER: Record<string, string> = {
  kr: "whois.kr",
  cn: "whois.cnnic.cn",
};

export function whoisServerForDomain(domain: string): string | undefined {
  const tld = domain.toLowerCase().split(".").pop();
  if (!tld) return undefined;
  return TLD_TO_WHOIS_SERVER[tld];
}

// Per-TLD WHOIS server cache populated by IANA WHOIS discovery.
const ianaWhoisCache = new Map<string, string | null>();

/** Look up the WHOIS server for a TLD via whois.iana.org and cache the result. */
async function discoverWhoisServer(
  tld: string,
  options: LookupOptions,
): Promise<string | undefined> {
  if (ianaWhoisCache.has(tld)) {
    return ianaWhoisCache.get(tld) ?? undefined;
  }
  try {
    const response = await whoisQuery({
      host: "whois.iana.org",
      query: tld,
      timeoutMs: options.timeoutMs,
      maxBytes: options.maxBytes,
    });
    const m = response.match(/^whois:\s*(\S+)/im);
    const server = m?.[1] ?? null;
    ianaWhoisCache.set(tld, server);
    return server ?? undefined;
  } catch {
    return undefined;
  }
}

export function clearWhoisServerCache(): void {
  ianaWhoisCache.clear();
}

/** Convert a possibly-unicode domain label to its ASCII (punycode) form. */
function toAsciiDomain(domain: string): { ascii: string; unicode?: string } {
  try {
    const host = new URL(`http://${domain}`).hostname;
    return host === domain ? { ascii: domain } : { ascii: host, unicode: domain };
  } catch {
    return { ascii: domain };
  }
}

export interface LookupOptions extends ConvertOptions {
  /** Override the WHOIS server (forces the WHOIS path, skipping IANA bootstrap). */
  server?: string;
  port?: number;
  timeoutMs?: number;
  maxBytes?: number;
  /** Whether to use the IANA RDAP bootstrap. Set false to skip and go straight to WHOIS. Default: true. */
  useIanaBootstrap?: boolean;
  /** Forwarded to the IANA bootstrap loader. */
  bootstrap?: BootstrapLoadOptions;
  /** Discover the WHOIS server via whois.iana.org when not in the static map. Default: true. */
  useIanaWhoisDiscovery?: boolean;
  /** Validate the TLD against the IANA TLD list before lookup. Default: false. */
  validateTld?: boolean;
  /** Forwarded to the IANA TLD list loader (used when validateTld is true). */
  tldList?: TldLoadOptions;
  fetchImpl?: typeof fetch;
}

async function fetchRdapDomain(
  baseUrls: string[],
  domain: string,
  options: LookupOptions,
): Promise<RdapDomain> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  let lastError: unknown;

  for (const base of baseUrls) {
    const url = `${base.replace(/\/+$/, "")}/domain/${encodeURIComponent(domain)}`;
    let res: Response;
    try {
      res = await fetchImpl(url, {
        headers: { Accept: "application/rdap+json" },
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      // Network/abort error — try next mirror.
      lastError = err;
      continue;
    }

    if (res.status >= 400 && res.status < 500 && res.status !== 429) {
      // Definitive client-side response — mirrors will agree, fail fast.
      throw new Error(`RDAP ${url}: HTTP ${res.status}`);
    }
    if (!res.ok) {
      lastError = new Error(`RDAP ${url}: HTTP ${res.status}`);
      continue;
    }
    const json = (await res.json()) as RdapDomain;
    if (options.normalizeCase !== false) normalizeLdhCase(json);
    return json;
  }

  throw new Error(
    `RDAP lookup failed for ${domain}: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
  );
}

export async function lookupRdap(domain: string, options: LookupOptions = {}): Promise<RdapDomain> {
  const raw = domain.trim().toLowerCase();
  if (!raw) throw new Error("lookupRdap: domain is required");

  const { ascii: normalized, unicode } = toAsciiDomain(raw);
  const tld = normalized.split(".").pop() ?? "";

  // Optional TLD validation against the official IANA list.
  if (options.validateTld) {
    const valid = await isValidTld(tld, options.tldList).catch(() => true);
    if (!valid) {
      throw new Error(`lookupRdap: "${tld}" is not a valid IANA TLD`);
    }
  }

  // 1) Prefer the official RDAP service from the IANA bootstrap, unless the caller
  //    pinned a WHOIS server or opted out.
  if (!options.server && options.useIanaBootstrap !== false) {
    const baseUrls = await rdapBaseUrlsForTld(tld, options.bootstrap).catch(() => undefined);
    if (baseUrls?.length) {
      const result = await fetchRdapDomain(baseUrls, normalized, options);
      if (unicode && !result.unicodeName) result.unicodeName = unicode;
      return result;
    }
  }

  // 2) Static WHOIS server map (kr, cn).
  // 3) Dynamic WHOIS server discovery via whois.iana.org.
  let server = options.server ?? whoisServerForDomain(normalized);
  if (!server && options.useIanaWhoisDiscovery !== false) {
    server = await discoverWhoisServer(tld, options);
  }

  if (!server) {
    throw new Error(
      `lookupRdap: no IANA RDAP entry and no WHOIS server found for "${normalized}"`,
    );
  }

  const text = await whoisQuery({
    host: server,
    query: normalized,
    port: options.port,
    timeoutMs: options.timeoutMs,
    maxBytes: options.maxBytes,
  });

  const result = whoisToRdap(text, {
    ...options,
    domain: normalized,
    sourceServer: options.sourceServer ?? server,
  });
  if (unicode && !result.unicodeName) result.unicodeName = unicode;
  return result;
}
