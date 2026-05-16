import { createConnection } from "node:net";
import type { ConvertOptions, RdapDomain } from "./types.js";
import { whoisToRdap } from "./convert.js";
import { normalizeLdhCase } from "./normalize.js";
import { rdapBaseUrlsForTld, type BootstrapLoadOptions } from "./iana.js";

export interface WhoisQueryOptions {
  host: string;
  query: string;
  port?: number;
  timeoutMs?: number;
}

export function whoisQuery({
  host,
  query,
  port = 43,
  timeoutMs = 10_000,
}: WhoisQueryOptions): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const socket = createConnection({ host, port }, () => {
      socket.write(`${query}\r\n`);
    });
    socket.setTimeout(timeoutMs, () => {
      socket.destroy(new Error(`whois query to ${host}:${port} timed out after ${timeoutMs}ms`));
    });
    socket.on("data", (chunk) => chunks.push(chunk));
    socket.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    socket.on("error", reject);
  });
}

const TLD_TO_WHOIS_SERVER: Record<string, string> = {
  kr: "whois.kr",
  cn: "whois.cnnic.cn",
};

export function whoisServerForDomain(domain: string): string | undefined {
  const tld = domain.toLowerCase().split(".").pop();
  if (!tld) return undefined;
  return TLD_TO_WHOIS_SERVER[tld];
}

export interface LookupOptions extends ConvertOptions {
  /** Override the WHOIS server (forces the WHOIS path, skipping IANA bootstrap). */
  server?: string;
  port?: number;
  timeoutMs?: number;
  /** Disable the IANA RDAP bootstrap lookup and go straight to WHOIS. Default: true. */
  useIanaBootstrap?: boolean;
  /** Forwarded to the IANA bootstrap loader. */
  bootstrap?: BootstrapLoadOptions;
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
  const normalized = domain.trim().toLowerCase();
  if (!normalized) throw new Error("lookupRdap: domain is required");

  const tld = normalized.split(".").pop() ?? "";

  // 1) Prefer the official RDAP service from the IANA bootstrap, unless the caller
  //    pinned a WHOIS server or opted out.
  if (!options.server && options.useIanaBootstrap !== false) {
    const baseUrls = await rdapBaseUrlsForTld(tld, options.bootstrap).catch(() => undefined);
    if (baseUrls?.length) {
      return fetchRdapDomain(baseUrls, normalized, options);
    }
  }

  // 2) Fall back to WHOIS + parser conversion.
  const server = options.server ?? whoisServerForDomain(normalized);
  if (!server) {
    throw new Error(
      `lookupRdap: no IANA RDAP entry and no WHOIS server configured for "${normalized}"`,
    );
  }

  const text = await whoisQuery({
    host: server,
    query: normalized,
    port: options.port,
    timeoutMs: options.timeoutMs,
  });

  return whoisToRdap(text, {
    ...options,
    domain: normalized,
    sourceServer: options.sourceServer ?? server,
  });
}
