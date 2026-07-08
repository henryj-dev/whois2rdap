import type {
  ConvertOptions,
  RdapDomain,
  RdapEntity,
  RdapEvent,
  RdapNameserver,
  RdapVcardArray,
} from "../types.js";
import { finalize } from "../finalize.js";

// Parser for the IIS (The Swedish Internet Foundation) WHOIS format served by
// whois.iis.se — covers the .se TLD (the .nu TLD uses the identical format).
// Fields are simple `key: value` lines, e.g.
//   domain:    example.se
//   created:   2020-01-01
//   expires:   2027-02-27
//   nserver:   ns1.example.com
//   dnssec:    signed delegation
//   status:    ok
//   registrar: Example Registrar AB

export interface SeNameserver {
  host: string;
  ips: string[];
}

export interface SeWhoisData {
  domain?: string;
  holder?: string;
  registrar?: string;
  registeredDate?: string; // created
  lastUpdatedDate?: string; // modified
  expirationDate?: string; // expires
  dnssec?: string;
  status?: string[];
  nameservers: SeNameserver[];
}

// RFC 8056 §2 — map EPP status names to RDAP status strings.
const EPP_TO_RDAP_STATUS: Record<string, string> = {
  ok: "active",
  active: "active",
  inactive: "inactive",
  serverDeleteProhibited: "server delete prohibited",
  serverHold: "server hold",
  serverRenewProhibited: "server renew prohibited",
  serverTransferProhibited: "server transfer prohibited",
  serverUpdateProhibited: "server update prohibited",
  clientDeleteProhibited: "client delete prohibited",
  clientHold: "client hold",
  clientRenewProhibited: "client renew prohibited",
  clientTransferProhibited: "client transfer prohibited",
  clientUpdateProhibited: "client update prohibited",
  pendingDelete: "pending delete",
  pendingTransfer: "pending transfer",
};

function mapStatus(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => EPP_TO_RDAP_STATUS[s] ?? s);
}

const FIELD = /^([^:]+?)\s*:\s*(.*)$/;

// IIS dates are date-only (YYYY-MM-DD). Normalize to UTC midnight.
function parseSeDate(value: string): string | undefined {
  const m = value.match(/(\d{4})-(\d{2})-(\d{2})/);
  if (!m) return undefined;
  return `${m[1]}-${m[2]}-${m[3]}T00:00:00Z`;
}

// GDPR-redacted holder is served as "(not shown)".
const NOT_SHOWN = /^\(?\s*not shown\s*\)?$/i;

export function parseSeWhois(raw: string): SeWhoisData {
  const data: SeWhoisData = { nameservers: [] };

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trimEnd();
    // Skip blank lines and comment banners (# ... / % ...).
    if (!line.trim() || line.startsWith("#") || line.startsWith("%")) continue;

    const m = line.match(FIELD);
    if (!m) continue;
    const key = m[1]!.trim().toLowerCase();
    const value = m[2]!.trim();
    if (!value) continue;

    switch (key) {
      case "domain":
        data.domain ??= value.toLowerCase();
        break;
      case "holder":
        if (!NOT_SHOWN.test(value)) data.holder ??= value;
        break;
      case "registrar":
        data.registrar ??= value;
        break;
      case "created":
        data.registeredDate ??= parseSeDate(value);
        break;
      case "modified":
        data.lastUpdatedDate ??= parseSeDate(value);
        break;
      case "expires":
        data.expirationDate ??= parseSeDate(value);
        break;
      case "dnssec":
        data.dnssec ??= value;
        break;
      case "status": {
        const statuses = mapStatus(value);
        if (statuses.length) (data.status ??= []).push(...statuses);
        break;
      }
      case "nserver": {
        // "host" or "host <ipv4> [ipv6]".
        const parts = value.split(/\s+/).filter(Boolean);
        const host = parts.shift();
        if (host) data.nameservers.push({ host, ips: parts });
        break;
      }
    }
  }

  return data;
}

function vcard(
  props: Array<[string, Record<string, unknown>, string, unknown]>,
): RdapVcardArray {
  return ["vcard", [["version", {}, "text", "4.0"], ...props]];
}

export type SeConvertOptions = ConvertOptions;

export function seWhoisToRdap(raw: string, opts: SeConvertOptions = {}): RdapDomain {
  const data = parseSeWhois(raw);
  const ldhName = (opts.domain ?? data.domain ?? "").toLowerCase();

  const events: RdapEvent[] = [];
  if (data.registeredDate)
    events.push({ eventAction: "registration", eventDate: data.registeredDate });
  if (data.lastUpdatedDate)
    events.push({ eventAction: "last changed", eventDate: data.lastUpdatedDate });
  if (data.expirationDate)
    events.push({ eventAction: "expiration", eventDate: data.expirationDate });

  const entities: RdapEntity[] = [];
  if (data.holder) {
    entities.push({
      objectClassName: "entity",
      roles: ["registrant"],
      vcardArray: vcard([["fn", {}, "text", data.holder]]),
    });
  }
  if (data.registrar) {
    entities.push({
      objectClassName: "entity",
      roles: ["registrar"],
      vcardArray: vcard([["fn", {}, "text", data.registrar]]),
    });
  }

  const nameservers: RdapNameserver[] = data.nameservers
    .filter((n) => n.host)
    .map((n) => {
      const ns: RdapNameserver = {
        objectClassName: "nameserver",
        ldhName: n.host.toLowerCase(),
      };
      const v4 = n.ips.filter((ip) => !ip.includes(":"));
      const v6 = n.ips.filter((ip) => ip.includes(":"));
      if (v4.length || v6.length) {
        ns.ipAddresses = {};
        if (v4.length) ns.ipAddresses.v4 = v4;
        if (v6.length) ns.ipAddresses.v6 = v6;
      }
      return ns;
    });

  const result: RdapDomain = { objectClassName: "domain", ldhName };
  if (opts.includeConformance !== false) result.rdapConformance = ["rdap_level_0"];
  if (data.status?.length) result.status = data.status;
  if (entities.length) result.entities = entities;
  if (nameservers.length) result.nameservers = nameservers;
  if (events.length) result.events = events;
  if (data.dnssec) {
    const v = data.dnssec.toLowerCase();
    // ".se" reports "signed delegation" / "unsigned delegation".
    const signed = v.includes("signed") && !v.includes("unsigned");
    result.secureDNS = { delegationSigned: signed };
  }

  return finalize(result, raw, opts);
}
