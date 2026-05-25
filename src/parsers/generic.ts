import type {
  ConvertOptions,
  RdapDomain,
  RdapEntity,
  RdapEvent,
  RdapNameserver,
  RdapVcardArray,
} from "../types.js";
import { finalize } from "../finalize.js";

// RFC 8056 — EPP status name → RDAP status string.
const EPP_TO_RDAP_STATUS: Record<string, string> = {
  clientDeleteProhibited: "client delete prohibited",
  clientHold: "client hold",
  clientRenewProhibited: "client renew prohibited",
  clientTransferProhibited: "client transfer prohibited",
  clientUpdateProhibited: "client update prohibited",
  inactive: "inactive",
  ok: "active",
  pendingCreate: "pending create",
  pendingDelete: "pending delete",
  pendingRenew: "pending renew",
  pendingRestore: "pending restore",
  pendingTransfer: "pending transfer",
  pendingUpdate: "pending update",
  serverDeleteProhibited: "server delete prohibited",
  serverHold: "server hold",
  serverRenewProhibited: "server renew prohibited",
  serverTransferProhibited: "server transfer prohibited",
  serverUpdateProhibited: "server update prohibited",
};

const MONTHS: Record<string, string> = {
  jan: "01", feb: "02", mar: "03", apr: "04", may: "05", jun: "06",
  jul: "07", aug: "08", sep: "09", oct: "10", nov: "11", dec: "12",
};

function parseGenericDate(value: string): string | undefined {
  // Strip trailing parenthetical remarks and whitespace.
  const v = value.trim().replace(/\s*\(.*\)$/, "").trim();
  if (!v) return undefined;

  // ISO 8601 with Z or offset (strip sub-seconds): 2024-01-15T00:00:00.000Z
  const isoFull = v.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})$/);
  if (isoFull) {
    const offset = isoFull[2] === "Z" ? "Z" : isoFull[2]!.replace(/(\d{2})(\d{2})$/, "$1:$2");
    return `${isoFull[1]}${offset}`;
  }

  // Date + time, no timezone: 2024-01-15T00:00:00 or 2024-01-15 00:00:00
  const dtNoTz = v.match(/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})/);
  if (dtNoTz) return `${dtNoTz[1]}T${dtNoTz[2]}Z`;

  // Date only, ISO: 2024-01-15
  const dateOnly = v.match(/^(\d{4}-\d{2}-\d{2})$/);
  if (dateOnly) return `${dateOnly[1]}T00:00:00Z`;

  // Dot-separated: 2024.01.15
  const dotDate = v.match(/^(\d{4})\.(\d{2})\.(\d{2})$/);
  if (dotDate) return `${dotDate[1]}-${dotDate[2]}-${dotDate[3]}T00:00:00Z`;

  // DD-Mon-YYYY: 15-Jan-2024
  const dmyAlpha = v.match(/^(\d{1,2})-([A-Za-z]{3})-(\d{4})/);
  if (dmyAlpha) {
    const mo = MONTHS[dmyAlpha[2]!.toLowerCase()];
    if (mo) return `${dmyAlpha[3]}-${mo}-${dmyAlpha[1]!.padStart(2, "0")}T00:00:00Z`;
  }

  // Mon-DD-YYYY: Jan-15-2024
  const mdyAlpha = v.match(/^([A-Za-z]{3})-(\d{1,2})-(\d{4})/);
  if (mdyAlpha) {
    const mo = MONTHS[mdyAlpha[1]!.toLowerCase()];
    if (mo) return `${mdyAlpha[3]}-${mo}-${mdyAlpha[2]!.padStart(2, "0")}T00:00:00Z`;
  }

  return undefined;
}

function normalizeGenericStatus(value: string): string[] {
  // ICANN-era WHOIS appends a URL after each status code:
  // "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited"
  return value
    .split(/\s+/)
    .filter((t) => !t.startsWith("http") && t.length > 0)
    .flatMap((t) => t.split(","))
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => EPP_TO_RDAP_STATUS[s] ?? s);
}

// Maps a raw WHOIS field key to a canonical name, or null if unrecognised.
const KEY_PATTERNS: Array<[RegExp, string]> = [
  [/^domain(?:\s+name)?$/i, "domain"],
  [/^domain\s+status$|^status$/i, "status"],
  [/^registrant(?:\s+(?:name|org(?:aniz?ation)?|contact))?$/i, "registrant"],
  [/^registrant\s+(?:contact\s+)?e?-?mail$/i, "registrantEmail"],
  [/^(?:sponsoring\s+)?registrar$|^registrar\s+name$/i, "registrar"],
  [/^creation\s+(?:date|time)$|^created(?:\s+on)?$|^registration\s+(?:date|time)$|^registered(?:\s+on)?$|^domain\s+registration\s+date$/i, "createdDate"],
  [/^registry\s+expiry\s+date$|^expir(?:ation|y)\s+(?:date|time)$|^expires(?:\s+on)?$|^paid-till$|^domain\s+expiration\s+date$|^registrar\s+registration\s+expiration\s+date$/i, "expiresDate"],
  [/^updated\s+date$|^last\s+(?:modified|updated?(?:\s+time)?)$|^modified$/i, "updatedDate"],
  [/^name\s+server$|^nameserver$|^nserver$/i, "nameserver"],
  [/^dnssec$/i, "dnssec"],
];

function classifyKey(raw: string): string | null {
  const key = raw.trim();
  for (const [re, name] of KEY_PATTERNS) {
    if (re.test(key)) return name;
  }
  return null;
}

const FIELD = /^([^:]+?)\s*:\s*(.*)$/;

export interface GenericWhoisData {
  domain?: string;
  status?: string[];
  registrant?: string;
  registrantEmail?: string;
  registrar?: string;
  registeredDate?: string;
  expirationDate?: string;
  lastUpdatedDate?: string;
  dnssec?: string;
  nameservers: string[];
}

export function parseGenericWhois(raw: string): GenericWhoisData {
  const data: GenericWhoisData = { nameservers: [] };

  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("%") || line.startsWith(";") || line.startsWith(">>>")) continue;

    const m = line.match(FIELD);
    if (!m) continue;
    const canonical = classifyKey(m[1]!);
    if (!canonical) continue;
    const value = m[2]!.trim();
    if (!value) continue;

    switch (canonical) {
      case "domain":
        data.domain ??= value.toLowerCase();
        break;
      case "status": {
        const statuses = normalizeGenericStatus(value);
        if (statuses.length) (data.status ??= []).push(...statuses);
        break;
      }
      case "registrant":
        data.registrant ??= value;
        break;
      case "registrantEmail":
        data.registrantEmail ??= value;
        break;
      case "registrar":
        data.registrar ??= value;
        break;
      case "createdDate":
        data.registeredDate ??= parseGenericDate(value);
        break;
      case "expiresDate":
        data.expirationDate ??= parseGenericDate(value);
        break;
      case "updatedDate":
        data.lastUpdatedDate ??= parseGenericDate(value);
        break;
      case "nameserver":
        data.nameservers.push(value.toLowerCase().split(/\s+/)[0]!);
        break;
      case "dnssec":
        data.dnssec ??= value;
        break;
    }
  }

  if (data.status?.length) {
    data.status = Array.from(new Set(data.status));
  }
  return data;
}

function vcard(
  props: Array<[string, Record<string, unknown>, string, unknown]>,
): RdapVcardArray {
  return ["vcard", [["version", {}, "text", "4.0"], ...props]];
}

export function genericWhoisToRdap(raw: string, opts: ConvertOptions = {}): RdapDomain {
  const data = parseGenericWhois(raw);
  const ldhName = (opts.domain ?? data.domain ?? "").toLowerCase();

  const events: RdapEvent[] = [];
  if (data.registeredDate)
    events.push({ eventAction: "registration", eventDate: data.registeredDate });
  if (data.lastUpdatedDate)
    events.push({ eventAction: "last changed", eventDate: data.lastUpdatedDate });
  if (data.expirationDate)
    events.push({ eventAction: "expiration", eventDate: data.expirationDate });

  const entities: RdapEntity[] = [];

  if (data.registrant || data.registrantEmail) {
    const props: Array<[string, Record<string, unknown>, string, unknown]> = [];
    if (data.registrant) props.push(["fn", {}, "text", data.registrant]);
    if (data.registrantEmail) props.push(["email", {}, "text", data.registrantEmail]);
    entities.push({
      objectClassName: "entity",
      roles: ["registrant"],
      vcardArray: vcard(props),
    });
  }

  if (data.registrar) {
    entities.push({
      objectClassName: "entity",
      roles: ["registrar"],
      vcardArray: vcard([["fn", {}, "text", data.registrar]]),
    });
  }

  const nameservers: RdapNameserver[] = data.nameservers.map((host) => ({
    objectClassName: "nameserver",
    ldhName: host,
  }));

  const result: RdapDomain = { objectClassName: "domain", ldhName };
  if (opts.includeConformance !== false) result.rdapConformance = ["rdap_level_0"];
  if (data.status?.length) result.status = data.status;
  if (entities.length) result.entities = entities;
  if (nameservers.length) result.nameservers = nameservers;
  if (events.length) result.events = events;
  if (data.dnssec) {
    const v = data.dnssec.toLowerCase();
    const signed = v === "signed" || v === "signeddelegation";
    result.secureDNS = { delegationSigned: signed };
  }

  return finalize(result, raw, opts);
}
