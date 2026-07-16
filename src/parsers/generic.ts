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
  active: "active",
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
  jan: "01", january: "01",
  feb: "02", february: "02",
  mar: "03", march: "03",
  apr: "04", april: "04",
  may: "05",
  jun: "06", june: "06",
  jul: "07", july: "07",
  aug: "08", august: "08",
  sep: "09", sept: "09", september: "09",
  oct: "10", october: "10",
  nov: "11", november: "11",
  dec: "12", december: "12",
};

export function parseGenericDate(value: string): string | undefined {
  // Strip trailing parenthetical remarks (e.g. "(JST)"), timezone words, and
  // "at HH:MM:SS" suffixes that some registries bolt onto a plain date.
  let v = value.trim().replace(/\s*\(.*\)\s*$/, "").trim();
  if (!v) return undefined;

  // ISO 8601 with Z or offset (strip sub-seconds): 2024-01-15T00:00:00.000Z
  const isoFull = v.match(/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})/);
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

  // Dot- or slash-separated ISO order: 2024.01.15 or 2024/01/15
  const ymdSep = v.match(/^(\d{4})[./](\d{2})[./](\d{2})/);
  if (ymdSep) return `${ymdSep[1]}-${ymdSep[2]}-${ymdSep[3]}T00:00:00Z`;

  // DD.MM.YYYY or DD/MM/YYYY (day first): 05.09.2016, 07/03/2000
  const dmySep = v.match(/^(\d{1,2})[./](\d{1,2})[./](\d{4})/);
  if (dmySep) {
    return `${dmySep[3]}-${dmySep[2]!.padStart(2, "0")}-${dmySep[1]!.padStart(2, "0")}T00:00:00Z`;
  }

  // DD-Mon-YYYY: 15-Jan-2024
  const dmyAlpha = v.match(/^(\d{1,2})-([A-Za-z]{3,})-(\d{4})/);
  if (dmyAlpha) {
    const mo = MONTHS[dmyAlpha[2]!.toLowerCase()];
    if (mo) return `${dmyAlpha[3]}-${mo}-${dmyAlpha[1]!.padStart(2, "0")}T00:00:00Z`;
  }

  // YYYY-Mon-DD: 2024-Aug-26 (TRABIS, with a trailing period this ignores).
  const ymdAlpha = v.match(/^(\d{4})-([A-Za-z]{3,})-(\d{1,2})/);
  if (ymdAlpha) {
    const mo = MONTHS[ymdAlpha[2]!.toLowerCase()];
    if (mo) return `${ymdAlpha[1]}-${mo}-${ymdAlpha[3]!.padStart(2, "0")}T00:00:00Z`;
  }

  // Mon-DD-YYYY: Jan-15-2024
  const mdyAlpha = v.match(/^([A-Za-z]{3,})-(\d{1,2})-(\d{4})/);
  if (mdyAlpha) {
    const mo = MONTHS[mdyAlpha[1]!.toLowerCase()];
    if (mo) return `${mdyAlpha[3]}-${mo}-${mdyAlpha[2]!.padStart(2, "0")}T00:00:00Z`;
  }

  // Ordinal long form (UK registries): "24th April 1997", "01st January 2020".
  const ordinal = v.match(/^(\d{1,2})(?:st|nd|rd|th)?\s+([A-Za-z]+)\s+(\d{4})/i);
  if (ordinal) {
    const mo = MONTHS[ordinal[2]!.toLowerCase()];
    if (mo) return `${ordinal[3]}-${mo}-${ordinal[1]!.padStart(2, "0")}T00:00:00Z`;
  }

  // "Mon DD YYYY" with optional weekday (.be: "Wed Apr 1 1998").
  const wdMonth = v.match(/^(?:[A-Za-z]{3,}\s+)?([A-Za-z]{3,})\s+(\d{1,2})\s+(\d{4})/);
  if (wdMonth) {
    const mo = MONTHS[wdMonth[1]!.toLowerCase()];
    if (mo) return `${wdMonth[3]}-${mo}-${wdMonth[2]!.padStart(2, "0")}T00:00:00Z`;
  }

  return undefined;
}

const eppStatus = (s: string): string | undefined =>
  EPP_TO_RDAP_STATUS[s] ?? EPP_TO_RDAP_STATUS[s.toLowerCase()];

export function normalizeGenericStatus(value: string): string[] {
  // ICANN-era WHOIS appends a URL after each status code:
  // "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited"
  const noUrl = value.replace(/https?:\/\/\S+/g, "").trim();
  if (!noUrl) return [];

  // A registry lists statuses comma-separated (".bg: busy, active") or one per
  // line; a free-text status ("NOT AVAILABLE", "Registered until cancelled") is
  // a phrase that must not be shattered into words. So split on commas, then map
  // each part — expanding to words only when every word is a known EPP status.
  const out: string[] = [];
  for (const part of noUrl.split(/\s*,\s*/)) {
    const p = part.trim();
    if (!p) continue;
    const words = p.split(/\s+/);
    if (words.length > 1 && words.every(eppStatus)) out.push(...words.map((w) => eppStatus(w)!));
    else out.push(eppStatus(p) ?? p);
  }
  return out;
}

type Canonical =
  | "domain"
  | "status"
  | "registrant"
  | "registrantOrg"
  | "registrantEmail"
  | "registrar"
  | "registrarName"
  | "createdDate"
  | "expiresDate"
  | "updatedDate"
  | "nameserver"
  | "dnssec";

// Maps a raw WHOIS field key to a canonical name, across the label variants and
// languages registries use. Order matters: earlier, more specific patterns win.
const KEY_PATTERNS: Array<[RegExp, Canonical]> = [
  // Domain name — English, French (nom de domaine), block-style (domainname).
  [/^(?:domain(?:[ _]?name)?|domainname|nom de domaine|ascii)$/i, "domain"],
  // Status / flags / EPP.
  [/^(?:domain[ _]?status|status|statut|estado|flags?|epp[ _]?status|registration status)$/i, "status"],
  // Registrant org sits before the looser registrant catch-all.
  [/^(?:registrant[ _]?(?:org(?:aniz?ation)?)|organization name|organisation name|owner org(?:aniz?ation)?)$/i, "registrantOrg"],
  [/^(?:registrant(?:[ _](?:name|contact))?|owner|holder|domain holder|titular)$/i, "registrant"],
  [/^registrant[ _]?(?:contact[ _]?)?e-?mail$/i, "registrantEmail"],
  // Registrar — "Name:" nested under a Registrar block maps to registrarName.
  [/^(?:sponsoring[ _]?)?registrar$|^registrar[ _]?name$|^registrar-name$/i, "registrar"],
  // Dates. Multilingual + block-style single words (created/registered/changed/expire).
  [/^(?:creation[ _]?(?:date|time)|created(?:[ _]?on)?|registered(?:[ _]?on)?|registration[ _]?(?:date|time)|domain[ _]?registration[ _]?date|registration[ _]?date[ _]?time|record[ _]?created(?:[ _]?on)?|activation|date de création|domain[ _]?record[ _]?activated)$/i, "createdDate"],
  [/^(?:registry[ _]?expiry[ _]?date|expir(?:ation|y)[ _]?(?:date|time)?|expires?(?:[ _]?on)?|expire|paid-till|domain[ _]?expiration[ _]?date|registrar[ _]?registration[ _]?expiration[ _]?date|record[ _]?expires(?:[ _]?on)?|domain[ _]?expires)$/i, "expiresDate"],
  [/^(?:updated[ _]?date|last[ _]?(?:modified|updated?(?:[ _]?time)?)|modified|changed|dernière modification|domain[ _]?record[ _]?last[ _]?updated)$/i, "updatedDate"],
  // Nameservers — "name server", block-style "nserver", "dns servers", and the
  // ".bg" block header "name server information".
  [/^(?:name[ _]?servers?(?:[ _]information)?|nameservers?|nserver|dns[ _]?servers?|domain[ _]?name[ _]?servers?)$/i, "nameserver"],
  // DNSSEC. As a block header ("Keys:", EURid) it must swallow its DNSKEY body —
  // "flags:KSK protocol:3 pubKey:…" — which would otherwise leak into status.
  [/^(?:dnssec|keys?|signing[ _]?key|dnskey|ds[ _]?(?:record|rdata))$/i, "dnssec"],
];

function classifyKey(raw: string): Canonical | null {
  for (const [re, name] of KEY_PATTERNS) {
    if (re.test(raw)) return name;
  }
  return null;
}

/**
 * Normalizes a raw field key: strips the decorations registries wrap keys in —
 * "** Domain Name" (TRABIS bullets), "domain........" (dot padding, .ax/.kz/.tn),
 * surrounding brackets — and collapses internal whitespace.
 */
function normalizeKey(raw: string): string {
  return raw
    .replace(/^\s*\*+\s*/, "") // ** bullet prefix
    .replace(/^\[|\]$/g, "") // [bracket] keys
    .replace(/[.\s]+$/, "") // trailing dot padding / whitespace
    .replace(/\s+/g, " ")
    .trim();
}

// A hostname token: rejects the "(1.2.3.4)" / IP columns some registries append.
const HOST = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/i;

function pushNameserver(list: string[], token: string | undefined): void {
  if (token && HOST.test(token)) list.push(token.toLowerCase());
}

// Bare date lines with no colon key: ".mo" → "Record created on 1993-01-01 …",
// ".gg" → "Registered on 24th April 1997 at 00:00:00". Captures the verb so the
// date lands in the right event.
const DATE_LINE =
  /^(record created|created|registered|record expires?|expires?|renewal|last updated|modified)\s+(?:on|date|until)?\s*[:]?\s*(.+)$/i;

function dateLineCanonical(verb: string): Canonical | null {
  const v = verb.toLowerCase();
  if (/expir|renewal/.test(v)) return "expiresDate";
  if (/updated|modified/.test(v)) return "updatedDate";
  if (/created|registered/.test(v)) return "createdDate";
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

/**
 * Parses the two structural shapes registries use, in one pass:
 *
 *   inline   Key: value                       — most registries
 *   block    Key:                             — EURid, DNS Belgium, CentralNic
 *              value                             (.eu/.be/.gg/.je), where the
 *              Subkey: value                     value(s) sit on indented lines
 *                                                below and may themselves be
 *                                                sub-fields.
 *
 * A block is opened by a recognized key whose inline value is empty; subsequent
 * lines indented past it belong to it until the indentation returns.
 */
export function parseGenericWhois(raw: string): GenericWhoisData {
  const data: GenericWhoisData = { nameservers: [] };
  const setOnce = <K extends keyof GenericWhoisData>(k: K, v: GenericWhoisData[K]) => {
    if (v != null && data[k] == null) data[k] = v;
  };
  const addStatus = (value: string) => {
    const s = normalizeGenericStatus(value);
    if (s.length) (data.status ??= []).push(...s);
  };
  const assign = (canonical: Canonical, value: string) => {
    if (!value) return;
    switch (canonical) {
      case "domain": setOnce("domain", value.toLowerCase().split(/\s+/)[0]); break;
      case "status": addStatus(value); break;
      case "registrant": setOnce("registrant", value); break;
      case "registrantOrg": setOnce("registrant", value); break;
      case "registrantEmail": setOnce("registrantEmail", value); break;
      case "registrar": case "registrarName": setOnce("registrar", value); break;
      case "createdDate": setOnce("registeredDate", parseGenericDate(value)); break;
      case "expiresDate": setOnce("expirationDate", parseGenericDate(value)); break;
      case "updatedDate": setOnce("lastUpdatedDate", parseGenericDate(value)); break;
      case "nameserver": pushNameserver(data.nameservers, value.split(/\s+/)[0]); break;
      case "dnssec": setOnce("dnssec", value); break;
    }
  };

  // The open block: its canonical key and the indent of its header line.
  let block: { canonical: Canonical; indent: number } | null = null;

  for (const rawLine of raw.split(/\r?\n/)) {
    if (!rawLine.trim()) continue; // blank lines do not close a block
    const indent = rawLine.length - rawLine.trimStart().length;
    const line = rawLine.trim();
    if (line.startsWith("%") || line.startsWith(";") || line.startsWith("#") || line.startsWith(">>>")) {
      continue;
    }

    // Leaving the block's indentation closes it.
    if (block && indent <= block.indent) block = null;

    const m = line.match(FIELD);
    if (m) {
      const key = normalizeKey(m[1]!);
      const value = m[2]!.trim();
      const canonical = classifyKey(key);

      if (block && indent > block.indent) {
        // Inside a DNSSEC block, every child is key material — swallow it so a
        // "flags:KSK protocol:3 pubKey:…" line cannot leak into status.
        if (block.canonical === "dnssec") {
          setOnce("dnssec", "signed");
          continue;
        }
        // Inside a block: a sub-field. "Name:"/"Organisation:" carry the block's
        // registrar/registrant identity; anything else recognized still assigns.
        if (/^(name|org(?:anisation|anization)?)$/i.test(key)) {
          assign(block.canonical, value || key);
        } else if (canonical) {
          assign(canonical, value);
        } else {
          pushNameserver(data.nameservers, block.canonical === "nameserver" ? line.split(/\s+/)[0] : undefined);
        }
        continue;
      }

      if (value) {
        block = null;
        if (canonical) assign(canonical, value);
        else {
          // An unrecognized "key: value" may be a date phrase whose own time
          // component supplied the colon we split on — ".mo" emits
          // "Record created on 1993-01-01 08:00:00", which splits into a
          // nonsense key. Re-read the whole line as a bare date line.
          const d = line.match(DATE_LINE);
          const c = d && dateLineCanonical(d[1]!);
          if (c) assign(c, d![2]!);
        }
      } else if (canonical) {
        // Empty inline value → open a block for the indented lines that follow.
        block = { canonical, indent };
        // A "Keys:" header alone attests a signed delegation.
        if (canonical === "dnssec") setOnce("dnssec", "signed");
      } else {
        block = null;
      }
      continue;
    }

    // No colon. Either a block body line, or a bare "Registered on <date>" line.
    if (block && indent > block.indent) {
      if (block.canonical === "dnssec") continue; // swallow key material
      if (block.canonical === "nameserver") pushNameserver(data.nameservers, line.split(/\s+/)[0]);
      else if (block.canonical === "status") addStatus(line);
      else if (block.canonical === "registrant") setOnce("registrant", line);
      else {
        const d = line.match(DATE_LINE);
        const c = d && dateLineCanonical(d[1]!);
        if (c) assign(c, d![2]!);
      }
      continue;
    }
    const d = line.match(DATE_LINE);
    const c = d && dateLineCanonical(d[1]!);
    if (c) assign(c, d![2]!);
  }

  if (data.status?.length) data.status = Array.from(new Set(data.status));
  data.nameservers = Array.from(new Set(data.nameservers));
  return data;
}

function vcard(
  props: Array<[string, Record<string, unknown>, string, unknown]>,
): RdapVcardArray {
  return ["vcard", [["version", {}, "text", "4.0"], ...props]];
}

/**
 * Assembles an RDAP `domain` object from the fields a parser extracted. Shared
 * by the generic parser and any TLD parser that produces a `GenericWhoisData`
 * (e.g. JPRS), so the WHOIS→RDAP mapping lives in exactly one place.
 */
export function buildRdapDomain(
  data: GenericWhoisData,
  raw: string,
  opts: ConvertOptions = {},
): RdapDomain {
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
    const signed = v === "signed" || v === "signeddelegation" || v === "yes";
    result.secureDNS = { delegationSigned: signed };
  }

  return finalize(result, raw, opts);
}

export function genericWhoisToRdap(raw: string, opts: ConvertOptions = {}): RdapDomain {
  return buildRdapDomain(parseGenericWhois(raw), raw, opts);
}
