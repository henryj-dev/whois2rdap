import type {
  RdapDomain,
  RdapEntity,
  RdapEvent,
  RdapNameserver,
  RdapVcardArray,
} from "../types.js";

export interface CnWhoisData {
  domain?: string;
  roid?: string;
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

const FIELD = /^([^:]+?)\s*:\s*(.*)$/;

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

function normalizeStatus(value: string): string[] {
  return value
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => EPP_TO_RDAP_STATUS[s] ?? s);
}

function parseCnDate(value: string): string | undefined {
  // CNNIC format: "2013-04-23 23:46:53" — assumed UTC.
  const m = value.match(/^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/);
  if (!m) return undefined;
  return `${m[1]}T${m[2]}Z`;
}

export function parseCnWhois(raw: string): CnWhoisData {
  const data: CnWhoisData = { nameservers: [] };
  for (const rawLine of raw.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const m = line.match(FIELD);
    if (!m) continue;
    const key = m[1]!.trim();
    const value = m[2]!.trim();
    if (!value) continue;

    switch (key) {
      case "Domain Name":
        data.domain ??= value.toLowerCase();
        break;
      case "ROID":
        data.roid ??= value;
        break;
      case "Domain Status": {
        const s = normalizeStatus(value);
        if (s.length) (data.status ??= []).push(...s);
        break;
      }
      case "Registrant":
      case "Registrant Name":
      case "Registrant Organization":
        data.registrant ??= value;
        break;
      case "Registrant Contact Email":
      case "Registrant Email":
        data.registrantEmail ??= value;
        break;
      case "Sponsoring Registrar":
      case "Registrar":
        data.registrar ??= value;
        break;
      case "Name Server":
        data.nameservers.push(value.toLowerCase());
        break;
      case "Registration Time":
      case "Creation Time":
        data.registeredDate ??= parseCnDate(value);
        break;
      case "Expiration Time":
        data.expirationDate ??= parseCnDate(value);
        break;
      case "Last Updated Time":
      case "Last Modified":
        data.lastUpdatedDate ??= parseCnDate(value);
        break;
      case "DNSSEC":
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

export interface CnConvertOptions {
  domain?: string;
  includeConformance?: boolean;
}

export function cnWhoisToRdap(raw: string, opts: CnConvertOptions = {}): RdapDomain {
  const data = parseCnWhois(raw);
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
  if (data.roid) result.handle = data.roid;
  if (data.status?.length) result.status = data.status;
  if (entities.length) result.entities = entities;
  if (nameservers.length) result.nameservers = nameservers;
  if (events.length) result.events = events;
  if (data.dnssec) {
    const v = data.dnssec.toLowerCase();
    const signed = v === "signed" || v === "signeddelegation";
    result.secureDNS = { delegationSigned: signed };
  }

  return result;
}
