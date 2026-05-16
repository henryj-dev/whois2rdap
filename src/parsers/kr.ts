import type {
  RdapDomain,
  RdapEntity,
  RdapEvent,
  RdapNameserver,
  RdapVcardArray,
} from "../types.js";

export interface KrNameserver {
  host: string;
  ip?: string;
}

export interface KrWhoisData {
  domain?: string;
  registrant?: string;
  registrantAddress?: string;
  registrantZip?: string;
  adminName?: string;
  adminEmail?: string;
  adminPhone?: string;
  registrar?: string;
  registeredDate?: string;
  lastUpdatedDate?: string;
  expirationDate?: string;
  dnssec?: string;
  status?: string[];
  nameservers: KrNameserver[];
}

// RFC 8056 §2 — map EPP status names to RDAP status strings.
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

const FIELD = /^([^:]+?)\s*:\s*(.*)$/;

function parseKrDate(value: string): string | undefined {
  // KRNIC format: "2020. 01. 01." (also handles single-digit month/day)
  const m = value.match(/(\d{4})\.\s*(\d{1,2})\.\s*(\d{1,2})/);
  if (!m) return undefined;
  const y = m[1]!;
  const mo = m[2]!.padStart(2, "0");
  const d = m[3]!.padStart(2, "0");
  return `${y}-${mo}-${d}T00:00:00Z`;
}

export function parseKrWhois(raw: string): KrWhoisData {
  const data: KrWhoisData = { nameservers: [] };
  const lines = raw.split(/\r?\n/);

  // Prefer the English section when present — field names are stable there.
  const englishStart = lines.findIndex((l) => /^#\s*ENGLISH\b/i.test(l));
  const section = englishStart >= 0 ? lines.slice(englishStart) : lines;

  let currentNs: KrNameserver | null = null;
  const flushNs = () => {
    if (currentNs && currentNs.host) data.nameservers.push(currentNs);
    currentNs = null;
  };

  for (const rawLine of section) {
    const line = rawLine.trimEnd();
    if (!line.trim()) {
      flushNs();
      continue;
    }

    if (/Name Server\s*$/i.test(line) || /네임서버 정보\s*$/.test(line)) {
      flushNs();
      currentNs = { host: "" };
      continue;
    }

    const m = line.match(FIELD);
    if (!m) continue;
    const key = m[1]!.trim();
    const value = m[2]!.trim();
    if (!value) continue;

    if (currentNs) {
      if (/^Host Name$/i.test(key) || /^호스트이름$/.test(key)) {
        currentNs.host = value;
        continue;
      }
      if (/^IP Address$/i.test(key) || /^IP 주소$/.test(key)) {
        currentNs.ip = value;
        continue;
      }
      flushNs();
    }

    switch (key) {
      case "Domain Name":
      case "도메인이름":
        data.domain ??= value.toLowerCase();
        break;
      case "Registrant":
      case "등록인":
        data.registrant ??= value;
        break;
      case "Registrant Address":
      case "등록인 주소":
        data.registrantAddress ??= value;
        break;
      case "Registrant Zip Code":
      case "등록인 우편번호":
        data.registrantZip ??= value;
        break;
      case "Administrative Contact(AC)":
      case "책임자":
        data.adminName ??= value;
        break;
      case "AC E-Mail":
      case "책임자 전자우편":
        data.adminEmail ??= value;
        break;
      case "AC Phone Number":
      case "책임자 전화번호":
        data.adminPhone ??= value;
        break;
      case "Authorized Agency":
      case "등록대행자":
      case "등록기관":
        data.registrar ??= value;
        break;
      case "Registered Date":
      case "등록일":
        data.registeredDate ??= parseKrDate(value);
        break;
      case "Last Updated Date":
      case "최근 정보 변경일":
        data.lastUpdatedDate ??= parseKrDate(value);
        break;
      case "Expiration Date":
      case "사용 종료일":
        data.expirationDate ??= parseKrDate(value);
        break;
      case "DNSSEC":
        data.dnssec ??= value;
        break;
      case "Domain Status":
      case "등록정보 보호": {
        const statuses = normalizeStatus(value);
        if (statuses.length) data.status ??= statuses;
        break;
      }
    }
  }

  flushNs();
  return data;
}

function vcard(
  props: Array<[string, Record<string, unknown>, string, unknown]>,
): RdapVcardArray {
  return ["vcard", [["version", {}, "text", "4.0"], ...props]];
}

export interface KrConvertOptions {
  domain?: string;
  includeConformance?: boolean;
}

export function krWhoisToRdap(raw: string, opts: KrConvertOptions = {}): RdapDomain {
  const data = parseKrWhois(raw);
  const ldhName = (opts.domain ?? data.domain ?? "").toLowerCase();

  const events: RdapEvent[] = [];
  if (data.registeredDate)
    events.push({ eventAction: "registration", eventDate: data.registeredDate });
  if (data.lastUpdatedDate)
    events.push({ eventAction: "last changed", eventDate: data.lastUpdatedDate });
  if (data.expirationDate)
    events.push({ eventAction: "expiration", eventDate: data.expirationDate });

  const entities: RdapEntity[] = [];

  if (data.registrant) {
    const props: Array<[string, Record<string, unknown>, string, unknown]> = [
      ["fn", {}, "text", data.registrant],
    ];
    if (data.registrantAddress || data.registrantZip) {
      props.push([
        "adr",
        data.registrantZip ? { code: data.registrantZip } : {},
        "text",
        ["", "", data.registrantAddress ?? "", "", "", data.registrantZip ?? "", ""],
      ]);
    }
    entities.push({
      objectClassName: "entity",
      roles: ["registrant"],
      vcardArray: vcard(props),
    });
  }

  if (data.adminName || data.adminEmail || data.adminPhone) {
    const props: Array<[string, Record<string, unknown>, string, unknown]> = [];
    if (data.adminName) props.push(["fn", {}, "text", data.adminName]);
    if (data.adminEmail) props.push(["email", {}, "text", data.adminEmail]);
    if (data.adminPhone)
      props.push(["tel", { type: ["voice"] }, "uri", `tel:${data.adminPhone}`]);
    entities.push({
      objectClassName: "entity",
      roles: ["administrative"],
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

  const nameservers: RdapNameserver[] = data.nameservers
    .filter((n) => n.host)
    .map((n) => {
      const ns: RdapNameserver = {
        objectClassName: "nameserver",
        ldhName: n.host.toLowerCase(),
      };
      if (n.ip) {
        const isV6 = n.ip.includes(":");
        ns.ipAddresses = isV6 ? { v6: [n.ip] } : { v4: [n.ip] };
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
    const signed = v === "signed" || (/서명/.test(data.dnssec) && !/미서명/.test(data.dnssec));
    result.secureDNS = { delegationSigned: signed };
  }

  return result;
}
