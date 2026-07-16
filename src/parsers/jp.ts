import type { ConvertOptions, RdapDomain } from "../types.js";
import {
  buildRdapDomain,
  normalizeGenericStatus,
  parseGenericDate,
  type GenericWhoisData,
} from "./generic.js";

/**
 * JPRS (.jp) WHOIS parser.
 *
 * JPRS uses a bracket-key layout unlike any other registry:
 *
 *   [Domain Name]                   JPRS.JP
 *   [登録者名]                      株式会社日本レジストリサービス
 *   [Name Server]                   ns1.jprs.jp
 *   [登録年月日]                    2001/02/02
 *   [有効期限]                      2027/02/28
 *   [状態]                          Active
 *
 * The key sits in brackets; the value follows after whitespace. Crucially, the
 * registration date, expiry, and status are labelled only in Japanese — an
 * English-only key map would miss every date — so both scripts are mapped.
 */

// Bracketed keys, Japanese and English, → canonical field.
const JP_KEYS: Array<[RegExp, keyof GenericWhoisData | "signingKey"]> = [
  [/^(?:Domain Name|ドメイン名)$/i, "domain"],
  [/^(?:Registrant|登録者名)$/i, "registrant"],
  [/^(?:Name Server|ネームサーバ)$/i, "nameservers"],
  [/^(?:登録年月日|Created(?: Date)?)$/i, "registeredDate"], // registration date
  [/^(?:有効期限|Expires(?: Date)?)$/i, "expirationDate"], // expiry
  [/^(?:最終更新|Last Update(?:d)?)$/i, "lastUpdatedDate"], // last updated
  [/^(?:状態|ロック状態|Status)$/i, "status"], // state / lock state
  [/^(?:Signing Key|DNSSEC)$/i, "signingKey"], // presence ⇒ signed delegation
];

// "[Key]<whitespace>value" — value may be empty (indented continuations, which
// this line-oriented pass ignores).
const JP_LINE = /^\[([^\]]+)\]\s*(.*)$/;

export function parseJpWhois(raw: string): GenericWhoisData {
  const data: GenericWhoisData = { nameservers: [] };

  for (const rawLine of raw.split(/\r?\n/)) {
    const m = rawLine.match(JP_LINE);
    if (!m) continue;
    const key = m[1]!.trim();
    const value = m[2]!.trim();
    if (!value) continue;

    const hit = JP_KEYS.find(([re]) => re.test(key));
    if (!hit) continue;

    switch (hit[1]) {
      case "domain":
        data.domain ??= value.toLowerCase().split(/\s+/)[0];
        break;
      case "registrant":
        // English "[Registrant]" follows the Japanese "[登録者名]"; prefer the
        // first (Japanese) only if no value yet, but overwrite-nothing keeps it.
        data.registrant ??= value;
        break;
      case "nameservers": {
        const host = value.split(/\s+/)[0]!.toLowerCase();
        if (host && !data.nameservers.includes(host)) data.nameservers.push(host);
        break;
      }
      case "registeredDate":
        data.registeredDate ??= parseGenericDate(value);
        break;
      case "expirationDate":
        data.expirationDate ??= parseGenericDate(value);
        break;
      case "lastUpdatedDate":
        data.lastUpdatedDate ??= parseGenericDate(value);
        break;
      case "status": {
        const s = normalizeGenericStatus(value);
        if (s.length) (data.status ??= []).push(...s);
        break;
      }
      case "signingKey":
        data.dnssec ??= "signed";
        break;
    }
  }

  if (data.status?.length) data.status = Array.from(new Set(data.status));
  return data;
}

export function jpWhoisToRdap(raw: string, opts: ConvertOptions = {}): RdapDomain {
  return buildRdapDomain(parseJpWhois(raw), raw, opts);
}
