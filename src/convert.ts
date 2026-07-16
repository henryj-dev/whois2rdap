import { krWhoisToRdap } from "./parsers/kr.js";
import { cnWhoisToRdap } from "./parsers/cn.js";
import { seWhoisToRdap } from "./parsers/se.js";
import { jpWhoisToRdap } from "./parsers/jp.js";
import { genericWhoisToRdap } from "./parsers/generic.js";
import type { ConvertOptions, RdapDomain } from "./types.js";

function detectKr(whois: string, domain: string): boolean {
  if (/\.kr$/i.test(domain)) return true;
  return /KISA\/KRNIC|KRNIC\s+WHOIS|whois\.kr/i.test(whois);
}

function detectCn(whois: string, domain: string): boolean {
  if (/\.cn$/i.test(domain)) return true;
  return /whois\.cnnic\.cn|CNNIC/i.test(whois) || /^ROID:\s/m.test(whois);
}

function detectSe(whois: string, domain: string): boolean {
  if (/\.se$/i.test(domain)) return true;
  return /whois\.iis\.se|\.se top level domain|Swedish Internet Foundation/i.test(whois);
}

function detectJp(whois: string, domain: string): boolean {
  if (/\.jp$/i.test(domain)) return true;
  // The JPRS banner and its bracket-key layout are unmistakable.
  return /whois\.jprs\.jp|\[Domain Name\]|\[ドメイン(?:名|情報)\]/.test(whois);
}

export function whoisToRdap(whois: string, options: ConvertOptions = {}): RdapDomain {
  const domain = options.domain ?? "";

  if (detectKr(whois, domain)) {
    return krWhoisToRdap(whois, options);
  }
  if (detectCn(whois, domain)) {
    return cnWhoisToRdap(whois, options);
  }
  if (detectSe(whois, domain)) {
    return seWhoisToRdap(whois, options);
  }
  if (detectJp(whois, domain)) {
    return jpWhoisToRdap(whois, options);
  }
  // Generic parser handles all other TLDs.
  return genericWhoisToRdap(whois, options);
}
