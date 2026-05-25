import { krWhoisToRdap } from "./parsers/kr.js";
import { cnWhoisToRdap } from "./parsers/cn.js";
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

export function whoisToRdap(whois: string, options: ConvertOptions = {}): RdapDomain {
  const domain = options.domain ?? "";

  if (detectKr(whois, domain)) {
    return krWhoisToRdap(whois, options);
  }
  if (detectCn(whois, domain)) {
    return cnWhoisToRdap(whois, options);
  }
  // Generic parser handles all other TLDs.
  return genericWhoisToRdap(whois, options);
}
