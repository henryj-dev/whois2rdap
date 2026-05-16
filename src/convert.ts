import { krWhoisToRdap } from "./parsers/kr.js";
import { cnWhoisToRdap } from "./parsers/cn.js";
import { normalizeLdhCase } from "./normalize.js";
import type { ConvertOptions, RdapDomain, RdapNotice } from "./types.js";

function detectKr(whois: string, domain: string): boolean {
  if (/\.kr$/i.test(domain)) return true;
  return /KISA\/KRNIC|KRNIC\s+WHOIS|whois\.kr/i.test(whois);
}

function detectCn(whois: string, domain: string): boolean {
  if (/\.cn$/i.test(domain)) return true;
  return /whois\.cnnic\.cn|CNNIC/i.test(whois) || /^ROID:\s/m.test(whois);
}

function finalize(rdap: RdapDomain, whois: string, options: ConvertOptions): RdapDomain {
  if (options.sourceServer) {
    rdap.port43 = options.sourceServer;
    const notice: RdapNotice = {
      title: "Source",
      description: [`Derived from WHOIS data served by ${options.sourceServer}.`],
    };
    rdap.notices = [...(rdap.notices ?? []), notice];
  }

  if (options.includeRawWhoisNotice && whois) {
    const notice: RdapNotice = {
      title: "Raw WHOIS data",
      description: whois.split(/\r?\n/),
    };
    rdap.notices = [...(rdap.notices ?? []), notice];
  }

  if (options.normalizeCase !== false) normalizeLdhCase(rdap);
  return rdap;
}

export function whoisToRdap(whois: string, options: ConvertOptions = {}): RdapDomain {
  const domain = options.domain ?? "";

  let base: RdapDomain;
  if (detectKr(whois, domain)) {
    base = krWhoisToRdap(whois, options);
  } else if (detectCn(whois, domain)) {
    base = cnWhoisToRdap(whois, options);
  } else {
    base = {
      objectClassName: "domain",
      ...(options.includeConformance === false ? {} : { rdapConformance: ["rdap_level_0"] }),
      ldhName: domain,
    };
  }

  return finalize(base, whois, options);
}
