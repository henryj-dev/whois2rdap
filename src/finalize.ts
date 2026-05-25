import { normalizeLdhCase } from "./normalize.js";
import type { ConvertOptions, RdapDomain, RdapNotice } from "./types.js";

export function finalize(rdap: RdapDomain, whois: string, options: ConvertOptions): RdapDomain {
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
