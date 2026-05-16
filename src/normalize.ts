import type { RdapDomain } from "./types.js";

/** Lowercase ldhName on the domain and any nameservers. Mutates and returns the input. */
export function normalizeLdhCase(rdap: RdapDomain): RdapDomain {
  if (rdap.ldhName) rdap.ldhName = rdap.ldhName.toLowerCase();
  if (rdap.nameservers) {
    for (const ns of rdap.nameservers) {
      if (ns.ldhName) ns.ldhName = ns.ldhName.toLowerCase();
    }
  }
  return rdap;
}
