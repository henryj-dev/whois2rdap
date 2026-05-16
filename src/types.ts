/**
 * Minimal RDAP domain object types based on RFC 9083.
 * Only the fields commonly produced from WHOIS conversion are modeled.
 */

export type RdapStatus = string;

export interface RdapEvent {
  eventAction:
    | "registration"
    | "expiration"
    | "last changed"
    | "transfer"
    | "deletion"
    | "reregistration"
    | "last update of RDAP database"
    | (string & {});
  eventDate: string;
  eventActor?: string;
}

export interface RdapNotice {
  title?: string;
  description: string[];
  links?: RdapLink[];
}

export interface RdapLink {
  value?: string;
  rel?: string;
  href: string;
  type?: string;
}

export type RdapVcardArray = ["vcard", Array<[string, Record<string, unknown>, string, unknown]>];

export interface RdapEntity {
  objectClassName: "entity";
  handle?: string;
  roles?: string[];
  vcardArray?: RdapVcardArray;
  entities?: RdapEntity[];
  publicIds?: Array<{ type: string; identifier: string }>;
  status?: RdapStatus[];
  events?: RdapEvent[];
}

export interface RdapNameserver {
  objectClassName: "nameserver";
  ldhName: string;
  unicodeName?: string;
  ipAddresses?: { v4?: string[]; v6?: string[] };
}

export interface RdapDomain {
  objectClassName: "domain";
  rdapConformance?: string[];
  handle?: string;
  ldhName: string;
  unicodeName?: string;
  status?: RdapStatus[];
  entities?: RdapEntity[];
  nameservers?: RdapNameserver[];
  events?: RdapEvent[];
  notices?: RdapNotice[];
  links?: RdapLink[];
  secureDNS?: { delegationSigned?: boolean };
  publicIds?: Array<{ type: string; identifier: string }>;
  /** RFC 9083 §4.7 — source WHOIS server hostname. */
  port43?: string;
}

export interface ConvertOptions {
  /** Domain name override if not detectable from the WHOIS payload. */
  domain?: string;
  /** Include rdapConformance array in output. Defaults to true. */
  includeConformance?: boolean;
  /** Source WHOIS server — emitted as `port43` and referenced in a notice. */
  sourceServer?: string;
  /** Embed the raw WHOIS text as an additional notice. Defaults to false. */
  includeRawWhoisNotice?: boolean;
  /** Lowercase ldhName fields on the domain and nameservers. Defaults to true. */
  normalizeCase?: boolean;
}
