/**
 * Classifies a raw WHOIS response before anything tries to parse it.
 *
 * A WHOIS server answers "no such domain", "you may not ask", and "here is the
 * record" over the same channel, in prose, with no status code. Handing all
 * three to a parser yields the same shrug — an object carrying nothing but the
 * name the caller already knew — so the three must be told apart here, up
 * front, or they cannot be told apart at all.
 *
 * Emptiness is not the signal. DENIC answers a registered domain with two
 * fields and nothing else ("Domain: denic.de / Status: connect"), so a thin
 * result is not evidence of a thin answer. Only the response's shape and
 * wording distinguish them.
 */

/** Comment conventions: % (RIPE-style), # — plus JPRS's "[ banner ]" lines. */
const COMMENT = /^\s*[%#]|^\s*\[\s/;

/**
 * A "key: value" line, in every shape registries use:
 *   Domain Name: x     most registries (.ax and .tg pad the key with dots)
 *   ** Domain Name: x  TRABIS (.tr) bullets its fields
 *   [Domain Name]  x   JPRS
 * The key length is capped so that prose sentences ending in a colon — legal
 * notices are full of them — are not mistaken for fields.
 */
const FIELD_LINE = /^\s*(?:\*+\s*)?(?:[a-z][a-z0-9 _/-]{0,30}\s*[.:]+|\[[^\]]{1,40}\])\s*\S/i;

/** The server turned us away. */
const REFUSED =
  /requests? of this client (are|is) not permitted|access will only be enabled|rate.?limit|quota exceeded|too many requests|excessive querying|try again later|access denied|permission denied|you have been blocked/i;

/**
 * The name is not registered, reserved, or otherwise refused registration.
 * Verified against 102 real records from distinct registries: none of them
 * trips these patterns, so testing the whole response — boilerplate included —
 * is safe, and it catches registries that report the verdict outside any field
 * (.cn: "the Domain Name you apply can not be registered online") or behind a
 * ">>>" marker (.xn--2scrj9c).
 */
const UNREGISTERED =
  /\bno match\b|\bnot found\b|no object found|no entries found|no data found|nothing found|not known in|can ?not be registered|cannot be registered|prohibited string|not available for registration|available for registration|reserved domain name|usage restrictions|name is not available|registration status: (invalid|free|available)|error code:/i;

/** What a WHOIS server's response actually is. */
export type WhoisResponseKind =
  /** A real registration — safe to parse. */
  | "record"
  /** The registry says the name is not registered or is reserved. */
  | "not-found"
  /** The server rejected the query: blocked, rate-limited, or IP-restricted. */
  | "refused"
  /** None of the above — no record we can recognize, and no stated reason. */
  | "unknown";

/** The non-comment "key: value" lines of a response. */
export function whoisFieldLines(body: string): string[] {
  return body
    .split("\n")
    .map((l) => l.replace(/\r$/, ""))
    .filter((l) => !COMMENT.test(l) && FIELD_LINE.test(l));
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Whether the response names the domain we asked about. A punycode query is
 * often echoed back in Unicode — TWNIC answers "nic.xn--kprw13d" with
 * "Domain Name: nic.台灣" — so fall back to matching the leading label inside a
 * domain-name field.
 */
export function whoisEchoesDomain(text: string, domain: string): boolean {
  if (text.toLowerCase().includes(domain.toLowerCase())) return true;
  const label = escapeRe(domain.split(".")[0] ?? "");
  if (!label) return false;
  return new RegExp(`\\[?domain\\s?name\\]?\\s*[.:]*\\s*${label}\\.`, "im").test(text);
}

/**
 * A real record: at least one field line naming our domain. One is enough —
 * .im answers with a bare "Domain Name: nic.im" above unkeyed prose sections.
 */
export function whoisHasRecord(text: string, domain: string): boolean {
  const fields = whoisFieldLines(text);
  return fields.length >= 1 && whoisEchoesDomain(fields.join("\n"), domain);
}

/**
 * Order matters. The unregistered check runs first because registries report a
 * reserved name *inside* an otherwise well-formed record (.bw answers nic.bw
 * with real fields plus "Domain Cannot Be Registered"). The refusal check runs
 * last because notices attached to good records mention rate limiting — .co
 * ends every record with "Access to the Whois and RDAP services is rate
 * limited", which must not read as a rejection.
 */
export function classifyWhoisResponse(body: string, domain: string): WhoisResponseKind {
  if (UNREGISTERED.test(body)) return "not-found";
  if (whoisHasRecord(body, domain)) return "record";
  if (REFUSED.test(body)) return "refused";
  return "unknown";
}

/** The server's own words, for error messages: its first line of substance. */
export function whoisResponseHint(body: string): string | undefined {
  return (
    body
      .split("\n")
      .map((l) => l.trim())
      .find((l) => l && !/^[%#[>*]/.test(l))
      ?.slice(0, 120) || undefined
  );
}
