/**
 * Lookup failures, split along the axis that matters to a caller: whether
 * retrying could ever help.
 */

export type WhoisUnavailableReason =
  /** The registry publishes no WHOIS service at all (e.g. .gb, .bv, .kp). */
  | "no-whois-server"
  /** WHOIS exists only behind a web form; nothing answers on port 43 (e.g. .gr). */
  | "web-only"
  /** Neither an RDAP service nor any known WHOIS server for this TLD. */
  | "no-source";

/**
 * No source of domain data exists for this TLD. Permanent: the same query will
 * fail the same way tomorrow, so callers may cache this outcome and must not
 * retry. Contrast with {@link WhoisQueryError}, which is transient.
 */
export class WhoisUnavailableError extends Error {
  override readonly name = "WhoisUnavailableError";
  /** Always true — distinguishes this from a transient failure. */
  readonly permanent = true;
  readonly tld: string;
  readonly reason: WhoisUnavailableReason;
  /** For `web-only`: where a human can run the query by hand. */
  readonly webUrl?: string;

  constructor(
    message: string,
    init: { tld: string; reason: WhoisUnavailableReason; webUrl?: string },
  ) {
    super(message);
    this.tld = init.tld;
    this.reason = init.reason;
    this.webUrl = init.webUrl;
  }
}

/**
 * A WHOIS server is known but could not be reached or refused the connection.
 * Transient: the server may be down, rate-limiting, or blocking this network,
 * so a retry (or a retry from elsewhere) can succeed.
 */
export class WhoisQueryError extends Error {
  override readonly name = "WhoisQueryError";
  /** Always false — the failure may not reproduce. */
  readonly permanent = false;
  readonly host: string;

  constructor(message: string, init: { host: string; cause?: unknown }) {
    super(message, { cause: init.cause });
    this.host = init.host;
  }
}

/**
 * The registry answered, and its answer is that no such domain is registered.
 * This is a definitive result rather than a failure — the WHOIS equivalent of
 * an RDAP 404. Retrying changes nothing until someone registers the name.
 */
export class DomainNotFoundError extends Error {
  override readonly name = "DomainNotFoundError";
  /** Always true — the same query returns the same answer. */
  readonly permanent = true;
  readonly domain: string;
  /** The server that said so. */
  readonly host: string;

  constructor(message: string, init: { domain: string; host: string }) {
    super(message);
    this.domain = init.domain;
    this.host = init.host;
  }
}

export type WhoisNoRecordReason =
  /** The server rejected the query outright: blocked, rate-limited, IP-restricted. */
  | "refused"
  /** A response arrived, but nothing in it resembles a record for this domain. */
  | "unrecognized";

/**
 * The server replied without giving us a record, and without saying the domain
 * is unregistered. Permanent in the sense that retrying the same query from the
 * same place gets the same answer: .ch and .li serve only a pointer to their web
 * form, and .es answers every unauthorized IP with its terms of use. Lifting
 * either needs an out-of-band step (get the IP whitelisted), not a retry.
 *
 * `hint` carries the server's own first line, which usually explains what it
 * wants.
 */
export class WhoisNoRecordError extends Error {
  override readonly name = "WhoisNoRecordError";
  /** Always true — an identical retry gets an identical answer. */
  readonly permanent = true;
  readonly reason: WhoisNoRecordReason;
  readonly domain: string;
  readonly host: string;
  /** The server's first line of substance, when it offered one. */
  readonly hint?: string;

  constructor(
    message: string,
    init: { reason: WhoisNoRecordReason; domain: string; host: string; hint?: string },
  ) {
    super(message);
    this.reason = init.reason;
    this.domain = init.domain;
    this.host = init.host;
    this.hint = init.hint;
  }
}
