# whois2rdap

Convert WHOIS responses into [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083) RDAP-shaped JSON, with an optional one-shot lookup that prefers the official RDAP service when one is registered with [IANA](https://data.iana.org/rdap/dns.json).

> 한국어 문서: [README.ko.md](./README.ko.md)

## Features

- **`lookupRdap(domain)`** — single call that does the right thing:
  1. Checks the IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`).
  2. If the TLD has an official RDAP service, fetches `<base>/domain/<name>` directly.
  3. Otherwise falls back to a TCP WHOIS query and converts the response.
- **`whoisToRdap(text)`** — pure converter from raw WHOIS text to an RDAP `domain` object.
- **`whoisQuery({ host, query })`** — low-level port-43 client.
- **RFC 9083 compliant output** — `objectClassName`, `rdapConformance`, jCard `vcardArray`, EPP→RDAP status mapping (RFC 8056), `port43`, `notices`, lowercase `ldhName` normalization.
- **TLD parsers** — currently `.kr` (KISA/KRNIC) and `.cn` (CNNIC). The architecture is pluggable; add a parser per TLD in `src/parsers/`.
- **Zero runtime dependencies.** Built with `tsup` for ESM + CJS + `.d.ts`.

## Install

```bash
npm install whois2rdap
# or
bun add whois2rdap
# or
pnpm add whois2rdap
```

Requires Node.js ≥ 18 (uses native `fetch` and `AbortSignal.timeout`).

## Quick start

```ts
import { lookupRdap } from "whois2rdap";

const rdap = await lookupRdap("oup.kr");
console.log(rdap.ldhName);   // "oup.kr"
console.log(rdap.status);    // ["client transfer prohibited"]
console.log(rdap.port43);    // "whois.kr"
```

For a TLD that has an IANA-registered RDAP server (e.g. `.com`, `.net`, `.org`), the call goes straight to that server — no WHOIS conversion happens.

```ts
const rdap = await lookupRdap("example.com");
// → fetched from https://rdap.verisign.com/com/v1/domain/example.com
```

## API

### `lookupRdap(domain, options?)`

| option | type | description |
| --- | --- | --- |
| `useIanaBootstrap` | `boolean` | Disable the IANA lookup and force the WHOIS path. Default `true`. |
| `bootstrap` | `BootstrapLoadOptions` | Forwarded to the bootstrap loader (`url`, `ttlMs`, `force`, `fetchImpl`, `signal`). |
| `fetchImpl` | `typeof fetch` | Inject a custom `fetch` (testing, proxies). |
| `server` | `string` | Pin a WHOIS server. Setting this also bypasses the IANA bootstrap. |
| `port` | `number` | WHOIS port. Default `43`. |
| `timeoutMs` | `number` | Timeout for either path. Default `10_000`. |
| `normalizeCase` | `boolean` | Lowercase `ldhName` on the domain and nameservers. Default `true`. |
| `includeRawWhoisNotice` | `boolean` | Include the raw WHOIS text as an extra `notices[]` entry (WHOIS path only). |
| `useWhoisAvailabilityTable` | `boolean` | Consult the bundled availability table when IANA lists no WHOIS server. Default `true`. |
| `classifyResponse` | `boolean` | Check what the server returned before parsing it. Default `true`. See [Why responses are classified](#why-responses-are-classified). |

### Errors

Every failure carries `permanent`, which answers the only question a caller
really has: could retrying ever help?

| class | `permanent` | meaning |
| --- | --- | --- |
| `WhoisUnavailableError` | `true` | No source exists for this TLD at all. |
| `DomainNotFoundError` | `true` | The registry answered: no such registration. |
| `WhoisNoRecordError` | `true` | The server replied but gave us no record. |
| `WhoisQueryError` | `false` | A known server was unreachable. Retrying may succeed. |

`WhoisUnavailableError.reason` says which permanent case applies:

- `no-whois-server` — the registry publishes no WHOIS at all (`.gb`, `.kp`, `.mil`).
- `web-only` — WHOIS exists only as a web form; `webUrl` points a human at it (`.gr`, `.ph`).
- `no-source` — neither RDAP nor any known WHOIS server for the TLD.

`WhoisNoRecordError.reason` distinguishes a rejection from a puzzle, and `hint`
carries the server's own words:

- `refused` — blocked, rate-limited, or IP-restricted. `.ch` and `.li` answer
  every query with a pointer to their web form; `.es` serves its terms of use to
  any IP Red.es has not authorized. Retrying is futile — lifting these needs an
  out-of-band step, not a second attempt.
- `unrecognized` — a response arrived with nothing in it resembling a record.

```ts
import { lookupRdap, DomainNotFoundError, WhoisNoRecordError } from "whois2rdap";

try {
  const rdap = await lookupRdap("example.ch");
} catch (err) {
  if (err instanceof DomainNotFoundError) return null;          // no such domain
  if (err instanceof WhoisNoRecordError) throw new Error(err.hint); // blocked
  throw err;
}
```

### Why responses are classified

A WHOIS server reports "no such domain", "you may not ask", and "here is the
record" as prose over one channel, with no status code. Parse all three and they
collapse into the same shrug — an object carrying only the name you passed in —
so `lookupRdap` classifies the response before parsing it (`classifyResponse`,
on by default; `classifyWhoisResponse` is exported if you want it directly).

Emptiness is not the signal. DENIC answers a *registered* domain with two fields
and nothing else:

```
Domain: denic.de
Status: connect
```

A thin result is therefore not evidence of a thin answer, and only the response's
shape and wording tell the cases apart. The patterns were verified against 102
real records from distinct registries — see the maintenance scripts below.

### WHOIS availability table

The IANA root database leaves `whois:` blank for 72 TLDs, but they are not alike:
32 publish no WHOIS at all, 27 offer only a web form, and 13 are known to have a
port-43 server IANA simply does not advertise. `WHOIS_AVAILABILITY` records the
difference, and `lookupRdap` consults it *after* IANA discovery comes back
empty — IANA stays authoritative, so a stale entry here can never mask a server
a registry has since published.

```ts
import { whoisAvailabilityForTld } from "whois2rdap";

whoisAvailabilityForTld("gb"); // { kind: "none" }
whoisAvailabilityForTld("gr"); // { kind: "web", url: "https://grweb.ics.forth.gr/…" }
whoisAvailabilityForTld("bz"); // { kind: "server", host: "whois.identitydigital.services" }
whoisAvailabilityForTld("de"); // undefined — IANA already serves it
```

Regenerate it with `npm run gen:whois-availability` (merges the IANA root
database with rfc1036/whois's `tld_serv_list`).

### `whoisToRdap(text, options?)`

Pure conversion. Detects `.kr` (or a KRNIC banner) and dispatches to the KR parser; everything else returns a minimal stub. Honors `sourceServer`, `includeRawWhoisNotice`, `normalizeCase`.

### `whoisQuery({ host, query, port?, timeoutMs? })`

Raw port-43 client returning the response as a UTF-8 string.

### IANA bootstrap helpers

```ts
import {
  loadIanaRdapBootstrap,
  rdapBaseUrlsForTld,
  setIanaRdapBootstrapCache,
  clearIanaRdapBootstrapCache,
} from "whois2rdap";
```

The bootstrap is fetched lazily on first use and cached in memory for 24h.

## Output shape (`.kr` example)

```json
{
  "objectClassName": "domain",
  "rdapConformance": ["rdap_level_0"],
  "ldhName": "oup.kr",
  "status": ["client transfer prohibited"],
  "entities": [
    { "objectClassName": "entity", "roles": ["registrant"], "vcardArray": [...] },
    { "objectClassName": "entity", "roles": ["administrative"], "vcardArray": [...] },
    { "objectClassName": "entity", "roles": ["registrar"], "vcardArray": [...] }
  ],
  "nameservers": [
    { "objectClassName": "nameserver", "ldhName": "adel.ns.cloudflare.com" },
    { "objectClassName": "nameserver", "ldhName": "trey.ns.cloudflare.com" }
  ],
  "events": [
    { "eventAction": "registration",  "eventDate": "2013-08-03T00:00:00Z" },
    { "eventAction": "last changed",  "eventDate": "2022-08-08T00:00:00Z" },
    { "eventAction": "expiration",    "eventDate": "2026-08-03T00:00:00Z" }
  ],
  "secureDNS": { "delegationSigned": true },
  "port43": "whois.kr",
  "notices": [
    { "title": "Source", "description": ["Derived from WHOIS data served by whois.kr."] }
  ]
}
```

## Supported TLDs

| TLD | Path | Notes |
| --- | --- | --- |
| `.com`, `.net`, `.org`, `.site`, `.blog`, ... | IANA RDAP passthrough | Anything in `data.iana.org/rdap/dns.json` |
| `.kr` | WHOIS → KR parser | KISA/KRNIC, English section preferred |
| `.cn` | WHOIS → CN parser | CNNIC, ROID → `handle`, `signedDelegation` → `secureDNS` |

PRs welcome for more TLDs — add a parser at `src/parsers/<tld>.ts` and wire it into `src/convert.ts`.

## RFC 9083 conformance

| Requirement | Status |
| --- | --- |
| `objectClassName`, `rdapConformance` | ✅ |
| jCard (`vcardArray`) per RFC 7095 | ✅ |
| EPP → RDAP status mapping (RFC 8056) | ✅ |
| `port43`, `notices` | ✅ (WHOIS path) |
| `events`, `entities`, `nameservers`, `secureDNS.delegationSigned` | ✅ |
| `secureDNS.dsData` / `keyData` | ❌ (WHOIS rarely exposes) |
| `links` self-reference | ❌ (no canonical URL known) |
| `unicodeName` for IDN | ❌ |

## Development

```bash
bun install
bun run typecheck
bun run test
bun run build
```

### Maintenance scripts

```bash
npm run gen:whois-availability   # regenerate src/whois-availability.ts
npm run probe:whois-formats      # measure parser coverage against live registries
npm run probe:whois-formats -- se kr cn   # …or just these TLDs
```

`probe:whois-formats` samples every WHOIS-only registry with a real apex domain
and reports what the parsers extracted. Two things keep it cheap: TLDs share
servers (179 WHOIS-only TLDs sit behind 132 hosts — India's 15 IDN TLDs all
answer from `whois.nixiregistry.in`), so it queries once per *server*; and a
registry's own domain (`nic.<tld>`, or the whois host minus its `whois.` prefix)
is registered almost everywhere, so a candidate ladder finds a live record
without hand-curating 132 entries. `scripts/representative-domains.json` covers
the registries where that fails — reserved names (`nic.om`), restricted ones
(`nic.nz`), and TLDs that sell only at the third level (`.il`, `.mm`).

Interpreting a thin result needs care, so the library's `classifyWhoisResponse` separates
three things a sparse response can mean — the server refused us (`.ch`), the name
we picked is not registered (`nic.cn` is reserved), or the parser genuinely fell
short. Only the last is a parser problem. It is worth reading before trusting any
coverage number: nearly every registry appends a legal notice that trips naive
refusal patterns.

## License

MIT
