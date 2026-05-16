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

## License

MIT
