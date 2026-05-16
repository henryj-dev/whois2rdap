# whois2rdap

WHOIS 응답을 [RFC 9083](https://datatracker.ietf.org/doc/html/rfc9083) RDAP JSON 형태로 변환하는 npm 모듈입니다. [IANA](https://data.iana.org/rdap/dns.json)에 공식 RDAP 서버가 등록된 TLD라면 자동으로 그쪽을 우선 호출합니다.

> English: [README.md](./README.md)

## 특징

- **`lookupRdap(domain)`** — 한 번의 호출로 알맞은 경로를 선택:
  1. IANA RDAP bootstrap (`data.iana.org/rdap/dns.json`) 확인
  2. 해당 TLD가 등록되어 있으면 `<base>/domain/<name>`을 직접 호출
  3. 없으면 TCP WHOIS 조회 → RDAP로 변환
- **`whoisToRdap(text)`** — WHOIS 원문 텍스트를 RDAP `domain` 객체로 변환하는 순수 함수
- **`whoisQuery({ host, query })`** — 저수준 port-43 클라이언트
- **RFC 9083 호환 출력** — `objectClassName`, `rdapConformance`, jCard `vcardArray`, EPP→RDAP status 매핑(RFC 8056), `port43`, `notices`, `ldhName` 소문자 정규화
- **TLD 파서** — 현재 `.kr`(KISA/KRNIC), `.cn`(CNNIC) 지원. `src/parsers/`에 파일 추가하는 식의 플러그형 구조
- **런타임 의존성 0개.** `tsup`으로 ESM + CJS + `.d.ts` 동시 빌드

## 설치

```bash
npm install whois2rdap
# 또는
bun add whois2rdap
# 또는
pnpm add whois2rdap
```

Node.js ≥ 18 (`fetch`, `AbortSignal.timeout` 사용).

## 빠른 시작

```ts
import { lookupRdap } from "whois2rdap";

const rdap = await lookupRdap("oup.kr");
console.log(rdap.ldhName);   // "oup.kr"
console.log(rdap.status);    // ["client transfer prohibited"]
console.log(rdap.port43);    // "whois.kr"
```

`.com`/`.net`/`.org` 처럼 IANA에 RDAP 서버가 등록된 TLD는 WHOIS를 거치지 않고 바로 RDAP 서버를 호출합니다.

```ts
const rdap = await lookupRdap("example.com");
// → https://rdap.verisign.com/com/v1/domain/example.com 에서 직접 가져옴
```

## API

### `lookupRdap(domain, options?)`

| 옵션 | 타입 | 설명 |
| --- | --- | --- |
| `useIanaBootstrap` | `boolean` | IANA 조회를 끄고 강제로 WHOIS 경로 사용. 기본 `true`. |
| `bootstrap` | `BootstrapLoadOptions` | bootstrap 로더에 전달 (`url`, `ttlMs`, `force`, `fetchImpl`, `signal`). |
| `fetchImpl` | `typeof fetch` | 커스텀 `fetch` 주입(테스트, 프록시용). |
| `server` | `string` | WHOIS 서버 고정. 설정 시 IANA bootstrap을 건너뜀. |
| `port` | `number` | WHOIS 포트. 기본 `43`. |
| `timeoutMs` | `number` | 양쪽 경로 공통 타임아웃. 기본 `10_000`. |
| `normalizeCase` | `boolean` | 도메인/네임서버의 `ldhName` 소문자화. 기본 `true`. |
| `includeRawWhoisNotice` | `boolean` | WHOIS 원문 전체를 `notices[]`에 추가(WHOIS 경로 한정). |

### `whoisToRdap(text, options?)`

순수 변환 함수. `.kr` 도메인이거나 KRNIC 배너가 감지되면 KR 파서로 디스패치, 그 외는 최소 stub 반환. `sourceServer`, `includeRawWhoisNotice`, `normalizeCase` 옵션 지원.

### `whoisQuery({ host, query, port?, timeoutMs? })`

port-43 raw 클라이언트. 응답을 UTF-8 문자열로 반환.

### IANA bootstrap 헬퍼

```ts
import {
  loadIanaRdapBootstrap,
  rdapBaseUrlsForTld,
  setIanaRdapBootstrapCache,
  clearIanaRdapBootstrapCache,
} from "whois2rdap";
```

bootstrap은 첫 호출 시 lazy하게 가져와서 24시간 메모리 캐시됩니다.

## 출력 예시 (`.kr`)

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

## 지원 TLD

| TLD | 경로 | 비고 |
| --- | --- | --- |
| `.com`, `.net`, `.org`, `.site`, `.blog`, ... | IANA RDAP 패스스루 | `data.iana.org/rdap/dns.json`에 등록된 모든 TLD |
| `.kr` | WHOIS → KR 파서 | KISA/KRNIC, 영문 섹션 우선 |
| `.cn` | WHOIS → CN 파서 | CNNIC, ROID → `handle`, `signedDelegation` → `secureDNS` |

새 TLD 추가는 `src/parsers/<tld>.ts`를 작성하고 `src/convert.ts`에 디스패치만 연결하면 됩니다. PR 환영합니다.

## RFC 9083 준수 현황

| 항목 | 상태 |
| --- | --- |
| `objectClassName`, `rdapConformance` | ✅ |
| jCard (`vcardArray`) — RFC 7095 | ✅ |
| EPP → RDAP status 매핑 (RFC 8056) | ✅ |
| `port43`, `notices` | ✅ (WHOIS 경로) |
| `events`, `entities`, `nameservers`, `secureDNS.delegationSigned` | ✅ |
| `secureDNS.dsData` / `keyData` | ❌ (WHOIS에 거의 노출되지 않음) |
| `links` self-reference | ❌ (호출 URL 정보 없음) |
| `unicodeName` (IDN) | ❌ |

## 개발

```bash
bun install
bun run typecheck
bun run test
bun run build
```

## 라이선스

MIT
