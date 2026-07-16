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
| `useWhoisAvailabilityTable` | `boolean` | IANA에 WHOIS 서버가 없을 때 내장 가용성 테이블 참조. 기본 `true`. |
| `classifyResponse` | `boolean` | 파싱 전에 서버 응답이 무엇인지 판별. 기본 `true`. |

### 에러

모든 에러가 `permanent` 를 갖습니다. 호출자가 실제로 궁금한 것 — 재시도가 의미
있는가 — 에 답하기 위해서입니다.

| 클래스 | `permanent` | 의미 |
| --- | --- | --- |
| `WhoisUnavailableError` | `true` | 해당 TLD에 조회할 소스 자체가 없음. |
| `DomainNotFoundError` | `true` | 레지스트리의 답변: 그런 등록 없음. |
| `WhoisNoRecordError` | `true` | 응답은 왔지만 레코드를 주지 않음. |
| `WhoisQueryError` | `false` | 서버는 아는데 도달 실패. 재시도로 성공 가능. |

`WhoisUnavailableError.reason`:

- `no-whois-server` — 레지스트리가 WHOIS를 아예 제공하지 않음 (`.gb`, `.kp`, `.mil`).
- `web-only` — 웹 폼으로만 제공. `webUrl` 로 사람이 볼 주소를 전달 (`.gr`, `.ph`).
- `no-source` — RDAP도 없고 알려진 WHOIS 서버도 없음.

`WhoisNoRecordError.reason` 은 거부와 미상을 구분하고, `hint` 에 서버가 한 말이
담깁니다.

- `refused` — 차단/rate limit/IP 제한. `.ch` 와 `.li` 는 모든 질의에 웹 폼 안내만
  돌려주고, `.es` 는 Red.es 가 승인하지 않은 IP 에 이용약관만 반환합니다. 재시도는
  무의미합니다 — 두 번째 시도가 아니라 대역 외 절차가 필요합니다.
- `unrecognized` — 응답은 왔으나 레코드로 볼 만한 것이 없음.

```ts
import { lookupRdap, DomainNotFoundError, WhoisNoRecordError } from "whois2rdap";

try {
  const rdap = await lookupRdap("example.ch");
} catch (err) {
  if (err instanceof DomainNotFoundError) return null;              // 그런 도메인 없음
  if (err instanceof WhoisNoRecordError) throw new Error(err.hint); // 차단당함
  throw err;
}
```

### 응답을 분류하는 이유

WHOIS 서버는 "그런 도메인 없음", "질의 권한 없음", "여기 레코드" 를 **상태 코드
없이 한 채널에 산문으로** 내려보냅니다. 셋 다 파싱하면 똑같이 *입력한 이름만 담긴
객체* 로 뭉개지므로, `lookupRdap` 은 파싱 전에 응답을 분류합니다 (`classifyResponse`,
기본 on. `classifyWhoisResponse` 로 직접 쓸 수도 있음).

**비어 있다는 게 신호가 아닙니다.** DENIC 은 *등록된* 도메인에도 두 줄만 줍니다.

```
Domain: denic.de
Status: connect
```

즉 결과가 얇다고 답이 얇은 게 아니며, 응답의 형태와 문구만이 구분해줍니다. 패턴은
서로 다른 레지스트리의 실제 레코드 102개로 검증했습니다.

### WHOIS 가용성 테이블

IANA 루트 DB는 72개 TLD의 `whois:` 를 빈 값으로 두지만, 성격이 다 다릅니다. 32개는
WHOIS 자체가 없고, 27개는 웹 폼만 있으며, 13개는 IANA가 알리지 않을 뿐 port 43 서버가
있는 것으로 확인됩니다. `WHOIS_AVAILABILITY` 가 이 차이를 담고, `lookupRdap` 은 **IANA 조회가
빈손으로 돌아온 뒤에만** 이 테이블을 봅니다. IANA가 항상 우선이므로, 테이블이 낡아도
레지스트리가 새로 개설한 서버를 가리는 일은 없습니다.

```ts
import { whoisAvailabilityForTld } from "whois2rdap";

whoisAvailabilityForTld("gb"); // { kind: "none" }
whoisAvailabilityForTld("gr"); // { kind: "web", url: "https://grweb.ics.forth.gr/…" }
whoisAvailabilityForTld("bz"); // { kind: "server", host: "whois.identitydigital.services" }
whoisAvailabilityForTld("de"); // undefined — IANA가 이미 제공
```

`npm run gen:whois-availability` 로 재생성합니다 (IANA 루트 DB + rfc1036/whois 의
`tld_serv_list` 병합).

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
