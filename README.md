# ssrf-safe-fetch

[![CI](https://github.com/Chinozilla/ssrf-safe-fetch/actions/workflows/ci.yml/badge.svg)](https://github.com/Chinozilla/ssrf-safe-fetch/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/ssrf-safe-fetch.svg)](https://www.npmjs.com/package/ssrf-safe-fetch)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

SSRF protection for server-side requests in Node.js: URL validation, private/reserved
IP blocking (IPv4 and IPv6), and a `fetch` wrapper that re-validates every redirect hop.

Zero runtime dependencies. ESM and CommonJS. TypeScript-first.

Extracted from a production web application, where it guards an availability
scraper and other outbound fetches of user-supplied URLs. The validation logic
shipped there after a security audit flagged an unauthenticated SSRF endpoint,
and has been battle-tested in production since.

## What is SSRF?

Server-Side Request Forgery (SSRF) happens when an attacker can make *your
server* send a request to a URL the attacker controls or chooses. Typical entry
points:

- **Webhook URLs** — "notify this URL when X happens" forms.
- **User-supplied links** — link previews, ticket/product URLs, avatar URLs,
  RSS feed URLs, import-from-URL features.
- **Scrapers and availability checkers** — anything that fetches third-party
  pages on a schedule.

Why it matters: from inside your infrastructure, `http://169.254.169.254/`
(cloud metadata, often holding credentials), `http://localhost:6379/` (Redis),
or `http://10.0.0.5/admin` are reachable even though they are invisible from
the internet. A naive `fetch(userUrl)` turns your server into a proxy into that
internal network. Redirects make naive blocklists useless: the attacker submits
a harmless-looking public URL that 302-redirects to an internal host.

This library closes both holes:

1. **Validate before fetching** — protocol must be http(s); the host (literal
   IP or every DNS-resolved address) must be outside private/reserved ranges.
2. **Validate every redirect hop** — `safeFetch` disables automatic redirect
   following and re-runs the full validation on each `Location` target before
   requesting it.

## Install

```sh
npm install ssrf-safe-fetch
```

Requires Node.js 18.17 or later (uses the global `fetch`, `node:net`, and
`node:dns/promises`).

## Quickstart

```ts
import { safeFetch, SsrfError } from "ssrf-safe-fetch";

try {
  const res = await safeFetch(userSuppliedUrl, { headers: { Accept: "text/html" } });
  const html = await res.text();
} catch (err) {
  if (err instanceof SsrfError) {
    // Blocked: private/reserved target, bad protocol, DNS failure, or too many redirects.
  }
  throw err;
}
```

Or validate without fetching (e.g. when storing a webhook URL):

```ts
import { assertPublicUrl, isSafeHttpUrl } from "ssrf-safe-fetch";

if (!isSafeHttpUrl(input)) reject();   // sync, cheap: protocol/shape check only
await assertPublicUrl(input);          // async: full check incl. DNS resolution
```

## API

### `safeFetch(url, init?, options?): Promise<Response>`

SSRF-safe drop-in for `fetch`. Validates the URL with `assertPublicUrl`,
performs the request with `redirect: "manual"`, and re-validates every redirect
hop before following it. Returns the final `Response`; throws `SsrfError` when
any hop is blocked or the redirect limit is exceeded.

- `init` — standard `RequestInit`, passed through except `redirect` (always
  forced to `"manual"`) and `signal` (combined with the per-hop timeout via
  `AbortSignal.any` on Node >= 20.3, otherwise replaced by it).
- `options.maxRedirects` — maximum redirects to follow. Default `4`.
- `options.timeoutMs` — per-hop timeout in milliseconds. Default `5000`.
- `options.lookup` — custom DNS resolver (see `assertPublicUrl`).
- `options.fetchImpl` — custom `fetch` implementation (e.g. an undici client
  with a proxy dispatcher, or a mock in tests).

Behavior notes:

- `init` is re-sent unchanged on every hop, method and body included.
  Browser-style 303 "switch to GET" semantics are intentionally not
  implemented — avoid following redirects for non-idempotent requests.
- A 3xx response without a `Location` header is returned as-is.

### `assertPublicUrl(url, options?): Promise<URL>`

Validates a single URL and returns the parsed `URL`, or throws `SsrfError`:

1. Protocol must be `http:` or `https:` (via `isSafeHttpUrl`).
2. If the host is a literal IP (including bracketed IPv6 literals and the
   decimal/octal/hex IPv4 encodings the WHATWG URL parser normalizes, such as
   `http://2130706433/` or `http://0x7f000001/`), it is checked directly
   against the blocked ranges — no DNS involved.
3. Otherwise the hostname is resolved (`dns.lookup` with `all: true`) and
   **every** returned address must be public. A single private A/AAAA record
   among public ones rejects the URL.

`options.lookup` lets you inject a custom resolver with the same contract as
`node:dns/promises` `lookup(host, { all: true })` — useful for tests, caching
resolvers, or DNS pinning.

Call this for the initial URL *and* every redirect hop — or just use
`safeFetch`, which does exactly that.

### `isPrivateIp(ip): boolean`

Pure predicate over an IP address string. Returns `true` for private, loopback,
link-local, and otherwise reserved addresses. **Fail-closed:** any string that
is not a syntactically valid IPv4/IPv6 address also returns `true`.

Blocked IPv4 ranges:

| Range | Why |
|---|---|
| `0.0.0.0/8` | "this" network |
| `10.0.0.0/8` | RFC 1918 private |
| `100.64.0.0/10` | carrier-grade NAT (RFC 6598) |
| `127.0.0.0/8` | loopback |
| `169.254.0.0/16` | link-local, includes cloud metadata `169.254.169.254` |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `224.0.0.0/3` | multicast, reserved, broadcast (224-255) |

Blocked IPv6 ranges:

| Range | Why |
|---|---|
| `::` / `::1` | unspecified / loopback |
| `fe80::/10` | link-local |
| `fc00::/7` | unique local |
| `ff00::/8` | multicast |
| `::ffff:a.b.c.d` | IPv4-mapped (dotted *and* hex form) — embedded IPv4 is checked |
| `::a.b.c.d` | deprecated IPv4-compatible — embedded IPv4 is checked |
| `64:ff9b::/96` | NAT64 well-known prefix — embedded IPv4 is checked |

### `isSafeHttpUrl(url): url is string`

Synchronous type guard: `true` only for strings that parse as absolute
`http:`/`https:` URLs. Rejects `javascript:`, `data:`, `file:`, `ftp:`,
protocol-relative URLs, and non-string input. No Node built-ins — usable in
any JavaScript runtime (handy for sanitizing `href` values too).

### `SsrfError`

Error subclass (`name === "SsrfError"`) thrown by `assertPublicUrl` and
`safeFetch` for every blocked request, so callers can distinguish policy
rejections from network errors.

## How redirect-hop validation works

```
safeFetch(url)
  └─ hop 0: assertPublicUrl(url)        -> blocked? throw SsrfError
            fetch(url, redirect:manual)
            3xx + Location?
  └─ hop 1: assertPublicUrl(location)   -> blocked? throw SsrfError (target never fetched)
            fetch(location, ...)
  └─ ... up to maxRedirects, else SsrfError("Too many redirects")
```

Because each `Location` target goes through the *full* validation (protocol,
literal-IP check, DNS resolution of every record) before any request is made,
the classic bypass — a public URL that redirects to
`http://169.254.169.254/latest/meta-data/` — is caught at the hop boundary.
Relative `Location` headers are resolved against the current URL first.

## Security model and limitations

Be honest about what a library like this can and cannot do:

- **DNS rebinding (TOCTOU) is not fully prevented.** `assertPublicUrl` resolves
  the hostname itself, but the subsequent `fetch` performs its *own* DNS
  resolution. A malicious authoritative DNS server with a very low TTL can
  answer the validation query with a public address and the fetch-time query
  with a private one. Full prevention requires pinning the connection to the
  validated address (custom dialer/agent), which the global `fetch` does not
  expose. If this is in your threat model, terminate outbound traffic through
  an egress proxy or use `options.fetchImpl` with an undici dispatcher that
  pins addresses.
- **Not an allowlist.** This is a denylist of well-known private/reserved
  ranges. If your internal services live on *public* IPs (or behind public
  load balancers), this library will not stop requests to them — add your own
  allowlist/denylist on top.
- **Some special-purpose IPv4 ranges are not blocked**, because they are
  routable-looking documentation/benchmark space rather than internal
  infrastructure: `192.0.0.0/24`, `192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24` (TEST-NET), `198.18.0.0/15` (benchmarking). The deprecated
  IPv6 site-local `fec0::/10` is likewise not blocked. PRs welcome if your
  environment needs them.
- **Obfuscated IPv4 forms are covered only as far as the WHATWG URL parser
  normalizes them.** Node's `URL` canonicalizes decimal (`2130706433`), octal
  (`0177.0.0.1`), hex (`0x7f000001`), and shorthand (`127.1`) hosts to dotted
  IPv4 before validation, so these are blocked. Hostname tricks that resolve
  via DNS (e.g. `localtest.me`-style wildcard domains pointing at 127.0.0.1)
  are blocked by the resolved-address check instead.
- **The response is not sanitized.** This library decides whether a request
  may be sent; what you do with the response body is up to you.
- **No protection against request smuggling, open ports on public IPs, or
  application-layer attacks** on legitimately public targets.

## Origin

This code was extracted from a production web application where it protects a
periodic availability scraper and other server-side fetches of user-submitted
URLs. A whitebox security audit of that application found an unauthenticated
SSRF vector (attacker-controlled URL passed to an HTTP client that followed
redirects); the fix — per-hop validation with private-range blocking — became
this library. The IPv6 handling was hardened during extraction (full
`fe80::/10` coverage, hex-form IPv4-mapped addresses, NAT64 prefix).

## License

[MIT](./LICENSE) — Copyright (c) 2026 Anhthien Nguyen
