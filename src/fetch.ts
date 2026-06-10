import { assertPublicUrl, SsrfError, type LookupFn } from "./validate.js";

export interface SafeFetchOptions {
  /** Maximum number of redirects to follow. Default: 4. */
  maxRedirects?: number;
  /** Per-request timeout in milliseconds (applies to each hop). Default: 5000. */
  timeoutMs?: number;
  /** Custom DNS resolver passed through to `assertPublicUrl`. */
  lookup?: LookupFn;
  /** Custom fetch implementation (defaults to the global `fetch`). */
  fetchImpl?: typeof fetch;
}

/**
 * SSRF-safe `fetch` wrapper.
 *
 * Validates the URL with `assertPublicUrl`, performs the request with
 * `redirect: "manual"`, and re-validates EVERY redirect hop before following
 * it - so a public URL that redirects to an internal host is caught.
 *
 * Each hop gets its own timeout via `AbortController`; if `init.signal` is
 * provided it is combined with the timeout signal where `AbortSignal.any`
 * is available (Node >= 20.3), otherwise the timeout signal takes precedence.
 *
 * Notes:
 * - `init` is re-sent unchanged on every hop (method and body included).
 *   Browser-style 303 "switch to GET" semantics are intentionally not
 *   implemented; avoid following redirects for non-idempotent requests.
 * - A 3xx response without a `Location` header is returned as-is.
 *
 * Returns the final `Response`. Throws `SsrfError` when any hop is blocked
 * or the redirect limit is exceeded.
 */
export async function safeFetch(
  raw: string,
  init: RequestInit = {},
  opts: SafeFetchOptions = {},
): Promise<Response> {
  const maxRedirects = opts.maxRedirects ?? 4;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const doFetch = opts.fetchImpl ?? fetch;
  let current = raw;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    await assertPublicUrl(current, { ...(opts.lookup ? { lookup: opts.lookup } : {}) });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const signal =
      init.signal && typeof AbortSignal.any === "function"
        ? AbortSignal.any([init.signal, controller.signal])
        : controller.signal;
    let res: Response;
    try {
      res = await doFetch(current, { ...init, redirect: "manual", signal });
    } finally {
      clearTimeout(timer);
    }
    if (res.status >= 300 && res.status < 400) {
      const loc = res.headers.get("location");
      if (!loc) return res;
      current = new URL(loc, current).toString();
      continue;
    }
    return res;
  }
  throw new SsrfError(`Too many redirects starting from: ${raw}`);
}
