import { lookup as dnsLookup } from "node:dns/promises";
import net from "node:net";
import { isPrivateIp } from "./ip.js";

/** Error thrown whenever a URL is rejected by the SSRF guard. */
export class SsrfError extends Error {
  override name = "SsrfError";
}

/**
 * Type guard: true only for strings that parse as absolute http(s) URLs.
 * Rejects `javascript:`, `data:`, `file:`, `ftp:`, protocol-relative URLs,
 * and non-string input. Safe to use in any JavaScript runtime (no Node
 * built-ins involved).
 */
export function isSafeHttpUrl(url: unknown): url is string {
  if (typeof url !== "string") return false;
  try {
    const u = new URL(url);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

/** Minimal shape of `node:dns/promises` `lookup(host, { all: true })`. */
export type LookupFn = (
  hostname: string,
  options: { all: true },
) => Promise<Array<{ address: string }>>;

export interface AssertPublicUrlOptions {
  /**
   * Custom DNS resolver (same contract as `node:dns/promises` `lookup` with
   * `{ all: true }`). Useful for tests, caching resolvers, or custom DNS.
   */
  lookup?: LookupFn;
}

/**
 * Validates that a URL is http(s) and that its host is public:
 *
 * - non-http(s) protocols are rejected
 * - literal IP hosts (including bracketed IPv6 literals and the decimal /
 *   octal / hex IPv4 forms that the WHATWG URL parser normalizes, e.g.
 *   `http://2130706433/`) are checked directly against the blocked ranges
 * - hostnames are resolved via DNS and EVERY returned address must be
 *   public; one private A/AAAA record among public ones is enough to reject
 *
 * Returns the parsed URL on success, throws `SsrfError` otherwise.
 *
 * Call this for the initial URL AND every redirect hop (or use `safeFetch`,
 * which does exactly that).
 */
export async function assertPublicUrl(
  raw: string,
  opts: AssertPublicUrlOptions = {},
): Promise<URL> {
  if (!isSafeHttpUrl(raw)) {
    throw new SsrfError(`Blocked non-http(s) URL: ${raw}`);
  }
  const u = new URL(raw);
  // Bracketed IPv6 literals come back as "[::1]" from URL.hostname.
  const host =
    u.hostname.startsWith("[") && u.hostname.endsWith("]")
      ? u.hostname.slice(1, -1)
      : u.hostname;

  // Literal IP in the host -> check directly, skip DNS.
  if (net.isIP(host)) {
    if (isPrivateIp(host)) {
      throw new SsrfError(`Blocked private IP host: ${host}`);
    }
    return u;
  }

  const lookup = opts.lookup ?? (dnsLookup as LookupFn);
  let results: Array<{ address: string }>;
  try {
    results = await lookup(host, { all: true });
  } catch {
    throw new SsrfError(`DNS resolution failed for host: ${host}`);
  }
  if (!results.length) {
    throw new SsrfError(`No DNS records for host: ${host}`);
  }
  for (const { address } of results) {
    if (isPrivateIp(address)) {
      throw new SsrfError(`Host ${host} resolves to private address ${address}`);
    }
  }
  return u;
}
