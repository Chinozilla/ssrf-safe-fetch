import net from "node:net";

/**
 * Returns true when the given IP address string belongs to a private,
 * loopback, link-local, or otherwise reserved range that a server should
 * never be tricked into requesting.
 *
 * Fail-closed: any string that is not a syntactically valid IPv4 or IPv6
 * address is treated as private (unsafe).
 *
 * IPv4 ranges blocked:
 * - 0.0.0.0/8        ("this" network)
 * - 10.0.0.0/8       (RFC 1918 private)
 * - 100.64.0.0/10    (RFC 6598 carrier-grade NAT)
 * - 127.0.0.0/8      (loopback)
 * - 169.254.0.0/16   (link-local, includes cloud metadata 169.254.169.254)
 * - 172.16.0.0/12    (RFC 1918 private)
 * - 192.168.0.0/16   (RFC 1918 private)
 * - 224.0.0.0/3      (multicast, reserved, broadcast: 224.0.0.0-255.255.255.255)
 *
 * IPv6 ranges blocked:
 * - ::               (unspecified)
 * - ::1              (loopback)
 * - fe80::/10        (link-local)
 * - fc00::/7         (unique local)
 * - ff00::/8         (multicast)
 * - ::ffff:a.b.c.d   (IPv4-mapped, both dotted and hex forms; the embedded
 *                     IPv4 address is checked against the IPv4 rules)
 * - ::a.b.c.d        (deprecated IPv4-compatible, embedded address checked)
 * - 64:ff9b::/96     (NAT64 well-known prefix, embedded address checked)
 */
export function isPrivateIp(ip: string): boolean {
  if (net.isIPv4(ip)) return isPrivateIpv4(ip);
  if (net.isIPv6(ip)) return isPrivateIpv6(ip);
  return true; // unknown format -> treat as unsafe
}

function isPrivateIpv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  const a = parts[0] ?? -1;
  const b = parts[1] ?? -1;
  if (a === 0) return true; // "this" network
  if (a === 10) return true; // RFC 1918
  if (a === 100 && b >= 64 && b <= 127) return true; // carrier-grade NAT
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local / metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // RFC 1918
  if (a === 192 && b === 168) return true; // RFC 1918
  if (a >= 224) return true; // multicast + reserved + broadcast
  return false;
}

function isPrivateIpv4Words(hi: number, lo: number): boolean {
  return isPrivateIpv4(`${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`);
}

/**
 * Expands an IPv6 address (already validated by `net.isIPv6`) into its
 * eight 16-bit groups. Handles `::` compression and embedded dotted IPv4
 * (e.g. `::ffff:127.0.0.1`). Returns null when the address cannot be
 * expanded; callers treat that as unsafe.
 */
function expandIpv6(ip: string): number[] | null {
  let s = ip.split("%")[0]!.toLowerCase(); // strip zone id (fe80::1%eth0)

  // Convert a trailing embedded IPv4 (dotted quad) into two hex groups.
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const quad = v4[1]!.split(".").map(Number);
    if (quad.length !== 4 || quad.some((p) => Number.isNaN(p) || p > 255)) return null;
    const hexTail =
      ((quad[0]! << 8) | quad[1]!).toString(16) + ":" + ((quad[2]! << 8) | quad[3]!).toString(16);
    s = s.slice(0, s.length - v4[1]!.length) + hexTail;
  }

  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  let groups: string[];
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  const nums = groups.map((g) => parseInt(g, 16));
  if (nums.some((n) => Number.isNaN(n) || n < 0 || n > 0xffff)) return null;
  return nums;
}

function isPrivateIpv6(ip: string): boolean {
  const g = expandIpv6(ip);
  if (!g) return true; // could not expand -> treat as unsafe

  const zeroThrough = (end: number) => g.slice(0, end).every((n) => n === 0);

  // :: (unspecified) and ::1 (loopback)
  if (zeroThrough(7) && (g[7] === 0 || g[7] === 1)) return true;

  // IPv4-mapped (::ffff:a.b.c.d) and deprecated IPv4-compatible (::a.b.c.d):
  // judge by the embedded IPv4 address.
  if (zeroThrough(5) && (g[5] === 0xffff || g[5] === 0)) {
    return isPrivateIpv4Words(g[6]!, g[7]!);
  }

  const first = g[0]!;
  if ((first & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((first & 0xfe00) === 0xfc00) return true; // unique local fc00::/7
  if ((first & 0xff00) === 0xff00) return true; // multicast ff00::/8

  // NAT64 well-known prefix 64:ff9b::/96 maps the embedded IPv4 address.
  if (first === 0x0064 && g[1] === 0xff9b && g.slice(2, 6).every((n) => n === 0)) {
    return isPrivateIpv4Words(g[6]!, g[7]!);
  }

  return false;
}
