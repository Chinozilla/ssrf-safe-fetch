import { describe, it, expect } from "vitest";
import { isPrivateIp } from "./ip.js";

describe("isPrivateIp - IPv4", () => {
  const privateV4 = [
    // loopback 127.0.0.0/8
    "127.0.0.1",
    "127.255.255.255",
    // RFC 1918
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.20.10.5",
    "172.31.255.255",
    "192.168.0.1",
    "192.168.255.255",
    // link-local (cloud metadata endpoint included)
    "169.254.169.254",
    "169.254.0.1",
    // "this" network
    "0.0.0.0",
    "0.1.2.3",
    // carrier-grade NAT 100.64.0.0/10
    "100.64.0.1",
    "100.127.255.255",
    // multicast / reserved / broadcast
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "255.255.255.255",
  ];
  it.each(privateV4)("blocks %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  const publicV4 = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "104.16.0.1",
    // boundary neighbours of blocked ranges
    "9.255.255.255",
    "11.0.0.1",
    "172.15.255.255",
    "172.32.0.1",
    "192.167.255.255",
    "192.169.0.1",
    "169.253.255.255",
    "169.255.0.1",
    "100.63.255.255",
    "100.128.0.1",
    "126.255.255.255",
    "128.0.0.1",
    "223.255.255.255",
  ];
  it.each(publicV4)("allows %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(false);
  });
});

describe("isPrivateIp - IPv6", () => {
  const privateV6 = [
    // loopback / unspecified
    "::1",
    "::",
    "0:0:0:0:0:0:0:1",
    // link-local fe80::/10 (full /10, not just the fe80 prefix)
    "fe80::1",
    "fe80::dead:beef",
    "fe9f::1",
    "feaf::1",
    "febf::ffff",
    // unique local fc00::/7
    "fc00::1",
    "fd12:3456:789a::1",
    "fdff::1",
    // multicast ff00::/8
    "ff02::1",
    "ff05::2",
    // IPv4-mapped, dotted form
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:192.168.1.1",
    "::ffff:169.254.169.254",
    // IPv4-mapped, hex form (same address as ::ffff:127.0.0.1)
    "::ffff:7f00:1",
    "::ffff:a00:1",
    // deprecated IPv4-compatible form
    "::127.0.0.1",
    "::10.0.0.1",
    // NAT64 well-known prefix embedding a private IPv4
    "64:ff9b::127.0.0.1",
    "64:ff9b::7f00:1",
  ];
  it.each(privateV6)("blocks %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(true);
  });

  const publicV6 = [
    "2606:4700:4700::1111", // Cloudflare DNS
    "2001:4860:4860::8888", // Google DNS
    "2a00:1450:4001:80b::200e",
    // IPv4-mapped public address stays public
    "::ffff:8.8.8.8",
    "::ffff:808:808",
    // NAT64 embedding a public IPv4
    "64:ff9b::8.8.8.8",
    // boundary neighbours
    "fe7f::1", // just below fe80::/10
    "fec0::1", // just above fe80::/10 (deprecated site-local, not blocked)
    "fbff::1", // just below fc00::/7
    "fe00::1", // just above fc00::/7
  ];
  it.each(publicV6)("allows %s", (ip) => {
    expect(isPrivateIp(ip)).toBe(false);
  });
});

describe("isPrivateIp - fail-closed on garbage", () => {
  const garbage = ["", "not-an-ip", "999.1.1.1", "1.2.3", "1.2.3.4.5", "localhost", "gggg::1"];
  it.each(garbage)("treats %j as unsafe", (value) => {
    expect(isPrivateIp(value)).toBe(true);
  });
});
