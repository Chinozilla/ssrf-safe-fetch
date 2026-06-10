import { describe, it, expect, vi } from "vitest";
import { assertPublicUrl, isSafeHttpUrl, SsrfError, type LookupFn } from "./validate.js";

describe("isSafeHttpUrl", () => {
  it("accepts absolute http(s) URLs", () => {
    expect(isSafeHttpUrl("http://example.com")).toBe(true);
    expect(isSafeHttpUrl("https://example.com/path?q=1#frag")).toBe(true);
  });

  it.each([
    "file:///etc/passwd",
    "ftp://example.com/file",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "gopher://example.com",
    "ws://example.com",
    "//example.com/protocol-relative",
    "example.com",
    "/relative/path",
    "",
  ])("rejects %j", (url) => {
    expect(isSafeHttpUrl(url)).toBe(false);
  });

  it("rejects non-string input", () => {
    expect(isSafeHttpUrl(null)).toBe(false);
    expect(isSafeHttpUrl(undefined)).toBe(false);
    expect(isSafeHttpUrl(123)).toBe(false);
    expect(isSafeHttpUrl({ href: "http://example.com" })).toBe(false);
  });
});

function mockLookup(map: Record<string, string[]>): LookupFn {
  return vi.fn(async (hostname: string) => {
    const addrs = map[hostname];
    if (!addrs) throw new Error(`ENOTFOUND ${hostname}`);
    return addrs.map((address) => ({ address }));
  });
}

describe("assertPublicUrl - protocol", () => {
  it.each(["file:///etc/passwd", "ftp://example.com", "javascript:alert(1)", "not a url"])(
    "rejects %j",
    async (url) => {
      await expect(assertPublicUrl(url)).rejects.toThrow(SsrfError);
    },
  );
});

describe("assertPublicUrl - literal IP hosts (no DNS involved)", () => {
  it("allows a public IPv4 literal", async () => {
    const u = await assertPublicUrl("http://93.184.216.34/page");
    expect(u.hostname).toBe("93.184.216.34");
  });

  it("allows a public IPv6 literal", async () => {
    const u = await assertPublicUrl("http://[2606:4700:4700::1111]/");
    expect(u.hostname).toBe("[2606:4700:4700::1111]");
  });

  it.each([
    "http://127.0.0.1/",
    "http://127.0.0.1:8080/admin",
    "http://10.0.0.5/",
    "http://172.16.0.1/",
    "http://192.168.1.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[fe80::1]/",
    "http://[fd00::1]/",
  ])("rejects private literal %s", async (url) => {
    await expect(assertPublicUrl(url)).rejects.toThrow(SsrfError);
  });

  it.each([
    // The WHATWG URL parser canonicalizes numeric hosts to dotted IPv4,
    // so decimal / hex / octal loopback encodings are caught as literals.
    ["http://2130706433/", "decimal"],
    ["http://0x7f000001/", "hex"],
    ["http://0177.0.0.1/", "octal"],
    ["http://0x7f.0.0.1/", "mixed hex"],
    ["http://127.1/", "shorthand"],
  ])("rejects obfuscated loopback %s (%s form)", async (url) => {
    await expect(assertPublicUrl(url)).rejects.toThrow(SsrfError);
  });
});

describe("assertPublicUrl - DNS-resolved hostnames", () => {
  it("allows a hostname resolving only to public addresses", async () => {
    const lookup = mockLookup({ "api.example.com": ["93.184.216.34", "2606:4700:4700::1111"] });
    const u = await assertPublicUrl("https://api.example.com/webhook", { lookup });
    expect(u.hostname).toBe("api.example.com");
    expect(lookup).toHaveBeenCalledWith("api.example.com", { all: true });
  });

  it("rejects a hostname resolving to a private IPv4", async () => {
    const lookup = mockLookup({ "internal.example.com": ["10.0.0.5"] });
    await expect(
      assertPublicUrl("https://internal.example.com/", { lookup }),
    ).rejects.toThrow(/resolves to private address 10\.0\.0\.5/);
  });

  it("rejects a hostname resolving to a private IPv6", async () => {
    const lookup = mockLookup({ "v6.example.com": ["fd00::1"] });
    await expect(assertPublicUrl("https://v6.example.com/", { lookup })).rejects.toThrow(
      SsrfError,
    );
  });

  it("rejects when ANY resolved address is private (split-horizon style)", async () => {
    const lookup = mockLookup({ "split.example.com": ["93.184.216.34", "127.0.0.1"] });
    await expect(assertPublicUrl("https://split.example.com/", { lookup })).rejects.toThrow(
      SsrfError,
    );
  });

  it("rejects when DNS resolution fails", async () => {
    const lookup = mockLookup({});
    await expect(assertPublicUrl("https://nxdomain.example.com/", { lookup })).rejects.toThrow(
      /DNS resolution failed/,
    );
  });

  it("rejects when DNS returns no records", async () => {
    const lookup: LookupFn = async () => [];
    await expect(assertPublicUrl("https://empty.example.com/", { lookup })).rejects.toThrow(
      /No DNS records/,
    );
  });

  it("rejects localhost via real-world style mapping", async () => {
    const lookup = mockLookup({ localhost: ["127.0.0.1", "::1"] });
    await expect(assertPublicUrl("http://localhost:3000/", { lookup })).rejects.toThrow(
      SsrfError,
    );
  });
});
