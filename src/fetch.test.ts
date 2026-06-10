import { describe, it, expect, vi } from "vitest";
import { safeFetch } from "./fetch.js";
import { SsrfError, type LookupFn } from "./validate.js";

// No real network: DNS is an in-memory map and fetch is a scripted mock.

function mockLookup(map: Record<string, string[]>): LookupFn {
  return async (hostname: string) => {
    const addrs = map[hostname];
    if (!addrs) throw new Error(`ENOTFOUND ${hostname}`);
    return addrs.map((address) => ({ address }));
  };
}

const PUBLIC_DNS = {
  "public.example.com": ["93.184.216.34"],
  "other-public.example.com": ["104.16.0.1"],
  "internal.example.com": ["10.0.0.5"],
  "metadata.example.com": ["169.254.169.254"],
};

function redirectResponse(status: number, location?: string): Response {
  const headers = new Headers();
  if (location !== undefined) headers.set("location", location);
  return new Response(null, { status, headers });
}

/** Builds a fetch mock that serves scripted responses per URL. */
function mockFetch(routes: Record<string, () => Response>) {
  return vi.fn(async (input: string | URL | Request) => {
    const url = String(input);
    const handler = routes[url];
    if (!handler) throw new Error(`Unexpected fetch: ${url}`);
    return handler();
  }) as unknown as typeof fetch & ReturnType<typeof vi.fn>;
}

describe("safeFetch", () => {
  it("returns a plain 200 response", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/data": () => new Response("ok", { status: 200 }),
    });
    const res = await safeFetch(
      "https://public.example.com/data",
      {},
      { lookup: mockLookup(PUBLIC_DNS), fetchImpl },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("forces redirect: 'manual' and per-hop signal on the underlying fetch", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/": () => new Response("ok"),
    });
    await safeFetch(
      "https://public.example.com/",
      { redirect: "follow", method: "GET" },
      { lookup: mockLookup(PUBLIC_DNS), fetchImpl },
    );
    const init = fetchImpl.mock.calls[0]![1] as RequestInit;
    expect(init.redirect).toBe("manual");
    expect(init.signal).toBeInstanceOf(AbortSignal);
  });

  it("follows a redirect chain across public hosts", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/start": () =>
        redirectResponse(302, "https://other-public.example.com/landing"),
      "https://other-public.example.com/landing": () => new Response("final", { status: 200 }),
    });
    const res = await safeFetch(
      "https://public.example.com/start",
      {},
      { lookup: mockLookup(PUBLIC_DNS), fetchImpl },
    );
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("final");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("resolves relative Location headers against the current URL", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/a": () => redirectResponse(301, "/b"),
      "https://public.example.com/b": () => new Response("moved", { status: 200 }),
    });
    const res = await safeFetch(
      "https://public.example.com/a",
      {},
      { lookup: mockLookup(PUBLIC_DNS), fetchImpl },
    );
    expect(await res.text()).toBe("moved");
  });

  it("blocks a redirect to a host that resolves to a private address", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/start": () =>
        redirectResponse(302, "https://internal.example.com/admin"),
    });
    await expect(
      safeFetch("https://public.example.com/start", {}, { lookup: mockLookup(PUBLIC_DNS), fetchImpl }),
    ).rejects.toThrow(/resolves to private address 10\.0\.0\.5/);
    // The internal target must never be fetched.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("blocks a redirect to a private IP literal (metadata endpoint)", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/start": () =>
        redirectResponse(302, "http://169.254.169.254/latest/meta-data/"),
    });
    await expect(
      safeFetch("https://public.example.com/start", {}, { lookup: mockLookup(PUBLIC_DNS), fetchImpl }),
    ).rejects.toThrow(SsrfError);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it("blocks the initial URL before any fetch happens", async () => {
    const fetchImpl = mockFetch({});
    await expect(
      safeFetch("http://127.0.0.1:8080/", {}, { fetchImpl }),
    ).rejects.toThrow(SsrfError);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("returns a 3xx response that has no Location header", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/odd": () => redirectResponse(304),
    });
    const res = await safeFetch(
      "https://public.example.com/odd",
      {},
      { lookup: mockLookup(PUBLIC_DNS), fetchImpl },
    );
    expect(res.status).toBe(304);
  });

  it("throws after exceeding maxRedirects", async () => {
    const fetchImpl = mockFetch({
      "https://public.example.com/loop": () => redirectResponse(302, "/loop"),
    });
    await expect(
      safeFetch(
        "https://public.example.com/loop",
        {},
        { lookup: mockLookup(PUBLIC_DNS), fetchImpl, maxRedirects: 3 },
      ),
    ).rejects.toThrow(/Too many redirects/);
    // initial request + 3 allowed redirects = 4 fetches
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  it("aborts a hanging request after timeoutMs", async () => {
    const fetchImpl = (async (_input: string | URL | Request, init?: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("aborted")));
      })) as typeof fetch;
    await expect(
      safeFetch(
        "https://public.example.com/slow",
        {},
        { lookup: mockLookup(PUBLIC_DNS), fetchImpl, timeoutMs: 20 },
      ),
    ).rejects.toThrow("aborted");
  });
});
