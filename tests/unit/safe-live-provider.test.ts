import { describe, expect, it, vi } from "vitest";
import { safeFetch, type SafeHttpResponse } from "@/lib/scanning/network-safety";
import {
  SafeLiveScanProvider,
  type SafeLiveAdapters
} from "@/lib/scanning/safe-live-provider";

function response(
  input: {
    status?: number;
    headers?: Record<string, string>;
    body?: string;
  } = {}
): SafeHttpResponse {
  const headers = new Headers(input.headers);
  const status = input.status ?? 200;
  return {
    status,
    ok: status >= 200 && status < 300,
    headers,
    text: async () => input.body ?? ""
  };
}

function providerAdapters(overrides: Partial<SafeLiveAdapters> = {}): SafeLiveAdapters {
  return {
    resolve4: vi.fn(async () => ["8.8.8.8"]),
    resolve6: vi.fn(async () => []),
    resolveCname: vi.fn(async () => []),
    resolveMx: vi.fn(async () => []),
    resolveNs: vi.fn(async () => []),
    resolveTxt: vi.fn(async () => []),
    safeFetch: vi.fn(async (url: string) => ({
      response: response({
        status: url.includes("security.txt") ? 404 : 200,
        headers: {
          "strict-transport-security": "max-age=31536000",
          "content-security-policy": "default-src 'self'",
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
          "referrer-policy": "no-referrer",
          "permissions-policy": "camera=()"
        }
      }),
      finalUrl: url,
      redirects: 0,
      redirectHistory: [url]
    })),
    inspectTls: vi.fn(async () => ({
      serialNumber: "A1",
      validTo: "Dec 31 23:59:59 2030 GMT",
      daysRemaining: 1200,
      subjectAltNames: ["app.verified.example"],
      hostnameValid: true,
      protocol: "TLSv1.3"
    })),
    tcpConnect: vi.fn(async () => false),
    ...overrides
  };
}

describe("safe-live provider boundary handling", () => {
  it("uses bounded adapters and produces conservative public observations", async () => {
    const adapters = providerAdapters();
    const result = await new SafeLiveScanProvider(adapters).scan("verified.example", {
      activeChecks: false
    });

    expect(result.assets.some((asset) => asset.ipAddress === "8.8.8.8")).toBe(true);
    expect(result.assets.some((asset) => asset.hostname === "app.verified.example")).toBe(
      true
    );
    expect(result.modules.find((item) => item.module === "DNS")?.status).toBe("COMPLETED");
    expect(adapters.tcpConnect).not.toHaveBeenCalled();
    expect(result.log.join(" ")).toMatch(/passive checks/i);
  });

  it("suppresses every active adapter when DNS mixes public and blocked addresses", async () => {
    const safeHttp = vi.fn();
    const inspectTls = vi.fn();
    const tcpConnect = vi.fn();
    const adapters = providerAdapters({
      resolve4: vi.fn(async () => ["8.8.8.8", "127.0.0.1"]),
      safeFetch: safeHttp,
      inspectTls,
      tcpConnect
    });

    const result = await new SafeLiveScanProvider(adapters).scan("verified.example", {
      activeChecks: true
    });

    expect(result.assets.some((asset) => asset.ipAddress === "127.0.0.1")).toBe(false);
    expect(result.modules.find((item) => item.module === "DNS")?.status).toBe("PARTIAL");
    expect(result.modules.find((item) => item.module === "PORT_CHECKS")?.status).toBe(
      "SKIPPED"
    );
    expect(result.findings.some((item) => item.ruleId === "https.not-observed")).toBe(
      false
    );
    expect(safeHttp).not.toHaveBeenCalled();
    expect(inspectTls).not.toHaveBeenCalled();
    expect(tcpConnect).not.toHaveBeenCalled();
  });

  it("fails closed when HTTP, TLS or TCP adapters reject or time out", async () => {
    const adapters = providerAdapters({
      safeFetch: vi.fn(async () => {
        throw new Error("Request timed out");
      }),
      inspectTls: vi.fn(async () => {
        throw new Error("TLS handshake timed out");
      }),
      tcpConnect: vi.fn(async () => false)
    });

    const result = await new SafeLiveScanProvider(adapters).scan("verified.example", {
      activeChecks: true
    });

    expect(result.modules.find((item) => item.module === "HTTP")?.status).toBe("FAILED");
    expect(result.modules.find((item) => item.module === "TLS")?.status).toBe("FAILED");
    expect(result.services).toHaveLength(0);
  });
});

describe("safe redirect engine", () => {
  it("blocks a redirect to localhost before a second request", async () => {
    const request = vi.fn(async () =>
      response({ status: 302, headers: { location: "http://127.0.0.1/admin" } })
    );

    await expect(
      safeFetch("https://verified.example", {
        expectedHostname: "verified.example",
        request
      })
    ).rejects.toThrow(/blocked|private|reserved/i);
    expect(request).toHaveBeenCalledTimes(1);
  });

  it("blocks a redirect to a metadata endpoint", async () => {
    const request = vi.fn(async () =>
      response({
        status: 302,
        headers: { location: "http://169.254.169.254/latest/meta-data" }
      })
    );

    await expect(
      safeFetch("https://verified.example", {
        expectedHostname: "verified.example",
        request
      })
    ).rejects.toThrow(/blocked|private|reserved/i);
  });

  it("enforces the redirect limit and propagates a rebinding-style failure", async () => {
    const loopingRequest = vi.fn(async () =>
      response({ status: 302, headers: { location: "/again" } })
    );
    await expect(
      safeFetch("https://verified.example", {
        expectedHostname: "verified.example",
        maxRedirects: 1,
        request: loopingRequest
      })
    ).rejects.toThrow(/redirect limit/i);

    let calls = 0;
    const rebindingRequest = vi.fn(async () => {
      calls += 1;
      if (calls === 1) {
        return response({ status: 302, headers: { location: "/next" } });
      }
      throw new Error("Blocked private or reserved address: 127.0.0.1");
    });
    await expect(
      safeFetch("https://verified.example", {
        expectedHostname: "verified.example",
        request: rebindingRequest
      })
    ).rejects.toThrow(/blocked private or reserved/i);
  });

  it("rejects disallowed URL ports before network activity", async () => {
    const request = vi.fn();
    await expect(
      safeFetch("https://verified.example:4444", {
        expectedHostname: "verified.example",
        request
      })
    ).rejects.toThrow(/port is not permitted/i);
    expect(request).not.toHaveBeenCalled();
  });
});
