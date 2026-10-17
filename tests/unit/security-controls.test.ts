import { describe, expect, it } from "vitest";
import { assertSameOrigin } from "@/lib/api";
import {
  isBlockedHostname,
  isPrivateOrReservedIp,
  validatePublicUrl,
  validateResolvedAddresses
} from "@/lib/scanning/network-safety";
import { sanitizeCsvCell, toCsv } from "@/lib/services/csv";
import { checkRateLimit, resetRateLimits } from "@/lib/services/rate-limit";
import { domainSchema } from "@/lib/validation/common";

describe("network safety", () => {
  it.each([
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.3",
    "169.254.169.254",
    "203.0.113.8",
    "::1",
    "fd00::1",
    "::ffff:127.0.0.1",
    "2001:db8::1"
  ])("blocks private or reserved %s", (ip: string) => {
    expect(isPrivateOrReservedIp(ip)).toBe(true);
  });

  it("allows a public address", () => {
    expect(isPrivateOrReservedIp("8.8.8.8")).toBe(false);
  });

  it.each([
    "localhost",
    "api.localhost",
    "metadata.google.internal",
    "service.internal",
    "router.lan"
  ])("blocks localhost and metadata hostname %s", (hostname: string) => {
    expect(isBlockedHostname(hostname)).toBe(true);
  });

  it("rejects mixed public and private DNS answers", () => {
    expect(() =>
      validateResolvedAddresses([
        { address: "8.8.8.8", family: 4 },
        { address: "127.0.0.1", family: 4 }
      ])
    ).toThrow(/blocked private or reserved/i);
  });

  it("blocks decimal, encoded and mapped loopback destinations", () => {
    expect(() => validatePublicUrl("http://2130706433/")).toThrow(/blocked/i);
    expect(() => validatePublicUrl("http://127.1/")).toThrow(/blocked/i);
    expect(() => validatePublicUrl("http://[::1]/")).toThrow(/blocked/i);
    expect(() => validatePublicUrl("http://[::ffff:127.0.0.1]/")).toThrow(/blocked/i);
  });

  it("blocks redirect destinations outside the verified boundary", () => {
    expect(() => validatePublicUrl("http://127.0.0.1/admin", "verified.example")).toThrow(
      /blocked/i
    );
    expect(() =>
      validatePublicUrl("https://169.254.169.254/latest/meta-data", "verified.example")
    ).toThrow(/blocked/i);
    expect(() =>
      validatePublicUrl("https://other.example/path", "verified.example")
    ).toThrow(/boundary/i);
  });

  it("allows a verified public subdomain", () => {
    expect(
      validatePublicUrl("https://app.verified.example/path", "verified.example").hostname
    ).toBe("app.verified.example");
  });
});

describe("domain verification input", () => {
  it("accepts a root domain and rejects a URL or raw private IP", () => {
    expect(domainSchema.parse("northstar.test")).toBe("northstar.test");
    expect(() => domainSchema.parse("https://northstar.test")).toThrow();
    expect(() => domainSchema.parse("127.0.0.1")).toThrow();
  });
});

describe("rate limiting", () => {
  it("blocks after the configured count", () => {
    resetRateLimits();
    expect(checkRateLimit("ip", 2, 1000, 0).allowed).toBe(true);
    expect(checkRateLimit("ip", 2, 1000, 1).allowed).toBe(true);
    expect(checkRateLimit("ip", 2, 1000, 2).allowed).toBe(false);
  });
});

describe("CSV hardening", () => {
  it.each(["=2+2", "+CMD", "-10+20", "@SUM(A1:A2)"])(
    "prefixes spreadsheet formula %s",
    (value: string) => {
      expect(sanitizeCsvCell(value)).toContain("'");
    }
  );

  it("escapes quotes and preserves safe values", () => {
    expect(toCsv([{ name: "normal", note: '+CMD|"x"' }])).toContain("'+CMD|");
    expect(sanitizeCsvCell("normal")).toBe("normal");
  });
});

// Request-origin enforcement is tested through the production API helper.

describe("same-origin mutation protection", () => {
  it("rejects an explicit cross-site browser request", () => {
    const request = new Request("http://localhost:3000/api/scans", {
      method: "POST",
      headers: { "sec-fetch-site": "cross-site" }
    });
    expect(() => assertSameOrigin(request)).toThrow("FORBIDDEN");
  });

  it("rejects a mismatched Origin header", () => {
    const request = new Request("http://localhost:3000/api/scans", {
      method: "POST",
      headers: { origin: "https://attacker.example" }
    });
    expect(() => assertSameOrigin(request)).toThrow("FORBIDDEN");
  });

  it("allows same-origin browser and non-browser requests", () => {
    expect(() =>
      assertSameOrigin(
        new Request("http://localhost:3000/api/scans", {
          method: "POST",
          headers: {
            origin: "http://localhost:3000",
            "sec-fetch-site": "same-origin"
          }
        })
      )
    ).not.toThrow();
    expect(() =>
      assertSameOrigin(new Request("http://localhost:3000/api/scans", { method: "POST" }))
    ).not.toThrow();
  });
});
