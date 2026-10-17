import { lookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { env } from "@/lib/env";

function normalizeIpLiteral(ip: string) {
  const withoutBrackets = ip.startsWith("[") && ip.endsWith("]") ? ip.slice(1, -1) : ip;
  return withoutBrackets.split("%", 1)[0]?.toLowerCase() ?? withoutBrackets.toLowerCase();
}

function ipv4ToInt(ip: string) {
  const octets = ip.split(".").map(Number);
  if (
    octets.length !== 4 ||
    octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)
  ) {
    return null;
  }
  return octets.reduce((sum, octet) => (sum << 8) + octet, 0) >>> 0;
}

function inCidr4(ip: string, base: string, prefix: number) {
  const value = ipv4ToInt(ip);
  const network = ipv4ToInt(base);
  if (value === null || network === null) return false;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (value & mask) === (network & mask);
}

const blockedV4: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4]
];

function parseIpv6(ipInput: string) {
  let ip = normalizeIpLiteral(ipInput);
  if (!ip.includes(":")) return null;
  const ipv4Match = ip.match(/(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (ipv4Match?.[1]) {
    const ipv4 = ipv4ToInt(ipv4Match[1]);
    if (ipv4 === null) return null;
    ip =
      ip.slice(0, ip.length - ipv4Match[1].length) +
      `${(ipv4 >>> 16).toString(16)}:${(ipv4 & 0xffff).toString(16)}`;
  }
  if ((ip.match(/::/g) ?? []).length > 1) return null;
  const [leftRaw, rightRaw] = ip.split("::");
  const left = leftRaw ? leftRaw.split(":") : [];
  const right = rightRaw ? rightRaw.split(":") : [];
  if (!ip.includes("::") && left.length !== 8) return null;
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (ip.includes("::") && missing < 1)) return null;
  const groups = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  if (groups.length !== 8 || groups.some((group) => !/^[0-9a-f]{1,4}$/i.test(group))) {
    return null;
  }
  return groups.reduce(
    (value, group) => (value << 16n) | BigInt(Number.parseInt(group, 16)),
    0n
  );
}

function inCidr6(ip: bigint, base: string, prefix: number) {
  const network = parseIpv6(base);
  if (network === null) return false;
  const shift = BigInt(128 - prefix);
  return ip >> shift === network >> shift;
}

const blockedV6: Array<[string, number]> = [
  ["::", 128],
  ["::1", 128],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 23],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
  ["5f00::", 16],
  ["fc00::", 7],
  ["fe80::", 10],
  ["fec0::", 10],
  ["ff00::", 8]
];

export function isPrivateOrReservedIp(ipInput: string) {
  const ip = normalizeIpLiteral(ipInput);
  const family = net.isIP(ip);
  if (family === 4) return blockedV4.some(([base, prefix]) => inCidr4(ip, base, prefix));
  if (family !== 6) return true;
  const value = parseIpv6(ip);
  if (value === null) return true;
  const mappedPrefix = parseIpv6("::ffff:0:0");
  if (mappedPrefix !== null && value >> 32n === mappedPrefix >> 32n) {
    const mapped = Number(value & 0xffffffffn);
    const dotted = `${mapped >>> 24}.${(mapped >>> 16) & 255}.${(mapped >>> 8) & 255}.${mapped & 255}`;
    return blockedV4.some(([base, prefix]) => inCidr4(dotted, base, prefix));
  }
  return blockedV6.some(([base, prefix]) => inCidr6(value, base, prefix));
}

export function isBlockedHostname(hostnameInput: string) {
  const hostname = hostnameInput.trim().replace(/\.+$/, "").toLowerCase();
  if (!hostname) return true;
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".home") ||
    hostname.endsWith(".lan")
  ) {
    return true;
  }
  return [
    "metadata.google.internal",
    "metadata.azure.internal",
    "instance-data",
    "instance-data.ec2.internal"
  ].includes(hostname);
}

export type ResolvedAddress = { address: string; family: number };

export function validateResolvedAddresses(records: ResolvedAddress[]) {
  if (!records.length) throw new Error("DNS resolution returned no addresses");
  const blocked = records.find((record) => isPrivateOrReservedIp(record.address));
  if (blocked) throw new Error(`Blocked private or reserved address: ${blocked.address}`);
  return records;
}

export async function resolvePublicAddresses(hostname: string) {
  if (isBlockedHostname(hostname))
    throw new Error("Local or metadata hostnames are blocked");
  const records = await lookup(hostname, { all: true, verbatim: true });
  return validateResolvedAddresses(records);
}

export function validatePublicUrl(input: string, expectedHostname?: string) {
  const url = new URL(input);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are permitted");
  }
  if (url.username || url.password)
    throw new Error("Credentials in URLs are not permitted");
  if (url.port && !["80", "443", "8080", "8443"].includes(url.port)) {
    throw new Error("URL port is not permitted");
  }
  const hostname = normalizeIpLiteral(url.hostname);
  if (isBlockedHostname(hostname))
    throw new Error("Local or metadata hostnames are blocked");
  if (net.isIP(hostname) && isPrivateOrReservedIp(hostname)) {
    throw new Error("Private or reserved destinations are blocked");
  }
  const expected = expectedHostname
    ? expectedHostname.trim().replace(/\.+$/, "").toLowerCase()
    : undefined;
  if (expected && url.hostname !== expected && !url.hostname.endsWith(`.${expected}`)) {
    throw new Error("Redirect left the verified domain boundary");
  }
  return url;
}

export type SafeHttpResponse = {
  status: number;
  ok: boolean;
  headers: Headers;
  text: () => Promise<string>;
};

export async function requestPinned(
  url: URL,
  timeoutMs: number,
  signal?: AbortSignal
): Promise<SafeHttpResponse> {
  const addresses = await resolvePublicAddresses(url.hostname);
  const pinned = addresses[0];
  if (!pinned) throw new Error("DNS resolution returned no usable public address");
  const transport = url.protocol === "https:" ? https : http;

  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Scan operation was aborted"));
      return;
    }
    const request = transport.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        servername: url.hostname,
        headers: {
          Host: url.host,
          "User-Agent": "RiskMap-SafeScanner/0.2 (+authorised-use-only)",
          Accept: "text/html,text/plain,application/security.txt;q=0.9,*/*;q=0.1"
        },
        lookup: (_hostname, _options, callback) =>
          callback(null, pinned.address, pinned.family)
      },
      (response) => {
        const chunks: Buffer[] = [];
        let size = 0;
        response.on("data", (chunk: Buffer | string) => {
          const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
          size += buffer.length;
          if (size <= env.SCAN_RESPONSE_LIMIT_BYTES) chunks.push(buffer);
          if (size > env.SCAN_RESPONSE_LIMIT_BYTES) {
            response.destroy(
              new Error(
                `Response body exceeded the ${env.SCAN_RESPONSE_LIMIT_BYTES}-byte safety limit`
              )
            );
          }
        });
        response.on("error", reject);
        response.on("end", () => {
          const headers = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (Array.isArray(value)) value.forEach((item) => headers.append(name, item));
            else if (value !== undefined) headers.set(name, String(value));
          }
          const status = response.statusCode ?? 0;
          const body = Buffer.concat(chunks).toString("utf8");
          resolve({
            status,
            ok: status >= 200 && status < 300,
            headers,
            text: async () => body
          });
        });
      }
    );
    const abort = () => request.destroy(new Error("Scan operation was aborted"));
    signal?.addEventListener("abort", abort, { once: true });
    request.setTimeout(timeoutMs, () => request.destroy(new Error("Request timed out")));
    request.once("close", () => signal?.removeEventListener("abort", abort));
    request.once("error", reject);
    request.end();
  });
}

export type SafeFetchResult = {
  response: SafeHttpResponse;
  finalUrl: string;
  redirects: number;
  redirectHistory: string[];
  blockedRedirect?: string;
};

export async function safeFetch(
  urlInput: string,
  options?: {
    timeoutMs?: number;
    expectedHostname?: string;
    maxRedirects?: number;
    observeExternalRedirect?: boolean;
    signal?: AbortSignal;
    request?: typeof requestPinned;
  }
): Promise<SafeFetchResult> {
  const timeoutMs = options?.timeoutMs ?? 5000;
  const maxRedirects = options?.maxRedirects ?? 3;
  let current = validatePublicUrl(urlInput, options?.expectedHostname);
  const redirectHistory = [current.toString()];
  const request = options?.request ?? requestPinned;

  for (let redirects = 0; redirects <= maxRedirects; redirects += 1) {
    const response = await request(current, timeoutMs, options?.signal);
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      return {
        response,
        finalUrl: current.toString(),
        redirects,
        redirectHistory
      };
    }
    const location = response.headers.get("location");
    if (!location) {
      return {
        response,
        finalUrl: current.toString(),
        redirects,
        redirectHistory
      };
    }
    if (redirects === maxRedirects) throw new Error("Redirect limit exceeded");
    const candidate = new URL(location, current);
    try {
      current = validatePublicUrl(candidate.toString(), options?.expectedHostname);
    } catch (error) {
      if (!options?.observeExternalRedirect) throw error;
      validatePublicUrl(candidate.toString());
      return {
        response,
        finalUrl: current.toString(),
        redirects,
        redirectHistory,
        blockedRedirect: candidate.toString()
      };
    }
    if (!options?.request) await resolvePublicAddresses(current.hostname);
    redirectHistory.push(current.toString());
  }
  throw new Error("Redirect handling failed");
}
