import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { allowedPorts, env } from "@/lib/env";
import { normalizeHostname } from "@/lib/scanning/identity";
import {
  isPrivateOrReservedIp,
  resolvePublicAddresses,
  safeFetch
} from "@/lib/scanning/network-safety";
import type {
  ScanAssetInput,
  ScanFindingInput,
  ScanModuleResultInput,
  ScanProvider,
  ScanProviderOptions,
  ScanProviderResult,
  ScanRelationshipInput,
  ScanServiceInput,
  ScanTechnologyInput
} from "@/lib/scanning/types";

type Settled<T> = { ok: true; value: T } | { ok: false; error: string };

async function settle<T>(operation: Promise<T>, signal?: AbortSignal): Promise<Settled<T>> {
  try {
    if (signal?.aborted) throw new Error("Scan operation was aborted");
    const value = signal
      ? await Promise.race([
          operation,
          new Promise<never>((_, reject) => {
            signal.addEventListener(
              "abort",
              () => reject(new Error("Scan operation was aborted")),
              { once: true }
            );
          })
        ])
      : await operation;
    return { ok: true, value };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : "Unknown error" };
  }
}

async function defaultTcpConnect(
  host: string,
  port: number,
  timeoutMs: number,
  signal?: AbortSignal
) {
  const addresses = await resolvePublicAddresses(host);
  const target = addresses[0];
  if (!target) return false;
  return new Promise<boolean>((resolve) => {
    if (signal?.aborted) {
      resolve(false);
      return;
    }
    const socket = net.createConnection({
      host: target.address,
      port,
      family: target.family
    });
    let finished = false;
    const finish = (result: boolean) => {
      if (finished) return;
      finished = true;
      signal?.removeEventListener("abort", abort);
      socket.destroy();
      resolve(result);
    };
    const abort = () => finish(false);
    signal?.addEventListener("abort", abort, { once: true });
    socket.setTimeout(timeoutMs, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

async function defaultInspectTls(host: string, timeoutMs: number, signal?: AbortSignal) {
  const addresses = await resolvePublicAddresses(host);
  const target = addresses[0];
  if (!target) throw new Error("No public address was available for TLS inspection");
  return new Promise<Record<string, unknown>>((resolve, reject) => {
    if (signal?.aborted) {
      reject(new Error("Scan operation was aborted"));
      return;
    }
    const socket = tls.connect({
      host: target.address,
      port: 443,
      servername: host,
      rejectUnauthorized: false,
      timeout: timeoutMs
    });
    const abort = () => socket.destroy(new Error("Scan operation was aborted"));
    signal?.addEventListener("abort", abort, { once: true });
    socket.once("close", () => signal?.removeEventListener("abort", abort));
    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate(true);
      const validTo = certificate.valid_to ? new Date(certificate.valid_to) : null;
      const altNames = String(certificate.subjectaltname ?? "")
        .split(",")
        .map((item) => item.trim().replace(/^DNS:/i, ""))
        .filter(Boolean);
      const hostnameError = tls.checkServerIdentity(host, certificate);
      resolve({
        subject: certificate.subject?.CN ?? null,
        issuer: certificate.issuer?.CN ?? null,
        serialNumber: certificate.serialNumber ?? null,
        fingerprint256: certificate.fingerprint256 ?? null,
        validFrom: certificate.valid_from ?? null,
        validTo: certificate.valid_to ?? null,
        daysRemaining: validTo
          ? Math.floor((validTo.getTime() - Date.now()) / 86_400_000)
          : null,
        subjectAltNames: altNames,
        hostnameValid: !hostnameError,
        authorizationError: hostnameError?.message ?? null,
        protocol: socket.getProtocol()
      });
      socket.end();
    });
    socket.once("timeout", () => socket.destroy(new Error("TLS handshake timed out")));
    socket.once("error", reject);
  });
}

export type SafeLiveAdapters = {
  resolve4: (hostname: string) => Promise<string[]>;
  resolve6: (hostname: string) => Promise<string[]>;
  resolveCname: (hostname: string) => Promise<string[]>;
  resolveMx: (hostname: string) => Promise<Array<{ exchange: string; priority: number }>>;
  resolveNs: (hostname: string) => Promise<string[]>;
  resolveTxt: (hostname: string) => Promise<string[][]>;
  safeFetch: typeof safeFetch;
  inspectTls: typeof defaultInspectTls;
  tcpConnect: typeof defaultTcpConnect;
};

const defaultAdapters: SafeLiveAdapters = {
  resolve4: (hostname) => dns.resolve4(hostname),
  resolve6: (hostname) => dns.resolve6(hostname),
  resolveCname: (hostname) => dns.resolveCname(hostname),
  resolveMx: (hostname) => dns.resolveMx(hostname),
  resolveNs: (hostname) => dns.resolveNs(hostname),
  resolveTxt: (hostname) => dns.resolveTxt(hostname),
  safeFetch,
  inspectTls: defaultInspectTls,
  tcpConnect: defaultTcpConnect
};

function missingHeaderFinding(
  domain: string,
  ruleId: string,
  header: string,
  title: string,
  severity: "MEDIUM" | "LOW",
  remediation: string
): ScanFindingInput {
  return {
    assetName: domain,
    service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
    ruleId,
    module: "HTTP",
    evidenceIdentity: `root-response:${header.toLowerCase()}`,
    title,
    severity,
    category: "HTTP security headers",
    description: `The sampled HTTPS root response did not include ${header}. This observation does not prove compromise or exploitability.`,
    evidence: `${header} was absent from the sampled root response.`,
    confidence: "HIGH",
    remediation,
    technicalDetail:
      "RiskMap sampled only the root response within a strict response-size and redirect limit. Other routes may differ.",
    businessImpact:
      "Appropriate response headers can reduce exposure to specific browser-side attack techniques when correctly designed.",
    references: [],
    externallyReachable: true
  };
}

function addAssetOnce(assets: ScanAssetInput[], asset: ScanAssetInput) {
  const key = `${asset.type}|${asset.hostname ?? ""}|${asset.ipAddress ?? ""}|${asset.serviceIdentifier ?? ""}`;
  const exists = assets.some(
    (candidate) =>
      `${candidate.type}|${candidate.hostname ?? ""}|${candidate.ipAddress ?? ""}|${candidate.serviceIdentifier ?? ""}` ===
      key
  );
  if (!exists) assets.push(asset);
}

function insideRoot(hostname: string, root: string) {
  const normalized = normalizeHostname(hostname);
  const normalizedRoot = normalizeHostname(root);
  return Boolean(
    normalized &&
      normalizedRoot &&
      (normalized === normalizedRoot || normalized.endsWith(`.${normalizedRoot}`))
  );
}

export class SafeLiveScanProvider implements ScanProvider {
  name = "safe-live-provider";
  private readonly adapters: SafeLiveAdapters;

  constructor(adapters: Partial<SafeLiveAdapters> = {}) {
    this.adapters = { ...defaultAdapters, ...adapters };
  }

  async scan(
    domain: string,
    options: ScanProviderOptions = { activeChecks: false }
  ): Promise<ScanProviderResult> {
    const timeoutMs = env.SCAN_TIMEOUT_MS;
    const assets: ScanAssetInput[] = [
      {
        name: domain,
        type: "ROOT_DOMAIN",
        hostname: domain,
        criticality: "HIGH",
        source: "Verified root domain",
        tags: ["verified"]
      }
    ];
    const services: ScanServiceInput[] = [];
    const technologies: ScanTechnologyInput[] = [];
    const findings: ScanFindingInput[] = [];
    const relationships: ScanRelationshipInput[] = [];
    const observations: ScanProviderResult["observations"] = [];
    const modules: ScanModuleResultInput[] = [];
    const log: string[] = [
      "Domain ownership and scan permission were validated before provider execution."
    ];

    const [aResult, aaaaResult, cnameResult, mxResult, nsResult, txtResult, dmarcResult] =
      await Promise.all([
        settle(this.adapters.resolve4(domain), options.signal),
        settle(this.adapters.resolve6(domain), options.signal),
        settle(this.adapters.resolveCname(domain), options.signal),
        settle(this.adapters.resolveMx(domain), options.signal),
        settle(this.adapters.resolveNs(domain), options.signal),
        settle(this.adapters.resolveTxt(domain), options.signal),
        settle(this.adapters.resolveTxt(`_dmarc.${domain}`), options.signal)
      ]);

    const a = aResult.ok ? aResult.value : [];
    const aaaa = aaaaResult.ok ? aaaaResult.value : [];
    const cname = cnameResult.ok ? cnameResult.value : [];
    const mx = mxResult.ok ? mxResult.value : [];
    const ns = nsResult.ok ? nsResult.value : [];
    const txt = txtResult.ok ? txtResult.value.flat() : [];
    const dmarc = dmarcResult.ok ? dmarcResult.value.flat() : [];
    const dnsFailures = [aResult, aaaaResult, cnameResult, mxResult, nsResult, txtResult]
      .filter((result) => !result.ok)
      .map((result) => (result as { ok: false; error: string }).error);
    const blockedDnsAddresses = [...a, ...aaaa].filter(isPrivateOrReservedIp);
    const publicDnsAddresses = [...a, ...aaaa].filter(
      (address) => !isPrivateOrReservedIp(address)
    );
    const dnsBoundaryBlocked = blockedDnsAddresses.length > 0;
    if (dnsBoundaryBlocked) {
      log.push(
        `Active network checks were blocked because DNS returned ${blockedDnsAddresses.length} private or reserved address(es).`
      );
    }

    for (const address of publicDnsAddresses) {
      addAssetOnce(assets, {
        name: address,
        type: "IP_ADDRESS",
        ipAddress: address,
        criticality: "MEDIUM",
        source: "DNS address record",
        tags: ["dns"]
      });
      relationships.push({
        from: domain,
        to: address,
        type: "Resolves to",
        source: "DNS",
        confidence: "HIGH",
        evidence: `${domain} returned address ${address}.`,
        state: "OBSERVED"
      });
    }

    for (const target of cname) {
      addAssetOnce(assets, {
        name: target,
        type: insideRoot(target, domain) ? "SUBDOMAIN" : "EXTERNAL_DEPENDENCY",
        hostname: target,
        criticality: "MEDIUM",
        source: "DNS CNAME",
        tags: [insideRoot(target, domain) ? "subdomain" : "external"]
      });
      relationships.push({
        from: domain,
        to: target,
        type: "CNAME points to",
        source: "DNS",
        confidence: "HIGH",
        evidence: `${domain} returned CNAME ${target}.`,
        state: "OBSERVED"
      });
    }

    for (const record of mx) {
      addAssetOnce(assets, {
        name: record.exchange,
        type: insideRoot(record.exchange, domain) ? "EMAIL_SERVICE" : "EXTERNAL_DEPENDENCY",
        hostname: record.exchange,
        criticality: "HIGH",
        source: "DNS MX",
        tags: ["mail"]
      });
      relationships.push({
        from: domain,
        to: record.exchange,
        type: "Uses mail provider",
        source: "DNS MX",
        confidence: "HIGH",
        evidence: `MX preference ${record.priority} points to ${record.exchange}.`,
        state: "OBSERVED"
      });
    }

    for (const target of ns) {
      addAssetOnce(assets, {
        name: target,
        type: insideRoot(target, domain) ? "DNS_SERVICE" : "EXTERNAL_DEPENDENCY",
        hostname: target,
        criticality: "HIGH",
        source: "DNS NS",
        tags: ["dns"]
      });
      relationships.push({
        from: domain,
        to: target,
        type: "Depends on",
        source: "DNS NS",
        confidence: "HIGH",
        evidence: `${target} is an authoritative name server for ${domain}.`,
        state: "OBSERVED"
      });
    }

    observations.push({
      assetName: domain,
      module: "DNS",
      type: "DNS",
      identity: "root-dns-set",
      success: dnsFailures.length < 6,
      data: {
        A: a,
        AAAA: aaaa,
        CNAME: cname,
        MX: mx,
        NS: ns,
        TXT: txt,
        DMARC: dmarc,
        blockedAddresses: blockedDnsAddresses
      }
    });
    modules.push({
      module: "DNS",
      status:
        dnsFailures.length >= 6
          ? "FAILED"
          : dnsFailures.length > 0 || dnsBoundaryBlocked
            ? "PARTIAL"
            : "COMPLETED",
      recordCount:
        a.length +
        aaaa.length +
        cname.length +
        mx.length +
        ns.length +
        txt.length +
        dmarc.length,
      error:
        [
          ...dnsFailures.slice(0, 3),
          ...(dnsBoundaryBlocked
            ? ["DNS returned a private or reserved address; active checks were suppressed."]
            : [])
        ].join("; ") || undefined
    });
    modules.push({
      module: "PASSIVE_DISCOVERY",
      status: dnsFailures.length < 6 && !dnsBoundaryBlocked ? "COMPLETED" : "PARTIAL",
      recordCount: assets.length
    });
    log.push(`DNS modules produced ${assets.length} normalised asset candidates.`);

    const spf = txt.find((value) => /^v=spf1/i.test(value));
    if (!spf) {
      findings.push({
        assetName: domain,
        ruleId: "email.spf.missing",
        module: "EMAIL_SECURITY",
        evidenceIdentity: "spf:absent",
        title: "SPF record not observed",
        severity: "MEDIUM",
        category: "Email authentication",
        description: "No SPF policy was observed in the sampled root TXT records.",
        evidence: "No TXT value beginning with v=spf1 was returned.",
        confidence: txtResult.ok ? "HIGH" : "LOW",
        remediation:
          "Inventory authorised mail sources and publish an SPF policy that reflects them.",
        technicalDetail:
          "DNS lookup failure can cause a false absence. Validate before remediation.",
        businessImpact:
          "Missing sender policy can make direct-domain spoofing controls less effective.",
        references: ["RFC 7208"],
        externallyReachable: true
      });
    } else if (/\?all|~all/i.test(spf)) {
      findings.push({
        assetName: domain,
        ruleId: "email.spf.weak-policy",
        module: "EMAIL_SECURITY",
        evidenceIdentity: `spf:${spf}`,
        title: "SPF policy is not strict",
        severity: "LOW",
        category: "Email authentication",
        description: "The observed SPF record uses a neutral or soft-fail ending.",
        evidence: spf,
        confidence: "HIGH",
        remediation:
          "Validate all legitimate senders before considering a stricter policy.",
        technicalDetail:
          "RiskMap evaluates the record text and does not recursively validate every sender.",
        businessImpact:
          "A permissive policy can provide weaker resistance to direct-domain spoofing.",
        references: ["RFC 7208"],
        externallyReachable: true
      });
    }

    if (!dmarc.length) {
      findings.push({
        assetName: domain,
        ruleId: "email.dmarc.missing",
        module: "EMAIL_SECURITY",
        evidenceIdentity: "dmarc:absent",
        title: "DMARC record not observed",
        severity: "MEDIUM",
        category: "Email authentication",
        description: "No DMARC policy was observed at the standard _dmarc hostname.",
        evidence: `No TXT response was obtained for _dmarc.${domain}.`,
        confidence: dmarcResult.ok ? "HIGH" : "LOW",
        remediation:
          "Publish DMARC in monitoring mode, review reports and move toward enforcement when ready.",
        technicalDetail:
          "A DNS lookup failure can also cause this result, so validation is required.",
        businessImpact:
          "Missing DMARC can reduce protection and reporting for direct-domain impersonation.",
        references: ["RFC 7489"],
        externallyReachable: true
      });
    } else if (dmarc.some((value) => /\bp=none\b/i.test(value))) {
      findings.push({
        assetName: domain,
        ruleId: "email.dmarc.monitoring-only",
        module: "EMAIL_SECURITY",
        evidenceIdentity: `dmarc:${dmarc.join("|")}`,
        title: "DMARC policy is monitoring only",
        severity: "LOW",
        category: "Email authentication",
        description: "The observed DMARC policy is set to monitoring only.",
        evidence: dmarc.join("; "),
        confidence: "HIGH",
        remediation: "Review reports and legitimate senders before gradual enforcement.",
        technicalDetail:
          "Policy text alone does not show whether enforcement is operationally ready.",
        businessImpact:
          "Monitoring-only policy provides limited direct-domain spoofing enforcement.",
        references: ["RFC 7489"],
        externallyReachable: true
      });
    }
    observations.push({
      assetName: domain,
      module: "EMAIL_SECURITY",
      type: "EMAIL_SECURITY",
      identity: "spf-dmarc",
      success: txtResult.ok || dmarcResult.ok,
      data: { spf: spf ?? null, dmarc }
    });
    modules.push({
      module: "EMAIL_SECURITY",
      status: txtResult.ok || dmarcResult.ok ? "COMPLETED" : "FAILED",
      recordCount: Number(Boolean(spf)) + dmarc.length,
      error:
        !txtResult.ok && !dmarcResult.ok ? "SPF and DMARC DNS checks failed" : undefined
    });

    const httpResult: Settled<Awaited<ReturnType<SafeLiveAdapters["safeFetch"]>>> =
      dnsBoundaryBlocked
        ? {
            ok: false,
            error: "HTTPS sampling was suppressed because DNS returned a blocked address."
          }
        : await settle(
            this.adapters.safeFetch(`https://${domain}`, {
              timeoutMs,
              signal: options.signal,
              expectedHostname: domain,
              maxRedirects: 3,
              observeExternalRedirect: true
            }),
            options.signal
          );
    if (httpResult.ok) {
      const { response, finalUrl, redirects, redirectHistory, blockedRedirect } =
        httpResult.value;
      const headers = Object.fromEntries(response.headers.entries());
      services.push({
        assetName: domain,
        port: 443,
        protocol: "https",
        transport: "tcp",
        serviceIdentifier: "root-https",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "HTTPS request",
        evidence: `HTTPS root response returned status ${response.status}.`,
        sourceModule: "HTTP",
        metadata: { status: response.status, finalUrl, redirects, headers }
      });
      observations.push({
        assetName: domain,
        service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
        module: "HTTP",
        type: "HTTP",
        identity: "root-https-response",
        data: {
          status: response.status,
          finalUrl,
          redirects,
          redirectHistory,
          blockedRedirect,
          headers
        }
      });

      if (blockedRedirect) {
        const redirectHost = new URL(blockedRedirect).hostname;
        addAssetOnce(assets, {
          name: redirectHost,
          type: insideRoot(redirectHost, domain) ? "SUBDOMAIN" : "EXTERNAL_DEPENDENCY",
          hostname: redirectHost,
          criticality: "MEDIUM",
          source: "HTTP redirect destination",
          tags: [insideRoot(redirectHost, domain) ? "redirect" : "external"]
        });
        relationships.push({
          from: domain,
          to: redirectHost,
          type: "Redirects to",
          source: "HTTP Location header",
          confidence: "HIGH",
          evidence: `The sampled response advertised redirect destination ${blockedRedirect}. RiskMap did not follow it outside the verified boundary.`,
          state: "OBSERVED"
        });
      }

      if (!response.headers.get("strict-transport-security")) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.hsts.missing",
            "Strict-Transport-Security",
            "HSTS not observed",
            "MEDIUM",
            "Enable HSTS after confirming all required subdomains support HTTPS."
          )
        );
      }
      if (!response.headers.get("content-security-policy")) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.csp.missing",
            "Content-Security-Policy",
            "Content Security Policy not observed",
            "MEDIUM",
            "Develop and test a restrictive policy tailored to the application."
          )
        );
      }
      if (!response.headers.get("x-content-type-options")) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.xcto.missing",
            "X-Content-Type-Options",
            "MIME sniffing protection not observed",
            "LOW",
            "Return X-Content-Type-Options: nosniff where appropriate."
          )
        );
      }
      if (
        !response.headers.get("x-frame-options") &&
        !/frame-ancestors/i.test(response.headers.get("content-security-policy") ?? "")
      ) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.frame-protection.missing",
            "X-Frame-Options or CSP frame-ancestors",
            "Frame-embedding protection not observed",
            "LOW",
            "Set an appropriate CSP frame-ancestors directive or X-Frame-Options policy."
          )
        );
      }
      if (!response.headers.get("referrer-policy")) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.referrer-policy.missing",
            "Referrer-Policy",
            "Referrer Policy not observed",
            "LOW",
            "Define a Referrer-Policy appropriate for application links and analytics."
          )
        );
      }
      if (!response.headers.get("permissions-policy")) {
        findings.push(
          missingHeaderFinding(
            domain,
            "http.permissions-policy.missing",
            "Permissions-Policy",
            "Permissions Policy not observed",
            "LOW",
            "Disable browser capabilities the application does not need."
          )
        );
      }

      const server = response.headers.get("server");
      if (server) {
        const match = server.match(/^([^/\s]+)(?:\/([^\s]+))?/);
        if (match?.[1]) {
          technologies.push({
            assetName: domain,
            service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
            productName: match[1],
            version: match[2],
            confidence: match[2] ? "HIGH" : "MEDIUM",
            evidence: `Server response header: ${server}`,
            source: "HTTP response header"
          });
        }
      }
      modules.push({ module: "HTTP", status: "COMPLETED", recordCount: 1 });
      log.push(`HTTPS root response sampled with status ${response.status}.`);
    } else {
      if (!dnsBoundaryBlocked)
        findings.push({
          assetName: domain,
          ruleId: "https.not-observed",
          module: "HTTP",
          evidenceIdentity: "https-root-unavailable",
          title: "HTTPS service not observed",
          severity: "HIGH",
          category: "Transport security",
          description:
            "RiskMap could not obtain an HTTPS response within the safe scanner limits.",
          evidence: httpResult.error,
          confidence: "MEDIUM",
          remediation:
            "Confirm that HTTPS is publicly available and that DNS, certificate and firewall configuration are correct.",
          technicalDetail:
            "A timeout or network policy can also cause this result. Manual validation is required.",
          businessImpact:
            "Users may be unable to establish an authenticated encrypted connection.",
          references: [],
          externallyReachable: true
        });
      modules.push({
        module: "HTTP",
        status: "FAILED",
        recordCount: 0,
        error: httpResult.error
      });
      log.push("HTTPS sampling failed within the configured safety limits.");
    }

    const plainHttpResult: Settled<Awaited<ReturnType<SafeLiveAdapters["safeFetch"]>>> =
      dnsBoundaryBlocked
        ? {
            ok: false,
            error: "HTTP sampling was suppressed because DNS returned a blocked address."
          }
        : await settle(
            this.adapters.safeFetch(`http://${domain}`, {
              timeoutMs,
              signal: options.signal,
              expectedHostname: domain,
              maxRedirects: 3,
              observeExternalRedirect: true
            }),
            options.signal
          );
    if (plainHttpResult.ok) {
      services.push({
        assetName: domain,
        port: 80,
        protocol: "http",
        transport: "tcp",
        serviceIdentifier: "root-http",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "HTTP request",
        evidence: `HTTP root response returned status ${plainHttpResult.value.response.status}.`,
        sourceModule: "HTTP",
        metadata: {
          status: plainHttpResult.value.response.status,
          finalUrl: plainHttpResult.value.finalUrl
        }
      });
      if (
        !plainHttpResult.value.blockedRedirect &&
        new URL(plainHttpResult.value.finalUrl).protocol !== "https:"
      ) {
        findings.push({
          assetName: domain,
          service: { port: 80, protocol: "http", serviceIdentifier: "root-http" },
          ruleId: "http.https.redirect.missing",
          module: "HTTP",
          evidenceIdentity: "root-http-redirect",
          title: "HTTP did not redirect to HTTPS",
          severity: "MEDIUM",
          category: "Transport security",
          description: "The sampled HTTP request remained on an unencrypted HTTP endpoint.",
          evidence: `Final sampled URL: ${plainHttpResult.value.finalUrl}.`,
          confidence: "HIGH",
          remediation: "Redirect public HTTP requests to the canonical HTTPS service.",
          technicalDetail:
            "RiskMap followed at most three redirects and did not crawl beyond the root request.",
          businessImpact: "Users who begin on HTTP may not receive transport protection.",
          references: [],
          externallyReachable: true
        });
      }
    }

    const tlsResult: Settled<Record<string, unknown>> = dnsBoundaryBlocked
      ? {
          ok: false,
          error: "TLS inspection was suppressed because DNS returned a blocked address."
        }
      : await settle(
          this.adapters.inspectTls(domain, timeoutMs, options.signal),
          options.signal
        );
    if (tlsResult.ok) {
      const tlsObservation = tlsResult.value;
      const serial = String(tlsObservation.serialNumber ?? "unknown");
      const certificateName = `TLS certificate ${domain} ${serial}`;
      addAssetOnce(assets, {
        name: certificateName,
        type: "CERTIFICATE",
        hostname: domain,
        serviceIdentifier: serial,
        criticality: "MEDIUM",
        source: "TLS handshake",
        tags: ["certificate"]
      });
      relationships.push({
        from: domain,
        to: certificateName,
        type: "Uses certificate",
        source: "TLS",
        confidence: "HIGH",
        evidence: `${domain}:443 presented certificate serial ${serial}.`,
        state: "OBSERVED"
      });
      const sans = Array.isArray(tlsObservation.subjectAltNames)
        ? (tlsObservation.subjectAltNames as string[])
        : [];
      for (const san of sans) {
        if (san.startsWith("*.")) continue;
        const normalized = normalizeHostname(san);
        if (!normalized || normalized === normalizeHostname(domain)) continue;
        addAssetOnce(assets, {
          name: normalized,
          type: insideRoot(normalized, domain) ? "SUBDOMAIN" : "EXTERNAL_DEPENDENCY",
          hostname: normalized,
          criticality: "MEDIUM",
          source: "TLS certificate SAN",
          tags: ["certificate-name"]
        });
        relationships.push({
          from: certificateName,
          to: normalized,
          type: "Associated with",
          source: "TLS certificate SAN",
          confidence: "MEDIUM",
          evidence: `${normalized} appeared in the observed certificate subject alternative names.`,
          state: "INFERRED"
        });
      }
      observations.push({
        assetName: domain,
        module: "TLS",
        type: "TLS",
        identity: "root-certificate",
        data: tlsObservation
      });
      modules.push({ module: "TLS", status: "COMPLETED", recordCount: 1 });

      if (tlsObservation.hostnameValid === false) {
        findings.push({
          assetName: domain,
          service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
          ruleId: "tls.hostname-mismatch",
          module: "TLS",
          evidenceIdentity: `certificate:${serial}:hostname`,
          title: "TLS certificate hostname mismatch observed",
          severity: "HIGH",
          category: "TLS certificate",
          description:
            "The certificate presented during the sampled TLS handshake did not match the verified hostname.",
          evidence: `Certificate serial ${serial}; ${String(tlsObservation.authorizationError ?? "hostname validation failed")}.`,
          confidence: "HIGH",
          remediation:
            "Deploy a certificate whose subject alternative names include the intended hostname.",
          technicalDetail:
            "RiskMap used the verified hostname for SNI and performed hostname identity validation.",
          businessImpact:
            "Hostname mismatch warnings can interrupt access and weaken user trust.",
          references: [],
          externallyReachable: true
        });
      }
      const daysRemaining =
        typeof tlsObservation.daysRemaining === "number"
          ? tlsObservation.daysRemaining
          : null;
      if (daysRemaining !== null && daysRemaining < 0) {
        findings.push({
          assetName: domain,
          service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
          ruleId: "tls.certificate.expired",
          module: "TLS",
          evidenceIdentity: `certificate:${serial}:expired`,
          title: "TLS certificate appears expired",
          severity: "HIGH",
          category: "TLS certificate",
          description: "The observed certificate validity end date is in the past.",
          evidence: `Certificate valid-to: ${String(tlsObservation.validTo ?? "unknown")}.`,
          confidence: "HIGH",
          remediation:
            "Renew and deploy a valid certificate, then verify the served chain.",
          technicalDetail:
            "RiskMap completed a TLS handshake without sending application payloads.",
          businessImpact:
            "Expired certificates can interrupt access and train users to ignore warnings.",
          references: [],
          externallyReachable: true
        });
      } else if (daysRemaining !== null && daysRemaining <= 30) {
        findings.push({
          assetName: domain,
          service: { port: 443, protocol: "https", serviceIdentifier: "root-https" },
          ruleId: "tls.certificate.expiring",
          module: "TLS",
          evidenceIdentity: `certificate:${serial}:expiring`,
          title: "TLS certificate expires soon",
          severity: "MEDIUM",
          category: "TLS certificate",
          description: "The observed certificate is approaching its validity end date.",
          evidence: `${daysRemaining} day(s) remaining.`,
          confidence: "HIGH",
          remediation: "Renew the certificate and confirm automated renewal monitoring.",
          technicalDetail:
            "Expiration is calculated from the certificate presented during this scan.",
          businessImpact:
            "Missed renewal can cause an avoidable outage and trust warnings.",
          references: [],
          externallyReachable: true
        });
      }
    } else {
      modules.push({
        module: "TLS",
        status: "FAILED",
        recordCount: 0,
        error: tlsResult.error
      });
    }

    const openPorts: Array<{ port: number; reachable: boolean }> = [];
    if (options.activeChecks && !dnsBoundaryBlocked) {
      for (const port of allowedPorts.slice(0, 20)) {
        const reachable = await this.adapters.tcpConnect(
          domain,
          port,
          Math.min(timeoutMs, 1800),
          options.signal
        );
        openPorts.push({ port, reachable });
        if (!reachable) continue;
        const protocol =
          port === 443
            ? "https"
            : port === 80
              ? "http"
              : port === 22
                ? "ssh"
                : port === 3389
                  ? "rdp"
                  : "tcp";
        services.push({
          assetName: domain,
          port,
          protocol,
          transport: "tcp",
          serviceIdentifier: `port-${port}`,
          observedState: "OPEN",
          confidence: "HIGH",
          evidenceSource: "Safe TCP connect",
          evidence: `TCP connect succeeded to ${domain}:${port}.`,
          sourceModule: "PORT_CHECKS",
          metadata: { method: "tcp-connect-only" }
        });
        if ([3306, 5432, 6379, 9200, 27017].includes(port)) {
          findings.push({
            assetName: domain,
            service: { port, protocol, serviceIdentifier: `port-${port}` },
            ruleId: "network.database.public",
            module: "PORT_CHECKS",
            evidenceIdentity: `tcp:${port}`,
            title: `Public database or data-service port observed (${port})`,
            severity: "HIGH",
            category: "Network exposure",
            description:
              "A TCP handshake succeeded on a commonly used data-service port. RiskMap did not authenticate or determine the software version.",
            evidence: `TCP connect succeeded to ${domain}:${port}.`,
            confidence: "HIGH",
            remediation:
              "Restrict the service to required private networks or trusted source ranges.",
            technicalDetail:
              "This is transport reachability only and requires owner validation.",
            businessImpact:
              "Public data services can increase exposure to scanning and configuration mistakes.",
            references: [],
            externallyReachable: true
          });
        } else if ([22, 3389, 8443].includes(port)) {
          findings.push({
            assetName: domain,
            service: { port, protocol, serviceIdentifier: `port-${port}` },
            ruleId: "network.admin.public",
            module: "PORT_CHECKS",
            evidenceIdentity: `tcp:${port}`,
            title: `Public remote administration port observed (${port})`,
            severity: "MEDIUM",
            category: "Network exposure",
            description:
              "A TCP handshake succeeded on a port commonly associated with remote administration. This is not proof of vulnerability.",
            evidence: `TCP connect succeeded to ${domain}:${port}.`,
            confidence: "HIGH",
            remediation:
              "Confirm business need, restrict source access and require strong authentication.",
            technicalDetail:
              "No authentication, banner exploitation or payload delivery was attempted.",
            businessImpact:
              "Public administration endpoints attract unauthorised access attempts.",
            references: [],
            externallyReachable: true
          });
        }
      }
      modules.push({
        module: "PORT_CHECKS",
        status: "COMPLETED",
        recordCount: openPorts.length
      });
      log.push(`Completed ${openPorts.length} allowlisted TCP-connect-only checks.`);
    } else {
      modules.push({ module: "PORT_CHECKS", status: "SKIPPED", recordCount: 0 });
      log.push(
        dnsBoundaryBlocked
          ? "TCP-connect checks were suppressed because DNS returned a blocked address."
          : "TCP-connect checks were skipped because passive checks are configured."
      );
    }
    observations.push({
      assetName: domain,
      module: "PORT_CHECKS",
      type: "PORTS",
      identity: "allowlisted-port-set",
      success: options.activeChecks,
      data: { ports: openPorts, method: "tcp-connect-only" }
    });

    const securityTxt: Settled<Awaited<ReturnType<SafeLiveAdapters["safeFetch"]>>> =
      dnsBoundaryBlocked
        ? {
            ok: false,
            error:
              "security.txt sampling was suppressed because DNS returned a blocked address."
          }
        : await settle(
            this.adapters.safeFetch(`https://${domain}/.well-known/security.txt`, {
              timeoutMs,
              signal: options.signal,
              expectedHostname: domain,
              maxRedirects: 2
            }),
            options.signal
          );
    observations.push({
      assetName: domain,
      module: "HTTP",
      type: "SECURITY_TXT",
      identity: "security-txt",
      success: securityTxt.ok,
      data: {
        present: securityTxt.ok && securityTxt.value.response.ok,
        status: securityTxt.ok ? securityTxt.value.response.status : null
      }
    });

    modules.push({
      module: "TECHNOLOGY",
      status: httpResult.ok ? "COMPLETED" : "SKIPPED",
      recordCount: technologies.length
    });
    modules.push({
      module: "GRAPH",
      status: "COMPLETED",
      recordCount: relationships.length
    });

    return {
      provider: this.name,
      assets,
      services,
      technologies,
      findings,
      relationships,
      observations,
      modules,
      log
    };
  }
}
