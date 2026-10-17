import { createHash } from "node:crypto";
import type {
  ScanAssetInput,
  ScanFindingInput,
  ScanProvider,
  ScanProviderOptions,
  ScanProviderResult,
  ScanObservationInput,
  ScanRelationshipInput,
  ScanServiceInput,
  ScanTechnologyInput
} from "@/lib/scanning/types";

function deterministicOctet(domain: string) {
  const digest = createHash("sha256").update(domain).digest();
  return 20 + ((digest[0] ?? 1) % 160);
}

function phaseFor(sequence?: number) {
  if (!sequence || sequence < 1) return 1;
  return Math.min(sequence, 4);
}

function finding(input: ScanFindingInput) {
  return input;
}

export class MockScanProvider implements ScanProvider {
  name = "demo-provider";

  async scan(
    domain: string,
    options: ScanProviderOptions = { activeChecks: true, scanSequence: 1 }
  ): Promise<ScanProviderResult> {
    const phase = phaseFor(options.scanSequence);
    const octet = deterministicOctet(domain);
    const root = domain;
    const app = `app.${domain}`;
    const admin = `admin.${domain}`;
    const api = `api.${domain}`;
    const mail = `mail.${domain}`;
    const legacy = `legacy.${domain}`;
    const mailProvider = `relay.partner-${octet}.test`;
    const certificateName =
      phase >= 3
        ? `TLS certificate ${domain} serial B2`
        : `TLS certificate ${domain} serial A1`;

    const assets: ScanAssetInput[] = [
      {
        name: root,
        type: "ROOT_DOMAIN",
        hostname: root,
        criticality: "HIGH",
        source: "Verified root domain",
        tags: ["production", "fictional-demo"]
      },
      {
        name: app,
        type: "WEB_APPLICATION",
        hostname: app,
        ipAddress: `203.0.113.${octet}`,
        criticality: "HIGH",
        source: "DNS A record",
        tags: ["customer-facing"]
      },
      {
        name: admin,
        type: "CRITICAL_ASSET",
        hostname: admin,
        ipAddress: `203.0.113.${octet + 1}`,
        criticality: "CRITICAL",
        source: "User-confirmed critical asset",
        tags: ["administration", "critical"]
      },
      {
        name: mail,
        type: "EMAIL_SERVICE",
        hostname: mail,
        ipAddress: `203.0.113.${octet + 3}`,
        criticality: "HIGH",
        source: "MX record",
        tags: ["mail"]
      },
      {
        name: mailProvider,
        type: "EXTERNAL_DEPENDENCY",
        hostname: mailProvider,
        criticality: "MEDIUM",
        source: "MX relationship",
        tags: ["third-party", "mail"]
      },
      {
        name: certificateName,
        type: "CERTIFICATE",
        hostname: app,
        serviceIdentifier: phase >= 3 ? "serial-b2" : "serial-a1",
        criticality: "MEDIUM",
        source: "TLS handshake",
        tags: ["certificate"]
      }
    ];

    if (phase === 1 || phase === 4) {
      assets.push({
        name: legacy,
        type: "SUBDOMAIN",
        hostname: legacy,
        ipAddress: `203.0.113.${octet + 4}`,
        criticality: "LOW",
        source: "DNS A record",
        tags: ["legacy"]
      });
    }

    if (phase >= 2) {
      assets.push({
        name: api,
        type: "API_ENDPOINT",
        hostname: api,
        ipAddress: `203.0.113.${octet + 2}`,
        criticality: "CRITICAL",
        source: "TLS certificate SAN and DNS",
        tags: ["api", "customer-data"]
      });
    }

    const services: ScanServiceInput[] = [
      {
        assetName: app,
        port: 443,
        protocol: "https",
        transport: "tcp",
        serviceIdentifier: "public-web",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "HTTPS request",
        evidence: `HTTPS response observed from ${app}:443.`,
        sourceModule: "HTTP",
        metadata: {
          status: 200,
          server: phase >= 3 ? "nginx/1.26.1" : "nginx/1.24.0",
          hsts: true,
          csp: phase === 3
        }
      },
      {
        assetName: mail,
        port: 25,
        protocol: "smtp",
        transport: "tcp",
        serviceIdentifier: "mail-transfer",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "MX and TCP metadata",
        evidence: `The MX target ${mail} was associated with TCP port 25 in the fictional fixture.`,
        sourceModule: "PASSIVE_DISCOVERY",
        metadata: { provider: mailProvider }
      }
    ];

    if (phase === 1 || phase === 4) {
      services.push({
        assetName: legacy,
        port: 80,
        protocol: "http",
        transport: "tcp",
        serviceIdentifier: "legacy-web",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "HTTP request",
        evidence: `HTTP response observed from ${legacy}:80.`,
        sourceModule: "HTTP",
        metadata: { status: 200, redirectToHttps: false }
      });
    }

    if (phase === 2 && options.activeChecks) {
      services.push({
        assetName: admin,
        port: 8443,
        protocol: "https-admin",
        transport: "tcp",
        serviceIdentifier: "administration-console",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "Safe TCP connect",
        evidence: `TCP connection succeeded to ${admin}:8443. No authentication was attempted.`,
        sourceModule: "PORT_CHECKS",
        metadata: { method: "tcp-connect-only", administrative: true }
      });
    }

    if (phase >= 2) {
      services.push({
        assetName: api,
        port: 443,
        protocol: "https",
        transport: "tcp",
        serviceIdentifier: "public-api",
        observedState: "OPEN",
        confidence: "HIGH",
        evidenceSource: "HTTPS request",
        evidence: `HTTPS response observed from ${api}:443.`,
        sourceModule: "HTTP",
        metadata: { status: 200, contentType: "application/json" }
      });
    }

    const technologies: ScanTechnologyInput[] = [
      {
        assetName: app,
        service: { port: 443, protocol: "https", serviceIdentifier: "public-web" },
        productName: "nginx",
        version: phase >= 3 ? "1.26.1" : "1.24.0",
        confidence: "HIGH",
        evidence: `Fictional Server header: nginx/${phase >= 3 ? "1.26.1" : "1.24.0"}`,
        source: "HTTP response header"
      }
    ];

    if (phase >= 2) {
      technologies.push({
        assetName: api,
        service: { port: 443, protocol: "https", serviceIdentifier: "public-api" },
        productName: "Northstar API Gateway",
        version: "4.2.0-demo",
        confidence: "MEDIUM",
        evidence: "Fictional x-gateway-version response metadata.",
        source: "HTTP response header"
      });
    }

    const findings: ScanFindingInput[] = [];
    if (phase !== 3) {
      findings.push(
        finding({
          assetName: app,
          service: { port: 443, protocol: "https", serviceIdentifier: "public-web" },
          ruleId: "http.csp.missing",
          module: "HTTP",
          evidenceIdentity: "root-response:csp",
          title: "Content Security Policy not observed",
          severity: "MEDIUM",
          category: "HTTP security headers",
          description:
            "The sampled HTTPS response did not include a Content-Security-Policy header. This does not mean the application is compromised.",
          evidence:
            "Content-Security-Policy was absent from the fictional root HTTPS response.",
          confidence: "HIGH",
          remediation:
            "Define and test a restrictive Content Security Policy that matches the application’s required resources.",
          technicalDetail:
            "Header presence was checked on the root response only. Other routes may differ.",
          businessImpact:
            "A well-designed policy can reduce the impact of certain content-injection weaknesses.",
          references: ["OWASP Content Security Policy Cheat Sheet"],
          externallyReachable: true
        })
      );
    }

    if (phase <= 2) {
      findings.push(
        finding({
          assetName: app,
          service: { port: 443, protocol: "https", serviceIdentifier: "public-web" },
          ruleId: "tls.certificate.expiring",
          module: "TLS",
          evidenceIdentity: "certificate:serial-a1",
          title: "TLS certificate expires soon",
          severity: "MEDIUM",
          category: "TLS certificate",
          description: "The fictional certificate is approaching its validity end date.",
          evidence: "Certificate serial A1 had 18 fictional days remaining.",
          confidence: "HIGH",
          remediation: "Renew the certificate and verify automated expiry monitoring.",
          technicalDetail:
            "No vulnerability or exploitation claim is made from expiry metadata.",
          businessImpact:
            "Missed renewal can cause an avoidable service outage and trust warnings.",
          references: [],
          externallyReachable: true
        })
      );
    }

    if (phase === 1) {
      findings.push(
        finding({
          assetName: legacy,
          service: { port: 80, protocol: "http", serviceIdentifier: "legacy-web" },
          ruleId: "http.https.redirect.missing",
          module: "HTTP",
          evidenceIdentity: "legacy-root-redirect",
          title: "Legacy HTTP service did not redirect to HTTPS",
          severity: "MEDIUM",
          category: "Transport security",
          description:
            "The fictional legacy service returned HTTP without redirecting to HTTPS.",
          evidence: `The root response from ${legacy}:80 remained on HTTP.`,
          confidence: "HIGH",
          remediation:
            "Retire the service or redirect traffic to an approved HTTPS endpoint.",
          technicalDetail: "Only the fictional root response was sampled.",
          businessImpact: "Users may access an unencrypted legacy endpoint.",
          references: [],
          externallyReachable: true
        })
      );
    }

    if (phase === 2 && options.activeChecks) {
      findings.push(
        finding({
          assetName: admin,
          service: {
            port: 8443,
            protocol: "https-admin",
            serviceIdentifier: "administration-console"
          },
          ruleId: "network.admin.public",
          module: "PORT_CHECKS",
          evidenceIdentity: "tcp:8443",
          title: "Public administration service observed",
          severity: "HIGH",
          category: "Network exposure",
          description:
            "A remotely reachable administration interface was observed on an internet-facing host. This requires validation and is not proof of exploitability.",
          evidence: `TCP connection succeeded to ${admin}:8443 during an authorised fictional safe check.`,
          confidence: "HIGH",
          remediation:
            "Restrict the interface to a trusted network or identity-aware access proxy and require strong authentication.",
          technicalDetail:
            "The scanner completed a TCP handshake only and did not authenticate or send a payload.",
          businessImpact:
            "Public management interfaces can increase exposure to unauthorised access attempts.",
          references: [
            "CIS Controls v8: Secure Configuration of Enterprise Assets and Software"
          ],
          externallyReachable: true
        })
      );
    }

    if (phase >= 2) {
      findings.push(
        finding({
          assetName: api,
          service: { port: 443, protocol: "https", serviceIdentifier: "public-api" },
          ruleId: "api.access-control.validation-required",
          module: "HTTP",
          evidenceIdentity: "public-api-root-metadata",
          title: "Public API access-control validation required",
          severity: "MEDIUM",
          category: "API exposure",
          description:
            "A public API endpoint was observed, but passive metadata cannot confirm whether every operation has appropriate access control.",
          evidence: `The fictional ${api} endpoint returned application/json metadata without an authentication challenge on the sampled root route.`,
          confidence: "MEDIUM",
          remediation:
            "Review endpoint-level authentication and authorisation tests in the application’s own security programme.",
          technicalDetail:
            "RiskMap did not attempt authentication bypass or call privileged operations.",
          businessImpact:
            "Incorrectly protected API operations could expose sensitive business functions or data.",
          references: ["OWASP API Security Top 10"],
          externallyReachable: true
        })
      );
    }

    if (phase === 4) {
      findings.push(
        finding({
          assetName: root,
          ruleId: "email.dmarc.monitoring-only",
          module: "EMAIL_SECURITY",
          evidenceIdentity: "dmarc:p=none",
          title: "DMARC policy is monitoring only",
          severity: "LOW",
          category: "Email authentication",
          description:
            "A fictional DMARC record was observed with a monitoring-only policy.",
          evidence: `_dmarc.${domain} TXT: v=DMARC1; p=none; rua=mailto:dmarc@${domain}`,
          confidence: "HIGH",
          remediation:
            "Review legitimate mail sources, then move gradually toward quarantine or reject when reporting confirms readiness.",
          technicalDetail:
            "RiskMap evaluates policy text only and does not assess every third-party sender.",
          businessImpact:
            "A monitoring-only policy provides limited protection against direct domain spoofing.",
          references: ["RFC 7489"],
          externallyReachable: true
        })
      );
    }

    const relationships: ScanRelationshipInput[] = [
      {
        from: root,
        to: app,
        type: "Associated with",
        source: "DNS",
        confidence: "HIGH",
        evidence: `${app} is inside the verified root domain and has an observed A record.`,
        state: "OBSERVED"
      },
      {
        from: root,
        to: admin,
        type: "Protects",
        source: "User criticality classification",
        confidence: "HIGH",
        evidence: `${admin} is marked as a critical administration asset.`,
        state: "OBSERVED"
      },
      {
        from: root,
        to: mail,
        type: "Uses mail provider",
        source: "MX",
        confidence: "HIGH",
        evidence: `MX data associates ${root} with ${mail}.`,
        state: "OBSERVED"
      },
      {
        from: mail,
        to: mailProvider,
        type: "Depends on",
        source: "MX provider relationship",
        confidence: "MEDIUM",
        evidence: `${mail} uses the fictional external relay ${mailProvider}.`,
        state: "INFERRED"
      },
      {
        from: app,
        to: certificateName,
        type: "Uses certificate",
        source: "TLS",
        confidence: "HIGH",
        evidence: `${app} presented ${certificateName}.`,
        state: "OBSERVED"
      },
      {
        from: app,
        to: admin,
        type: "Could reach",
        source: "Fictional architecture inventory",
        confidence: "MEDIUM",
        evidence:
          "The customer-facing application is associated with the critical administration boundary.",
        state: "INFERRED"
      }
    ];

    if (phase === 1 || phase === 4) {
      relationships.push({
        from: root,
        to: legacy,
        type: "Associated with",
        source: "DNS",
        confidence: "HIGH",
        evidence: `${legacy} had an observed A record.`,
        state: "OBSERVED"
      });
    }

    if (phase >= 2) {
      relationships.push(
        {
          from: root,
          to: api,
          type: "Associated with",
          source: "DNS and certificate SAN",
          confidence: "HIGH",
          evidence: `${api} was observed in DNS and certificate-name evidence.`,
          state: "OBSERVED"
        },
        {
          from: api,
          to: admin,
          type: "Depends on",
          source: "Fictional application inventory",
          confidence: "MEDIUM",
          evidence: "The public API depends on a critical administration capability.",
          state: "INFERRED"
        }
      );
    }

    const dmarc =
      phase === 4
        ? `v=DMARC1; p=none; rua=mailto:dmarc@${domain}`
        : "v=DMARC1; p=quarantine";
    const observations: ScanObservationInput[] = [
      {
        assetName: root,
        module: "DNS" as const,
        type: "DNS",
        identity: "root-dns-set",
        data: {
          A: [`203.0.113.${octet}`],
          AAAA: [],
          CNAME: [],
          MX: [mail],
          NS: [`ns1.${domain}`, `ns2.${domain}`],
          TXT: [`v=spf1 include:${mailProvider} -all`],
          DMARC: [dmarc],
          discoveredNames:
            phase === 1
              ? [app, admin, mail, legacy]
              : phase === 2
                ? [app, admin, api, mail, legacy]
                : [app, admin, api, mail]
        }
      },
      {
        assetName: app,
        service: { port: 443, protocol: "https", serviceIdentifier: "public-web" },
        module: "HTTP" as const,
        type: "HTTP",
        identity: "app-root-http",
        data: {
          status: 200,
          finalUrl: `https://${app}/`,
          headers: {
            server: phase >= 3 ? "nginx/1.26.1" : "nginx/1.24.0",
            hsts: true,
            csp: phase === 3,
            xContentTypeOptions: true
          }
        }
      },
      {
        assetName: app,
        module: "TLS" as const,
        type: "TLS",
        identity: "app-certificate",
        data: {
          serialNumber: phase >= 3 ? "B2" : "A1",
          valid: true,
          daysRemaining: phase >= 3 ? 280 : 18,
          issuer: "Fictional Demo CA",
          subjectAltNames: [app, ...(phase >= 2 ? [api] : [])]
        }
      },
      {
        assetName: root,
        module: "EMAIL_SECURITY" as const,
        type: "EMAIL_SECURITY",
        identity: "spf-dmarc",
        data: { spf: `v=spf1 include:${mailProvider} -all`, dmarc }
      }
    ];

    if (phase === 2 && options.activeChecks) {
      observations.push({
        assetName: admin,
        service: {
          port: 8443,
          protocol: "https-admin",
          serviceIdentifier: "administration-console"
        },
        module: "PORT_CHECKS",
        type: "PORT",
        identity: "tcp-8443",
        data: { port: 8443, reachable: true, method: "tcp-connect-only" }
      });
    }

    const modules = [
      {
        module: "PASSIVE_DISCOVERY" as const,
        status: "COMPLETED" as const,
        recordCount: assets.length
      },
      { module: "DNS" as const, status: "COMPLETED" as const, recordCount: 6 },
      {
        module: "HTTP" as const,
        status: "COMPLETED" as const,
        recordCount: services.filter((service) => service.sourceModule === "HTTP").length
      },
      { module: "TLS" as const, status: "COMPLETED" as const, recordCount: 1 },
      { module: "EMAIL_SECURITY" as const, status: "COMPLETED" as const, recordCount: 2 },
      {
        module: "PORT_CHECKS" as const,
        status: options.activeChecks ? ("COMPLETED" as const) : ("SKIPPED" as const),
        recordCount: options.activeChecks
          ? services.filter((service) => service.sourceModule === "PORT_CHECKS").length
          : 0
      },
      {
        module: "TECHNOLOGY" as const,
        status: "COMPLETED" as const,
        recordCount: technologies.length
      },
      {
        module: "GRAPH" as const,
        status: "COMPLETED" as const,
        recordCount: relationships.length
      }
    ];

    return {
      provider: this.name,
      assets,
      services,
      technologies,
      findings,
      relationships,
      observations,
      modules,
      log: [
        "Authorisation and verification checks passed.",
        `Loaded deterministic fictional snapshot ${phase} of 4.`,
        "Passive DNS, TLS name and redirect relationships were normalised.",
        options.activeChecks
          ? "Allowed TCP-connect-only fixture evidence was included without authentication or exploitation."
          : "Active TCP checks were skipped because the domain is configured for passive checks only.",
        "Observed evidence and inferred relationships remain separately labelled."
      ]
    };
  }
}
