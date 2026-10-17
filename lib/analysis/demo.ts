import type { Dataset } from "@/lib/analysis/dataset";

export const demoDataset: Dataset = {
  version: 1,
  name: "Northstar Labs · fictional demo",
  assets: [
    {
      id: "web-01",
      name: "WEB-01",
      type: "WEB_APPLICATION",
      criticality: "HIGH",
      public: true,
      evidence: "Fictional inventory: public web server at 192.0.2.10."
    },
    {
      id: "api-01",
      name: "API-01",
      type: "API_ENDPOINT",
      criticality: "HIGH",
      public: true,
      evidence: "Fictional inventory: public API at 192.0.2.20."
    },
    {
      id: "svc-deploy",
      name: "SVC-DEPLOY",
      type: "IDENTITY",
      criticality: "HIGH",
      public: false,
      evidence: "Fictional service account used by the web deployment pipeline."
    },
    {
      id: "db-01",
      name: "DB-01",
      type: "CRITICAL_ASSET",
      criticality: "CRITICAL",
      public: false,
      evidence: "Fictional internal database containing customer records."
    },
    {
      id: "backup-01",
      name: "BACKUP-01",
      type: "CRITICAL_ASSET",
      criticality: "CRITICAL",
      public: false,
      evidence: "Fictional internal backup repository containing database snapshots."
    },
    {
      id: "docs-01",
      name: "DOCS-01",
      type: "WEB_APPLICATION",
      criticality: "LOW",
      public: true,
      evidence: "Fictional public documentation site at 192.0.2.30."
    }
  ],
  services: [
    {
      id: "web-ssh",
      assetId: "web-01",
      port: 22,
      protocol: "ssh",
      confidence: "HIGH",
      evidence: "Fictional firewall review: TCP/22 accepts connections from 0.0.0.0/0."
    },
    {
      id: "web-https",
      assetId: "web-01",
      port: 443,
      protocol: "https",
      confidence: "HIGH",
      evidence: "Fictional public HTTPS listener."
    },
    {
      id: "api-https",
      assetId: "api-01",
      port: 443,
      protocol: "https-api",
      confidence: "HIGH",
      evidence: "Fictional public API listener."
    },
    {
      id: "db-postgres",
      assetId: "db-01",
      port: 5432,
      protocol: "postgresql",
      confidence: "HIGH",
      evidence: "Fictional private PostgreSQL listener; no direct Internet ingress."
    },
    {
      id: "docs-https",
      assetId: "docs-01",
      port: 443,
      protocol: "https",
      confidence: "HIGH",
      evidence: "Fictional documentation HTTPS listener."
    }
  ],
  findings: [
    {
      id: "public-ssh",
      assetId: "web-01",
      serviceId: "web-ssh",
      title: "Public SSH administration on WEB-01",
      severity: "HIGH",
      confidence: "HIGH",
      category: "Administrative exposure",
      description:
        "An administrative service accepts Internet connections. Access controls still require validation; no credential guessing or exploitation was performed.",
      evidence:
        "Fictional firewall rule WEB-SSH-01 permits TCP/22 from any source. WEB-01 uses SVC-DEPLOY.",
      remediation:
        "Restrict SSH on WEB-01 to the management network or an authenticated bastion."
    },
    {
      id: "deploy-privilege",
      assetId: "svc-deploy",
      title: "Excessive privileges on SVC-DEPLOY",
      severity: "HIGH",
      confidence: "HIGH",
      category: "Identity access control",
      description:
        "The deployment account can read customer records and backups beyond its deployment duties.",
      evidence:
        "Fictional access review grants SVC-DEPLOY read access to DB-01 and BACKUP-01.",
      remediation: "Remove customer-data and backup read permissions from SVC-DEPLOY."
    },
    {
      id: "api-access",
      assetId: "api-01",
      serviceId: "api-https",
      title: "API object access controls require validation",
      severity: "MEDIUM",
      confidence: "MEDIUM",
      category: "API access control",
      description:
        "The supplied review identifies an unvalidated object authorisation boundary. Exploitability has not been demonstrated.",
      evidence:
        "Fictional API review API-AC-02 flags the customer-records handler. API-01 connects to DB-01.",
      remediation:
        "Validate and enforce per-object authorisation on API-01 before returning customer records."
    },
    {
      id: "docs-header",
      assetId: "docs-01",
      serviceId: "docs-https",
      title: "Missing content security policy on DOCS-01",
      severity: "LOW",
      confidence: "HIGH",
      category: "HTTP headers",
      description:
        "The response does not include a content security policy. This alone does not demonstrate a script injection vulnerability.",
      evidence:
        "Fictional response-header review contains no Content-Security-Policy header.",
      remediation: "Add a tested content security policy to DOCS-01."
    }
  ],
  relationships: [
    {
      id: "web-deploy",
      from: "web-01",
      to: "svc-deploy",
      type: "Uses identity",
      state: "INFERRED",
      confidence: "MEDIUM",
      viaFindingId: "public-ssh",
      evidence:
        "Fictional deployment configuration associates WEB-01 with SVC-DEPLOY. SSH access could expose this context; validate the boundary."
    },
    {
      id: "deploy-db",
      from: "svc-deploy",
      to: "db-01",
      type: "Can access",
      state: "OBSERVED",
      confidence: "HIGH",
      viaFindingId: "deploy-privilege",
      evidence:
        "Fictional policy grants SVC-DEPLOY customer-record read permissions on DB-01."
    },
    {
      id: "deploy-backup",
      from: "svc-deploy",
      to: "backup-01",
      type: "Can access",
      state: "OBSERVED",
      confidence: "HIGH",
      viaFindingId: "deploy-privilege",
      evidence: "Fictional policy grants SVC-DEPLOY read permissions on BACKUP-01."
    },
    {
      id: "api-db",
      from: "api-01",
      to: "db-01",
      type: "Connects to",
      state: "INFERRED",
      confidence: "MEDIUM",
      viaFindingId: "api-access",
      evidence:
        "Fictional application inventory maps the API to DB-01; the authorisation boundary is unvalidated."
    }
  ]
};
