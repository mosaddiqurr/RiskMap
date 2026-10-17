export type ScanModuleName =
  | "PASSIVE_DISCOVERY"
  | "DNS"
  | "HTTP"
  | "TLS"
  | "EMAIL_SECURITY"
  | "PORT_CHECKS"
  | "TECHNOLOGY"
  | "GRAPH";

export type ScanModuleResultInput = {
  module: ScanModuleName;
  status: "COMPLETED" | "PARTIAL" | "FAILED" | "SKIPPED";
  recordCount?: number;
  error?: string;
};

export type ScanAssetInput = {
  name: string;
  type: string;
  hostname?: string;
  ipAddress?: string;
  port?: number;
  protocol?: string;
  serviceIdentifier?: string;
  criticality: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  source: string;
  tags: string[];
};

export type ScanServiceInput = {
  assetName: string;
  port: number;
  protocol: string;
  transport: "tcp" | "udp";
  serviceIdentifier?: string;
  observedState: "OPEN" | "CLOSED" | "UNKNOWN";
  confidence: "LOW" | "MEDIUM" | "HIGH";
  evidenceSource: string;
  evidence: string;
  sourceModule: ScanModuleName;
  metadata?: Record<string, unknown>;
};

export type ScanTechnologyInput = {
  assetName: string;
  service?: {
    port: number;
    protocol: string;
    transport?: "tcp" | "udp";
    serviceIdentifier?: string;
  };
  productName: string;
  version?: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  evidence: string;
  source: string;
};

export type ScanFindingInput = {
  assetName: string;
  service?: {
    port: number;
    protocol: string;
    transport?: "tcp" | "udp";
    serviceIdentifier?: string;
  };
  ruleId: string;
  module: ScanModuleName;
  evidenceIdentity?: string;
  title: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  category: string;
  description: string;
  evidence: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  remediation: string;
  technicalDetail: string;
  businessImpact: string;
  references: string[];
  externallyReachable: boolean;
};

export type ScanRelationshipInput = {
  from: string;
  to: string;
  type: string;
  source: string;
  confidence: "LOW" | "MEDIUM" | "HIGH";
  evidence: string;
  state: "OBSERVED" | "INFERRED";
};

export type ScanObservationInput = {
  assetName?: string;
  service?: {
    port: number;
    protocol: string;
    transport?: "tcp" | "udp";
    serviceIdentifier?: string;
  };
  module: ScanModuleName;
  type: string;
  identity?: string;
  success?: boolean;
  data: Record<string, unknown>;
};

export type ScanProviderResult = {
  provider: string;
  assets: ScanAssetInput[];
  services: ScanServiceInput[];
  technologies: ScanTechnologyInput[];
  findings: ScanFindingInput[];
  relationships: ScanRelationshipInput[];
  observations: ScanObservationInput[];
  modules: ScanModuleResultInput[];
  log: string[];
};

export type ScanProviderOptions = {
  activeChecks: boolean;
  scanSequence?: number;
  signal?: AbortSignal;
};

export interface ScanProvider {
  name: string;
  scan(domain: string, options?: ScanProviderOptions): Promise<ScanProviderResult>;
}
