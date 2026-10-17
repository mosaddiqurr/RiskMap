import { z } from "zod";

export const INPUT_LIMIT_BYTES = 1_048_576;
export const INPUT_LIMITS = {
  assets: 100,
  services: 200,
  findings: 200,
  relationships: 300
} as const;
const id = z
  .string()
  .min(1)
  .max(64)
  .regex(
    /^[A-Za-z0-9][A-Za-z0-9_.-]*$/,
    "Use letters, numbers, dots, underscores or hyphens for IDs."
  );
const text = (max: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(max)
    .refine(
      // eslint-disable-next-line no-control-regex -- Reject unsafe controls in untrusted evidence.
      (value) => !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value),
      "Control characters are not allowed."
    );
const confidence = z.enum(["HIGH", "MEDIUM", "LOW"]);
const severity = z.enum(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]);
export const assetInput = z
  .object({
    id,
    name: text(100),
    type: z.enum([
      "WEB_APPLICATION",
      "API_ENDPOINT",
      "IP_ADDRESS",
      "ROOT_DOMAIN",
      "SUBDOMAIN",
      "EMAIL_SERVICE",
      "CRITICAL_ASSET",
      "IDENTITY",
      "EXTERNAL_DEPENDENCY"
    ]),
    criticality: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]),
    public: z.boolean(),
    evidence: text(2000)
  })
  .strict();
export const serviceInput = z
  .object({
    id,
    assetId: id,
    port: z.number().int().min(1).max(65535),
    protocol: text(40),
    confidence,
    evidence: text(2000)
  })
  .strict();
export const findingInput = z
  .object({
    id,
    assetId: id,
    serviceId: id.optional(),
    title: text(200),
    severity,
    confidence,
    category: text(100),
    description: text(3000),
    evidence: text(3000),
    remediation: text(2000),
    cve: z
      .string()
      .regex(/^CVE-\d{4}-\d{4,}$/)
      .max(32)
      .optional(),
    firstSeen: z.string().datetime({ offset: true }).optional()
  })
  .strict();
export const relationshipInput = z
  .object({
    id,
    from: id,
    to: id,
    type: z.enum([
      "Could reach",
      "Depends on",
      "Uses identity",
      "Can access",
      "Connects to",
      "Uses mail provider"
    ]),
    state: z.enum(["OBSERVED", "INFERRED"]),
    confidence,
    evidence: text(2000),
    viaFindingId: id.optional()
  })
  .strict();
export const datasetSchema = z
  .object({
    version: z.literal(1),
    name: text(100),
    assets: z.array(assetInput).min(1).max(INPUT_LIMITS.assets),
    services: z.array(serviceInput).max(INPUT_LIMITS.services),
    findings: z.array(findingInput).max(INPUT_LIMITS.findings),
    relationships: z.array(relationshipInput).max(INPUT_LIMITS.relationships)
  })
  .strict()
  .superRefine((data, ctx) => {
    for (const collection of ["assets", "services", "findings", "relationships"] as const) {
      const seen = new Set<string>();
      data[collection].forEach((record, index) => {
        if (seen.has(record.id))
          ctx.addIssue({
            code: "custom",
            path: [collection, index, "id"],
            message: "IDs must be unique within each collection."
          });
        seen.add(record.id);
      });
    }
    const assets = new Map(data.assets.map((a) => [a.id, a]));
    const services = new Map(data.services.map((s) => [s.id, s]));
    const findings = new Map(data.findings.map((f) => [f.id, f]));
    data.services.forEach((s, i) => {
      if (!assets.has(s.assetId))
        ctx.addIssue({
          code: "custom",
          path: ["services", i, "assetId"],
          message: "Asset ID does not exist."
        });
    });
    data.findings.forEach((f, i) => {
      if (!assets.has(f.assetId))
        ctx.addIssue({
          code: "custom",
          path: ["findings", i, "assetId"],
          message: "Asset ID does not exist."
        });
      if (f.serviceId && services.get(f.serviceId)?.assetId !== f.assetId)
        ctx.addIssue({
          code: "custom",
          path: ["findings", i, "serviceId"],
          message: "Service must exist on this finding's asset."
        });
    });
    const relationshipKeys = new Set<string>();
    data.relationships.forEach((r, i) => {
      const key = JSON.stringify([
        r.from,
        r.to,
        r.type,
        r.state,
        r.confidence,
        r.evidence,
        r.viaFindingId
      ]);
      if (relationshipKeys.has(key))
        ctx.addIssue({
          code: "custom",
          path: ["relationships", i],
          message: "Duplicate relationship evidence. Reuse one relationship ID."
        });
      relationshipKeys.add(key);
      if (!assets.has(r.from) || !assets.has(r.to) || r.from === r.to)
        ctx.addIssue({
          code: "custom",
          path: ["relationships", i],
          message: "Relationships need two different, existing asset IDs."
        });
      if (r.viaFindingId && findings.get(r.viaFindingId)?.assetId !== r.from)
        ctx.addIssue({
          code: "custom",
          path: ["relationships", i, "viaFindingId"],
          message: "The enabling finding must exist on the source asset."
        });
    });
  });
export type Dataset = z.infer<typeof datasetSchema>;
export type InputFinding = Dataset["findings"][number];

export function parseDatasetBytes(bytes: Uint8Array): Dataset {
  if (bytes.byteLength > INPUT_LIMIT_BYTES)
    throw new Error("Dataset exceeds the 1 MiB limit.");
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("Dataset must use UTF-8 text.");
  }
  return parseDataset(source);
}

export function parseDataset(source: string): Dataset {
  if (new TextEncoder().encode(source).byteLength > INPUT_LIMIT_BYTES)
    throw new Error("Dataset exceeds the 1 MiB limit.");
  let data: unknown;
  try {
    data = JSON.parse(source);
  } catch {
    throw new Error(
      "This file is not valid JSON. Use the sample dataset for the expected format."
    );
  }
  const parsed = datasetSchema.safeParse(data);
  if (!parsed.success) {
    throw new Error(
      parsed.error.issues
        .slice(0, 5)
        .map((issue) => `${issue.path.join(".") || "dataset"}: ${issue.message}`)
        .join("\n")
    );
  }
  return parsed.data;
}
