import { createHash } from "node:crypto";
import net from "node:net";
import { domainToASCII } from "node:url";

function compactHash(namespace: string, parts: Array<string | number | null | undefined>) {
  const canonical = parts
    .map((part) =>
      part === null || part === undefined || part === "" ? "∅" : String(part)
    )
    .join("\u001f");
  return `${namespace}:v1:${createHash("sha256").update(canonical).digest("hex")}`;
}

export function normalizeHostname(value?: string | null) {
  if (!value) return null;
  const stripped = value
    .trim()
    .replace(/^\[|\]$/g, "")
    .replace(/\.+$/, "")
    .toLowerCase();
  if (!stripped) return null;
  const ascii = domainToASCII(stripped);
  return (ascii || stripped).toLowerCase();
}

export function normalizeIpAddress(value?: string | null) {
  if (!value) return null;
  const raw =
    value
      .trim()
      .replace(/^\[|\]$/g, "")
      .split("%", 1)[0]
      ?.toLowerCase() ?? "";
  const dottedParts = raw.split(".");
  if (
    dottedParts.length === 4 &&
    dottedParts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
  ) {
    return dottedParts.map((part) => String(Number(part))).join(".");
  }
  const family = net.isIP(raw);
  if (family === 4)
    return raw
      .split(".")
      .map((part) => String(Number(part)))
      .join(".");
  if (family === 6) {
    try {
      const hostname = new URL(`http://[${raw}]/`).hostname;
      return hostname.slice(1, -1).toLowerCase();
    } catch {
      return raw;
    }
  }
  return raw || null;
}

export function normalizeProtocol(value?: string | null) {
  if (!value) return null;
  return value.trim().toLowerCase().replace(/:$/, "") || null;
}

export function normalizeTransport(value?: string | null) {
  const transport = normalizeProtocol(value);
  return transport === "udp" ? "udp" : "tcp";
}

export function normalizeServiceIdentifier(value?: string | null) {
  return value?.trim().toLowerCase().replace(/\s+/g, "-") || null;
}

export function createAssetFingerprint(input: {
  organisationId: string;
  type: string;
  hostname?: string | null;
  ipAddress?: string | null;
  port?: number | null;
  protocol?: string | null;
  serviceIdentifier?: string | null;
  name?: string | null;
}) {
  return compactHash("asset", [
    input.organisationId,
    input.type.toUpperCase(),
    normalizeHostname(input.hostname),
    normalizeIpAddress(input.ipAddress),
    input.port ?? null,
    normalizeProtocol(input.protocol),
    normalizeServiceIdentifier(input.serviceIdentifier),
    !input.hostname && !input.ipAddress ? input.name?.trim().toLowerCase() : null
  ]);
}

export function createServiceFingerprint(input: {
  organisationId: string;
  assetFingerprint: string;
  port: number;
  protocol?: string | null;
  transport?: string | null;
  serviceIdentifier?: string | null;
}) {
  return compactHash("service", [
    input.organisationId,
    input.assetFingerprint,
    Number(input.port),
    normalizeProtocol(input.protocol) ?? "unknown",
    normalizeTransport(input.transport),
    normalizeServiceIdentifier(input.serviceIdentifier)
  ]);
}

export function createFindingFingerprint(input: {
  organisationId: string;
  assetFingerprint: string;
  serviceFingerprint?: string | null;
  ruleId: string;
  evidenceIdentity?: string | null;
  port?: number | null;
  protocol?: string | null;
}) {
  return compactHash("finding", [
    input.organisationId,
    input.assetFingerprint,
    input.serviceFingerprint,
    input.ruleId.trim().toLowerCase(),
    input.evidenceIdentity?.trim().toLowerCase(),
    input.port ?? null,
    normalizeProtocol(input.protocol)
  ]);
}

export function createRelationshipFingerprint(input: {
  organisationId: string;
  fromFingerprint: string;
  toFingerprint: string;
  type: string;
}) {
  return compactHash("relationship", [
    input.organisationId,
    input.fromFingerprint,
    input.toFingerprint,
    input.type.trim().toLowerCase()
  ]);
}

export function createAttackPathFingerprint(input: {
  organisationId: string;
  orderedNodeKeys: string[];
  orderedEdgeKeys: string[];
}) {
  return compactHash("attack-path", [
    input.organisationId,
    ...input.orderedNodeKeys,
    "edges",
    ...input.orderedEdgeKeys
  ]);
}

export function createTechnologyFingerprint(input: {
  organisationId: string;
  assetFingerprint: string;
  serviceFingerprint?: string | null;
  productName: string;
  version?: string | null;
}) {
  return compactHash("technology", [
    input.organisationId,
    input.assetFingerprint,
    input.serviceFingerprint,
    input.productName.trim().toLowerCase(),
    input.version?.trim().toLowerCase()
  ]);
}

export function createObservationFingerprint(input: {
  module: string;
  type: string;
  assetFingerprint?: string | null;
  serviceFingerprint?: string | null;
  identity?: string | null;
}) {
  return compactHash("observation", [
    input.module,
    input.type,
    input.assetFingerprint,
    input.serviceFingerprint,
    input.identity
  ]);
}
