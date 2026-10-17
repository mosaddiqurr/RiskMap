import { describe, expect, it } from "vitest";
import {
  createAssetFingerprint,
  createAttackPathFingerprint,
  createFindingFingerprint,
  createRelationshipFingerprint,
  createServiceFingerprint,
  normalizeHostname,
  normalizeIpAddress
} from "@/lib/scanning/identity";
import {
  applyFindingLifecycle,
  applyPresenceLifecycle,
  serviceStateTransition
} from "@/lib/scanning/lifecycle";

describe("stable identity", () => {
  it("normalises IDNs, case, trailing dots and IPv6 consistently", () => {
    expect(normalizeHostname("BÜCHER.Example.")).toBe("xn--bcher-kva.example");
    expect(normalizeHostname("APP.NORTHSTAR.TEST...")).toBe("app.northstar.test");
    expect(normalizeIpAddress("2001:0DB8:0:0:0:0:0:1")).toBe("2001:db8::1");
    expect(normalizeIpAddress("127.000.000.001")).toBe("127.0.0.1");
  });

  it("keeps unchanged asset and service fingerprints stable", () => {
    const firstAsset = createAssetFingerprint({
      organisationId: "org-a",
      type: "SUBDOMAIN",
      hostname: "Admin.Northstar.Test."
    });
    const secondAsset = createAssetFingerprint({
      organisationId: "org-a",
      type: "subdomain",
      hostname: "admin.northstar.test"
    });
    expect(firstAsset).toBe(secondAsset);

    const firstService = createServiceFingerprint({
      organisationId: "org-a",
      assetFingerprint: firstAsset,
      port: 8443,
      protocol: "HTTPS:",
      transport: "TCP",
      serviceIdentifier: "Administration Console"
    });
    const secondService = createServiceFingerprint({
      organisationId: "org-a",
      assetFingerprint: secondAsset,
      port: 8443,
      protocol: "https",
      transport: "tcp",
      serviceIdentifier: "administration-console"
    });
    expect(firstService).toBe(secondService);
  });

  it("changes a finding fingerprint only when its evidence identity changes", () => {
    const assetFingerprint = createAssetFingerprint({
      organisationId: "org-a",
      type: "SUBDOMAIN",
      hostname: "admin.northstar.test"
    });
    const base = {
      organisationId: "org-a",
      assetFingerprint,
      ruleId: "network.admin.public",
      port: 8443,
      protocol: "https"
    };
    expect(createFindingFingerprint({ ...base, evidenceIdentity: "tcp:8443" })).toBe(
      createFindingFingerprint({ ...base, evidenceIdentity: "TCP:8443" })
    );
    expect(createFindingFingerprint({ ...base, evidenceIdentity: "tcp:8443" })).not.toBe(
      createFindingFingerprint({ ...base, evidenceIdentity: "tcp:443" })
    );
  });

  it("creates ordered relationship and path fingerprints", () => {
    const relationship = createRelationshipFingerprint({
      organisationId: "org-a",
      fromFingerprint: "asset:a",
      toFingerprint: "asset:b",
      type: "Could reach"
    });
    const reversed = createRelationshipFingerprint({
      organisationId: "org-a",
      fromFingerprint: "asset:b",
      toFingerprint: "asset:a",
      type: "Could reach"
    });
    expect(relationship).not.toBe(reversed);

    const path = createAttackPathFingerprint({
      organisationId: "org-a",
      orderedNodeKeys: ["internet", "asset:a", "finding:x", "asset:b"],
      orderedEdgeKeys: ["edge:1", "edge:2", "edge:3"]
    });
    expect(path).toBe(
      createAttackPathFingerprint({
        organisationId: "org-a",
        orderedNodeKeys: ["internet", "asset:a", "finding:x", "asset:b"],
        orderedEdgeKeys: ["edge:1", "edge:2", "edge:3"]
      })
    );
  });
});

describe("presence lifecycle", () => {
  it("waits for the configured absence threshold before deactivation", () => {
    const firstMiss = applyPresenceLifecycle(
      { active: true, consecutivePresenceCount: 3, consecutiveAbsenceCount: 0 },
      false,
      2
    );
    expect(firstMiss).toMatchObject({ active: true, transition: "MISSED" });

    const secondMiss = applyPresenceLifecycle(firstMiss, false, 2);
    expect(secondMiss).toMatchObject({ active: false, transition: "INACTIVE" });
    expect(applyPresenceLifecycle(secondMiss, true, 2).transition).toBe("REAPPEARED");
  });

  it("resolves only after a successful module and reopens on recurrence", () => {
    const open = applyFindingLifecycle(null, true, true, 1);
    const preserved = applyFindingLifecycle(open, false, false, 1);
    expect(preserved).toMatchObject({ status: "OPEN", transition: "PRESERVED" });

    const resolved = applyFindingLifecycle(preserved, false, true, 1);
    expect(resolved).toMatchObject({ status: "RESOLVED", resolvedNow: true });

    const reopened = applyFindingLifecycle(resolved, true, true, 1);
    expect(reopened).toMatchObject({
      status: "REOPENED",
      reopenedNow: true,
      recurrenceCount: 1
    });
  });

  it("preserves accepted-risk and false-positive decisions", () => {
    const accepted = applyFindingLifecycle(
      {
        status: "ACCEPTED_RISK",
        currentlyObserved: true,
        observationCount: 2,
        consecutiveMisses: 0,
        recurrenceCount: 0
      },
      false,
      true,
      1
    );
    expect(accepted.status).toBe("ACCEPTED_RISK");
    expect(accepted.transition).toBe("PRESERVED");
  });

  it("records service closure and reopening transitions", () => {
    expect(serviceStateTransition(true, "OPEN", false, "CLOSED", false)).toBe("CLOSED");
    expect(serviceStateTransition(false, "CLOSED", true, "OPEN", true)).toBe("REOPENED");
  });
});
