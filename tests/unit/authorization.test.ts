import { describe, expect, it } from "vitest";
import {
  assertResourceOrganisation,
  canChangeMemberRole,
  canManageBilling,
  canRemoveMember,
  canStartScans,
  hasMinimumRole,
  scopedWhere
} from "@/lib/services/authorization";
import { invitationMatchesAccount } from "@/lib/services/invitations";

describe("server-side role policy", () => {
  it("allows analysts to scan but only owners to manage billing", () => {
    expect(canStartScans("ANALYST")).toBe(true);
    expect(canStartScans("VIEWER")).toBe(false);
    expect(canManageBilling("OWNER")).toBe(true);
    expect(canManageBilling("ADMIN")).toBe(false);
  });

  it("prevents admins from changing or removing the owner", () => {
    expect(
      canChangeMemberRole({
        actorRole: "ADMIN",
        actorUserId: "admin",
        targetUserId: "owner",
        targetRole: "OWNER",
        nextRole: "VIEWER"
      })
    ).toBe(false);
    expect(
      canRemoveMember({
        actorRole: "ADMIN",
        actorUserId: "admin",
        targetUserId: "owner",
        targetRole: "OWNER"
      })
    ).toBe(false);
  });

  it("prevents self-removal and preserves role hierarchy", () => {
    expect(
      canRemoveMember({
        actorRole: "ADMIN",
        actorUserId: "admin",
        targetUserId: "admin",
        targetRole: "ADMIN"
      })
    ).toBe(false);
    expect(hasMinimumRole("VIEWER", "ANALYST")).toBe(false);
    expect(hasMinimumRole("OWNER", "ADMIN")).toBe(true);
  });
});

describe("tenant and invitation boundaries", () => {
  it("injects the selected organisation into every scoped filter", () => {
    expect(scopedWhere("org-a", { status: "OPEN" })).toEqual({
      organisationId: "org-a",
      status: "OPEN"
    });
  });

  it("hides cross-tenant resources as not found", () => {
    expect(() => assertResourceOrganisation("org-b", "org-a")).toThrow("NOT_FOUND");
    expect(() => assertResourceOrganisation("org-a", "org-a")).not.toThrow();
  });

  it("accepts an invitation only for the matching account email", () => {
    expect(invitationMatchesAccount("User@Example.test", "user@example.test")).toBe(true);
    expect(invitationMatchesAccount("user@example.test", "other@example.test")).toBe(false);
  });
});
