import { Role, type Membership, type Organisation, type User } from "@prisma/client";
import { cookies } from "next/headers";
import { prisma } from "@/lib/db";
import { getCurrentUser } from "@/lib/services/auth";

export const ORG_COOKIE = "riskmap_org";

const roleWeight: Record<Role, number> = {
  OWNER: 4,
  ADMIN: 3,
  ANALYST: 2,
  VIEWER: 1
};

export function hasMinimumRole(actual: Role, required: Role) {
  return (roleWeight[actual] ?? 0) >= (roleWeight[required] ?? Number.POSITIVE_INFINITY);
}

export function canStartScans(role: Role) {
  return hasMinimumRole(role, Role.ANALYST);
}

export function canManageBilling(role: Role) {
  return role === Role.OWNER;
}

export function assertResourceOrganisation(
  resourceOrganisationId: string,
  selectedOrganisationId: string
) {
  if (resourceOrganisationId !== selectedOrganisationId) throw new Error("NOT_FOUND");
}

export function canChangeMemberRole(input: {
  actorRole: Role;
  actorUserId: string;
  targetUserId: string;
  targetRole: Role;
  nextRole: Role;
}) {
  if (!hasMinimumRole(input.actorRole, Role.ADMIN)) return false;
  if (input.targetRole === Role.OWNER || input.nextRole === Role.OWNER) return false;
  if (input.actorUserId === input.targetUserId && input.actorRole !== Role.OWNER)
    return false;
  return true;
}

export function canRemoveMember(input: {
  actorRole: Role;
  actorUserId: string;
  targetUserId: string;
  targetRole: Role;
}) {
  if (!hasMinimumRole(input.actorRole, Role.ADMIN)) return false;
  if (input.targetRole === Role.OWNER) return false;
  if (input.actorUserId === input.targetUserId) return false;
  return true;
}

export type CurrentContext = {
  user: User;
  organisation: Organisation;
  membership: Membership;
  organisations: Array<Membership & { organisation: Organisation }>;
};

export async function getCurrentContext(): Promise<CurrentContext | null> {
  const user = await getCurrentUser();
  if (!user) return null;

  const memberships = await prisma.membership.findMany({
    where: { userId: user.id, organisation: { deletedAt: null } },
    include: { organisation: true },
    orderBy: { createdAt: "asc" }
  });
  if (!memberships.length) return null;

  const store = await cookies();
  const requestedId = store.get(ORG_COOKIE)?.value;
  const membership =
    memberships.find((item) => item.organisationId === requestedId) ?? memberships[0];
  if (!membership) return null;

  return {
    user,
    organisation: membership.organisation,
    membership,
    organisations: memberships
  };
}

export async function requireCurrentContext(requiredRole: Role = Role.VIEWER) {
  const context = await getCurrentContext();
  if (!context) throw new Error("UNAUTHENTICATED");
  if (!hasMinimumRole(context.membership.role, requiredRole)) throw new Error("FORBIDDEN");
  return context;
}

export function scopedWhere<T extends object>(organisationId: string, where?: T) {
  return { organisationId, ...(where ?? {}) } as T & { organisationId: string };
}
