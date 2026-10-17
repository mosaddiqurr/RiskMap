import { createHash } from "node:crypto";
import { InvitationStatus } from "@prisma/client";
import { prisma } from "@/lib/db";

export function invitationMatchesAccount(invitationEmail: string, userEmail: string) {
  return invitationEmail.trim().toLowerCase() === userEmail.trim().toLowerCase();
}

function tokenHash(token: string) {
  return createHash("sha256").update(token).digest("hex");
}

export async function acceptInvitation(input: {
  userId: string;
  userEmail: string;
  token: string;
}) {
  const invitation = await prisma.invitation.findUnique({
    where: { tokenHash: tokenHash(input.token) },
    include: { organisation: true }
  });
  if (!invitation || invitation.status !== InvitationStatus.PENDING) {
    throw new Error("NOT_FOUND");
  }
  if (invitation.expiresAt <= new Date()) throw new Error("INVITATION_EXPIRED");
  if (!invitationMatchesAccount(invitation.email, input.userEmail)) {
    throw new Error("FORBIDDEN");
  }

  return prisma.$transaction(async (tx) => {
    const membership = await tx.membership.upsert({
      where: {
        organisationId_userId: {
          organisationId: invitation.organisationId,
          userId: input.userId
        }
      },
      create: {
        organisationId: invitation.organisationId,
        userId: input.userId,
        role: invitation.role
      },
      update: {}
    });
    await tx.invitation.update({
      where: { id: invitation.id },
      data: { status: InvitationStatus.ACCEPTED }
    });
    await tx.auditLog.create({
      data: {
        organisationId: invitation.organisationId,
        userId: input.userId,
        action: "INVITATION_ACCEPTED",
        entityType: "Invitation",
        entityId: invitation.id,
        detailsJson: JSON.stringify({ email: invitation.email, role: invitation.role })
      }
    });
    return { membership, organisation: invitation.organisation };
  });
}
