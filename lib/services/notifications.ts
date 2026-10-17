import { type AlertSeverity, Prisma } from "@prisma/client";
import { prisma } from "@/lib/db";

const severityWeight: Record<AlertSeverity, number> = {
  CRITICAL: 5,
  HIGH: 4,
  MEDIUM: 3,
  LOW: 2,
  INFORMATIONAL: 1
};

export async function simulateAlertDeliveries(alertId: string) {
  const alert = await prisma.alert.findUnique({ where: { id: alertId } });
  if (!alert) return;
  const settings = await prisma.notificationSetting.findMany({
    where: { organisationId: alert.organisationId }
  });
  const logs: Prisma.AuditLogCreateManyInput[] = [];

  for (const setting of settings) {
    if ((severityWeight[alert.severity] ?? 0) < (severityWeight[setting.minSeverity] ?? 99))
      continue;
    const channels = [
      ["email", setting.emailEnabled],
      ["slack", setting.slackEnabled],
      ["microsoft-teams", setting.teamsEnabled],
      ["webhook", setting.webhookEnabled]
    ] as const;
    for (const [channel, enabled] of channels) {
      if (!enabled) continue;
      logs.push({
        organisationId: alert.organisationId,
        userId: setting.userId,
        action: "NOTIFICATION_SIMULATED",
        entityType: "Alert",
        entityId: alert.id,
        detailsJson: JSON.stringify({
          channel,
          delivered: true,
          simulated: true,
          severity: alert.severity
        }),
        createdAt: new Date()
      });
    }
  }
  if (logs.length) await prisma.auditLog.createMany({ data: logs });
}

export async function createAlertAndSimulate(data: Prisma.AlertUncheckedCreateInput) {
  const alert = await prisma.alert.create({ data });
  await simulateAlertDeliveries(alert.id);
  return alert;
}
