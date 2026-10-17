import { Plan } from "@prisma/client";

export const planLimits = {
  FREE: {
    rootDomains: 1,
    assets: 10,
    members: 1,
    historyDays: 7,
    manualScansPerWeek: 1,
    visibleFindings: 3,
    scheduled: false,
    fullGraph: false,
    reports: false,
    multipleUsers: false,
    emailAlerts: false,
    webhooks: false
  },
  PRO: {
    rootDomains: 3,
    assets: 10,
    members: 1,
    historyDays: 90,
    manualScansPerWeek: 20,
    visibleFindings: 10_000,
    scheduled: true,
    fullGraph: true,
    reports: true,
    multipleUsers: false,
    emailAlerts: true,
    webhooks: false
  },
  BUSINESS: {
    rootDomains: 10,
    assets: 50,
    members: 25,
    historyDays: 365,
    manualScansPerWeek: 100,
    visibleFindings: 10_000,
    scheduled: true,
    fullGraph: true,
    reports: true,
    multipleUsers: true,
    emailAlerts: true,
    webhooks: true
  }
} satisfies Record<Plan, Record<string, number | boolean>>;

export function getPlanLimit(plan: Plan) {
  return planLimits[plan as keyof typeof planLimits];
}

export function getHistoryCutoff(plan: Plan, now = new Date()) {
  return new Date(now.getTime() - getPlanLimit(plan).historyDays * 86_400_000);
}
