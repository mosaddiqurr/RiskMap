import type { FindingStatus, ServiceObservedState } from "@prisma/client";

export type PresenceLifecycleInput = {
  active: boolean;
  consecutivePresenceCount: number;
  consecutiveAbsenceCount: number;
};

export type PresenceLifecycleResult = PresenceLifecycleInput & {
  transition: "DISCOVERED" | "STILL_PRESENT" | "MISSED" | "INACTIVE" | "REAPPEARED";
};

export function applyPresenceLifecycle(
  previous: PresenceLifecycleInput | null,
  observed: boolean,
  absenceThreshold: number
): PresenceLifecycleResult {
  const threshold = Math.max(1, absenceThreshold);
  if (!previous) {
    return observed
      ? {
          active: true,
          consecutivePresenceCount: 1,
          consecutiveAbsenceCount: 0,
          transition: "DISCOVERED"
        }
      : {
          active: false,
          consecutivePresenceCount: 0,
          consecutiveAbsenceCount: 1,
          transition: "INACTIVE"
        };
  }

  if (observed) {
    return {
      active: true,
      consecutivePresenceCount: previous.consecutivePresenceCount + 1,
      consecutiveAbsenceCount: 0,
      transition: previous.active ? "STILL_PRESENT" : "REAPPEARED"
    };
  }

  const misses = previous.consecutiveAbsenceCount + 1;
  return {
    active: misses < threshold && previous.active,
    consecutivePresenceCount: 0,
    consecutiveAbsenceCount: misses,
    transition: misses >= threshold ? "INACTIVE" : "MISSED"
  };
}

export type FindingLifecycleInput = {
  status: FindingStatus;
  currentlyObserved: boolean;
  observationCount: number;
  consecutiveMisses: number;
  recurrenceCount: number;
};

export type FindingLifecycleResult = FindingLifecycleInput & {
  transition: "CREATED" | "STILL_OPEN" | "PRESERVED" | "MISSED" | "RESOLVED" | "REOPENED";
  resolvedNow: boolean;
  reopenedNow: boolean;
};

export function applyFindingLifecycle(
  previous: FindingLifecycleInput | null,
  observed: boolean,
  moduleCompletedSuccessfully: boolean,
  resolutionAbsenceThreshold: number
): FindingLifecycleResult {
  const threshold = Math.max(1, resolutionAbsenceThreshold);
  if (!previous) {
    if (!observed) throw new Error("A new finding lifecycle cannot begin unobserved");
    return {
      status: "OPEN",
      currentlyObserved: true,
      observationCount: 1,
      consecutiveMisses: 0,
      recurrenceCount: 0,
      transition: "CREATED",
      resolvedNow: false,
      reopenedNow: false
    };
  }

  if (observed) {
    const reopen = previous.status === "RESOLVED";
    const protectedStatus =
      previous.status === "ACCEPTED_RISK" || previous.status === "FALSE_POSITIVE";
    return {
      status: reopen ? "REOPENED" : previous.status,
      currentlyObserved: true,
      observationCount: previous.observationCount + 1,
      consecutiveMisses: 0,
      recurrenceCount: previous.recurrenceCount + (reopen ? 1 : 0),
      transition: reopen ? "REOPENED" : protectedStatus ? "PRESERVED" : "STILL_OPEN",
      resolvedNow: false,
      reopenedNow: reopen
    };
  }

  if (!moduleCompletedSuccessfully) {
    return {
      ...previous,
      transition: "PRESERVED",
      resolvedNow: false,
      reopenedNow: false
    };
  }

  const misses = previous.consecutiveMisses + 1;
  const protectedStatus =
    previous.status === "ACCEPTED_RISK" || previous.status === "FALSE_POSITIVE";
  const alreadyResolved = previous.status === "RESOLVED";
  const resolve = !protectedStatus && !alreadyResolved && misses >= threshold;
  return {
    ...previous,
    status: resolve ? "RESOLVED" : previous.status,
    currentlyObserved: false,
    consecutiveMisses: misses,
    transition: resolve ? "RESOLVED" : protectedStatus ? "PRESERVED" : "MISSED",
    resolvedNow: resolve,
    reopenedNow: false
  };
}

export function serviceStateTransition(
  previousActive: boolean,
  previousState: ServiceObservedState,
  nextActive: boolean,
  nextState: ServiceObservedState,
  reappeared: boolean
) {
  if (reappeared || (!previousActive && nextActive)) return "REOPENED";
  if (previousState !== "OPEN" && nextState === "OPEN") return "OPENED";
  if (previousState === "OPEN" && (!nextActive || nextState === "CLOSED")) return "CLOSED";
  if (previousState !== nextState) return "CHANGED";
  return nextActive ? "STILL_OPEN" : "STILL_CLOSED";
}
