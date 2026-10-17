-- RiskMap Phase 2 baseline schema generated from prisma/schema.prisma.

CREATE TABLE "User" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME
);

CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

CREATE TABLE "Session" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tokenHash" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Session_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Session_tokenHash_key" ON "Session"("tokenHash");

CREATE INDEX "Session_userId_idx" ON "Session"("userId");

CREATE INDEX "Session_expiresAt_idx" ON "Session"("expiresAt");

CREATE TABLE "Organisation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "slug" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME
);

CREATE UNIQUE INDEX "Organisation_slug_key" ON "Organisation"("slug");

CREATE TABLE "Membership" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'VIEWER',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Membership_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Membership_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Membership_organisationId_userId_key" ON "Membership"("organisationId", "userId");

CREATE INDEX "Membership_userId_idx" ON "Membership"("userId");

CREATE TABLE "Invitation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "tokenHash" TEXT NOT NULL,
    "invitedById" TEXT NOT NULL,
    "expiresAt" DATETIME NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Invitation_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Invitation_invitedById_fkey" FOREIGN KEY ("invitedById") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Invitation_tokenHash_key" ON "Invitation"("tokenHash");

CREATE INDEX "Invitation_organisationId_email_idx" ON "Invitation"("organisationId", "email");

CREATE TABLE "Subscription" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "plan" TEXT NOT NULL DEFAULT 'FREE',
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "currentPeriodEnd" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Subscription_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Subscription_organisationId_key" ON "Subscription"("organisationId");

CREATE TABLE "RootDomain" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "domain" TEXT NOT NULL,
    "verificationStatus" TEXT NOT NULL DEFAULT 'PENDING',
    "verifiedAt" DATETIME,
    "scanPermission" TEXT NOT NULL DEFAULT 'PASSIVE',
    "activeChecksAuthorized" BOOLEAN NOT NULL DEFAULT false,
    "preferredScanWindow" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME,
    CONSTRAINT "RootDomain_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "RootDomain_organisationId_domain_key" ON "RootDomain"("organisationId", "domain");

CREATE INDEX "RootDomain_organisationId_verificationStatus_idx" ON "RootDomain"("organisationId", "verificationStatus");

CREATE TABLE "VerificationChallenge" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "rootDomainId" TEXT NOT NULL,
    "method" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'PENDING',
    "expiresAt" DATETIME NOT NULL,
    "verifiedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "VerificationChallenge_rootDomainId_fkey" FOREIGN KEY ("rootDomainId") REFERENCES "RootDomain" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "VerificationChallenge_rootDomainId_status_idx" ON "VerificationChallenge"("rootDomainId", "status");

CREATE TABLE "Asset" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "rootDomainId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "hostname" TEXT,
    "normalizedHostname" TEXT,
    "ipAddress" TEXT,
    "normalizedIpAddress" TEXT,
    "port" INTEGER,
    "protocol" TEXT,
    "serviceIdentifier" TEXT,
    "status" TEXT NOT NULL DEFAULT 'ACTIVE',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "verificationStatus" TEXT NOT NULL DEFAULT 'VERIFIED',
    "criticality" TEXT NOT NULL DEFAULT 'MEDIUM',
    "source" TEXT NOT NULL,
    "tagsJson" TEXT NOT NULL DEFAULT '[]',
    "ownerName" TEXT,
    "notes" TEXT,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanId" TEXT,
    "consecutivePresenceCount" INTEGER NOT NULL DEFAULT 0,
    "consecutiveAbsenceCount" INTEGER NOT NULL DEFAULT 0,
    "reappearedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME,
    CONSTRAINT "Asset_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Asset_rootDomainId_fkey" FOREIGN KEY ("rootDomainId") REFERENCES "RootDomain" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Asset_organisationId_fingerprint_key" ON "Asset"("organisationId", "fingerprint");

CREATE INDEX "Asset_organisationId_type_idx" ON "Asset"("organisationId", "type");

CREATE INDEX "Asset_organisationId_normalizedHostname_idx" ON "Asset"("organisationId", "normalizedHostname");

CREATE INDEX "Asset_organisationId_normalizedIpAddress_idx" ON "Asset"("organisationId", "normalizedIpAddress");

CREATE INDEX "Asset_organisationId_status_idx" ON "Asset"("organisationId", "status");

CREATE INDEX "Asset_rootDomainId_active_idx" ON "Asset"("rootDomainId", "active");

CREATE TABLE "AssetPresence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "assetId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "observed" BOOLEAN NOT NULL,
    "transition" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AssetPresence_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AssetPresence_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AssetPresence_assetId_scanId_key" ON "AssetPresence"("assetId", "scanId");

CREATE INDEX "AssetPresence_scanId_observed_idx" ON "AssetPresence"("scanId", "observed");

CREATE TABLE "Service" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "port" INTEGER NOT NULL,
    "protocol" TEXT NOT NULL,
    "transport" TEXT NOT NULL,
    "serviceIdentifier" TEXT,
    "observedState" TEXT NOT NULL DEFAULT 'UNKNOWN',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "confidence" TEXT NOT NULL,
    "evidenceSource" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "metadataJson" TEXT NOT NULL DEFAULT '{}',
    "sourceModule" TEXT NOT NULL DEFAULT 'PORT_CHECKS',
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanId" TEXT,
    "consecutivePresenceCount" INTEGER NOT NULL DEFAULT 0,
    "consecutiveAbsenceCount" INTEGER NOT NULL DEFAULT 0,
    "reappearedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Service_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Service_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Service_organisationId_fingerprint_key" ON "Service"("organisationId", "fingerprint");

CREATE INDEX "Service_assetId_active_idx" ON "Service"("assetId", "active");

CREATE INDEX "Service_organisationId_port_protocol_idx" ON "Service"("organisationId", "port", "protocol");

CREATE TABLE "ServicePresence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "serviceId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "observed" BOOLEAN NOT NULL,
    "state" TEXT NOT NULL,
    "transition" TEXT NOT NULL,
    "metadataJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ServicePresence_serviceId_fkey" FOREIGN KEY ("serviceId") REFERENCES "Service" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "ServicePresence_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "ServicePresence_serviceId_scanId_key" ON "ServicePresence"("serviceId", "scanId");

CREATE INDEX "ServicePresence_scanId_observed_idx" ON "ServicePresence"("scanId", "observed");

CREATE TABLE "AssetRelationship" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "fingerprint" TEXT NOT NULL,
    "fromAssetId" TEXT NOT NULL,
    "toAssetId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "state" TEXT NOT NULL DEFAULT 'OBSERVED',
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanId" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "AssetRelationship_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AssetRelationship_fromAssetId_fkey" FOREIGN KEY ("fromAssetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AssetRelationship_toAssetId_fkey" FOREIGN KEY ("toAssetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AssetRelationship_organisationId_fingerprint_key" ON "AssetRelationship"("organisationId", "fingerprint");

CREATE INDEX "AssetRelationship_organisationId_state_active_idx" ON "AssetRelationship"("organisationId", "state", "active");

CREATE INDEX "AssetRelationship_fromAssetId_toAssetId_idx" ON "AssetRelationship"("fromAssetId", "toAssetId");

CREATE TABLE "Scan" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "rootDomainId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "trigger" TEXT NOT NULL DEFAULT 'manual',
    "progress" INTEGER NOT NULL DEFAULT 0,
    "startedAt" DATETIME,
    "completedAt" DATETIME,
    "logJson" TEXT NOT NULL DEFAULT '[]',
    "summaryJson" TEXT NOT NULL DEFAULT '{}',
    "comparisonJson" TEXT NOT NULL DEFAULT '{}',
    "riskScore" INTEGER,
    "previousRiskScore" INTEGER,
    "previousScanId" TEXT,
    "error" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "Scan_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Scan_rootDomainId_fkey" FOREIGN KEY ("rootDomainId") REFERENCES "RootDomain" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "Scan_organisationId_createdAt_idx" ON "Scan"("organisationId", "createdAt");

CREATE INDEX "Scan_rootDomainId_status_completedAt_idx" ON "Scan"("rootDomainId", "status", "completedAt");

CREATE INDEX "Scan_status_createdAt_idx" ON "Scan"("status", "createdAt");

CREATE TABLE "ScanJob" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'QUEUED',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "availableAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lockedAt" DATETIME,
    "lastError" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "ScanJob_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "ScanJob_scanId_key" ON "ScanJob"("scanId");

CREATE INDEX "ScanJob_status_availableAt_idx" ON "ScanJob"("status", "availableAt");

CREATE TABLE "ScanModuleResult" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "scanId" TEXT NOT NULL,
    "module" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "recordCount" INTEGER NOT NULL DEFAULT 0,
    "error" TEXT,
    "startedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "completedAt" DATETIME,
    CONSTRAINT "ScanModuleResult_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "ScanModuleResult_scanId_module_key" ON "ScanModuleResult"("scanId", "module");

CREATE INDEX "ScanModuleResult_module_status_idx" ON "ScanModuleResult"("module", "status");

CREATE TABLE "ScanObservation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "assetId" TEXT,
    "serviceId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "module" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "success" BOOLEAN NOT NULL DEFAULT true,
    "dataJson" TEXT NOT NULL,
    "observedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanObservation_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "ScanObservation_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "ScanObservation_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "ScanObservation_serviceId_fkey" FOREIGN KEY ("serviceId") REFERENCES "Service" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "ScanObservation_scanId_fingerprint_key" ON "ScanObservation"("scanId", "fingerprint");

CREATE INDEX "ScanObservation_scanId_type_idx" ON "ScanObservation"("scanId", "type");

CREATE INDEX "ScanObservation_organisationId_observedAt_idx" ON "ScanObservation"("organisationId", "observedAt");

CREATE TABLE "TechnologyObservation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "assetId" TEXT NOT NULL,
    "serviceId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "productName" TEXT NOT NULL,
    "version" TEXT,
    "confidence" TEXT NOT NULL,
    "evidence" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "active" BOOLEAN NOT NULL DEFAULT true,
    CONSTRAINT "TechnologyObservation_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "TechnologyObservation_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "TechnologyObservation_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "TechnologyObservation_serviceId_fkey" FOREIGN KEY ("serviceId") REFERENCES "Service" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "TechnologyObservation_organisationId_fingerprint_key" ON "TechnologyObservation"("organisationId", "fingerprint");

CREATE INDEX "TechnologyObservation_assetId_active_idx" ON "TechnologyObservation"("assetId", "active");

CREATE INDEX "TechnologyObservation_scanId_idx" ON "TechnologyObservation"("scanId");

CREATE TABLE "Finding" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "scanId" TEXT,
    "assetId" TEXT NOT NULL,
    "serviceId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "ruleId" TEXT NOT NULL,
    "module" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'OPEN',
    "category" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "evidenceSummary" TEXT NOT NULL,
    "evidenceIdentity" TEXT,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanId" TEXT,
    "currentlyObserved" BOOLEAN NOT NULL DEFAULT true,
    "observationCount" INTEGER NOT NULL DEFAULT 1,
    "consecutiveMisses" INTEGER NOT NULL DEFAULT 0,
    "recurrenceCount" INTEGER NOT NULL DEFAULT 0,
    "resolvedAt" DATETIME,
    "resolutionScanId" TEXT,
    "reopenedAt" DATETIME,
    "confidence" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "remediation" TEXT NOT NULL,
    "technicalDetail" TEXT NOT NULL,
    "businessImpact" TEXT NOT NULL,
    "referencesJson" TEXT NOT NULL DEFAULT '[]',
    "falsePositive" BOOLEAN NOT NULL DEFAULT false,
    "assignedUserId" TEXT,
    "dueDate" DATETIME,
    "notes" TEXT,
    "isNew" BOOLEAN NOT NULL DEFAULT false,
    "externallyReachable" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "deletedAt" DATETIME,
    CONSTRAINT "Finding_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Finding_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Finding_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Finding_serviceId_fkey" FOREIGN KEY ("serviceId") REFERENCES "Service" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Finding_assignedUserId_fkey" FOREIGN KEY ("assignedUserId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "Finding_organisationId_fingerprint_key" ON "Finding"("organisationId", "fingerprint");

CREATE INDEX "Finding_organisationId_severity_status_idx" ON "Finding"("organisationId", "severity", "status");

CREATE INDEX "Finding_assetId_status_idx" ON "Finding"("assetId", "status");

CREATE INDEX "Finding_serviceId_status_idx" ON "Finding"("serviceId", "status");

CREATE INDEX "Finding_module_currentlyObserved_idx" ON "Finding"("module", "currentlyObserved");

CREATE TABLE "FindingEvidence" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "findingId" TEXT NOT NULL,
    "scanId" TEXT,
    "kind" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "collectedAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "FindingEvidence_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "FindingEvidence_findingId_idx" ON "FindingEvidence"("findingId");

CREATE INDEX "FindingEvidence_scanId_idx" ON "FindingEvidence"("scanId");

CREATE TABLE "FindingObservation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "findingId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "observed" BOOLEAN NOT NULL,
    "severity" TEXT NOT NULL,
    "confidence" TEXT NOT NULL,
    "statusAfter" TEXT NOT NULL,
    "evidenceSummary" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "FindingObservation_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "FindingObservation_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "FindingObservation_findingId_scanId_key" ON "FindingObservation"("findingId", "scanId");

CREATE INDEX "FindingObservation_scanId_observed_idx" ON "FindingObservation"("scanId", "observed");

CREATE TABLE "AttackPath" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "scanId" TEXT,
    "fingerprint" TEXT NOT NULL,
    "pathType" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "confidence" TEXT NOT NULL,
    "entryAssetId" TEXT,
    "targetAssetId" TEXT,
    "evidence" TEXT NOT NULL,
    "weakestLink" TEXT NOT NULL,
    "recommendedFix" TEXT NOT NULL,
    "recommendedBreakPoint" TEXT,
    "riskReduction" INTEGER NOT NULL,
    "scoreContributorsJson" TEXT NOT NULL DEFAULT '{}',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "isNew" BOOLEAN NOT NULL DEFAULT true,
    "firstSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeen" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastScanId" TEXT,
    "occurrenceCount" INTEGER NOT NULL DEFAULT 1,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "brokenAt" DATETIME,
    CONSTRAINT "AttackPath_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AttackPath_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "AttackPath_entryAssetId_fkey" FOREIGN KEY ("entryAssetId") REFERENCES "Asset" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "AttackPath_targetAssetId_fkey" FOREIGN KEY ("targetAssetId") REFERENCES "Asset" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AttackPath_organisationId_fingerprint_key" ON "AttackPath"("organisationId", "fingerprint");

CREATE INDEX "AttackPath_organisationId_active_riskScore_idx" ON "AttackPath"("organisationId", "active", "riskScore");

CREATE TABLE "AttackPathStep" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "attackPathId" TEXT NOT NULL,
    "stepOrder" INTEGER NOT NULL,
    "nodeKey" TEXT NOT NULL,
    "edgeKey" TEXT,
    "nodeType" TEXT NOT NULL,
    "label" TEXT NOT NULL,
    "assetId" TEXT,
    "findingId" TEXT,
    "relationshipId" TEXT,
    "evidence" TEXT NOT NULL,
    "observedState" TEXT NOT NULL DEFAULT 'OBSERVED',
    "confidence" TEXT NOT NULL DEFAULT 'MEDIUM',
    CONSTRAINT "AttackPathStep_attackPathId_fkey" FOREIGN KEY ("attackPathId") REFERENCES "AttackPath" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AttackPathStep_assetId_fkey" FOREIGN KEY ("assetId") REFERENCES "Asset" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "AttackPathStep_findingId_fkey" FOREIGN KEY ("findingId") REFERENCES "Finding" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "AttackPathStep_relationshipId_fkey" FOREIGN KEY ("relationshipId") REFERENCES "AssetRelationship" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AttackPathStep_attackPathId_stepOrder_key" ON "AttackPathStep"("attackPathId", "stepOrder");

CREATE TABLE "AttackPathObservation" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "attackPathId" TEXT NOT NULL,
    "scanId" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL,
    "riskScore" INTEGER NOT NULL,
    "confidence" TEXT NOT NULL,
    "scoreContributorsJson" TEXT NOT NULL DEFAULT '{}',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AttackPathObservation_attackPathId_fkey" FOREIGN KEY ("attackPathId") REFERENCES "AttackPath" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "AttackPathObservation_scanId_fkey" FOREIGN KEY ("scanId") REFERENCES "Scan" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "AttackPathObservation_attackPathId_scanId_key" ON "AttackPathObservation"("attackPathId", "scanId");

CREATE INDEX "AttackPathObservation_scanId_active_idx" ON "AttackPathObservation"("scanId", "active");

CREATE TABLE "Alert" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "severity" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "relatedAssetId" TEXT,
    "relatedFindingId" TEXT,
    "relatedScanId" TEXT,
    "relatedPathId" TEXT,
    "readAt" DATETIME,
    "dismissedAt" DATETIME,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Alert_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX "Alert_organisationId_readAt_createdAt_idx" ON "Alert"("organisationId", "readAt", "createdAt");

CREATE TABLE "Report" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "type" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "periodStart" DATETIME NOT NULL,
    "periodEnd" DATETIME NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'READY',
    "dataJson" TEXT NOT NULL,
    "createdById" TEXT NOT NULL,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Report_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "Report_createdById_fkey" FOREIGN KEY ("createdById") REFERENCES "User" ("id") ON DELETE RESTRICT ON UPDATE CASCADE
);

CREATE INDEX "Report_organisationId_createdAt_idx" ON "Report"("organisationId", "createdAt");

CREATE TABLE "AuditLog" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT,
    "userId" TEXT,
    "action" TEXT NOT NULL,
    "entityType" TEXT NOT NULL,
    "entityId" TEXT,
    "detailsJson" TEXT NOT NULL DEFAULT '{}',
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AuditLog_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "AuditLog_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);

CREATE INDEX "AuditLog_organisationId_createdAt_idx" ON "AuditLog"("organisationId", "createdAt");

CREATE INDEX "AuditLog_userId_createdAt_idx" ON "AuditLog"("userId", "createdAt");

CREATE TABLE "ScanExclusion" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "rootDomainId" TEXT NOT NULL,
    "pattern" TEXT NOT NULL,
    "reason" TEXT NOT NULL,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanExclusion_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "ScanExclusion_rootDomainId_fkey" FOREIGN KEY ("rootDomainId") REFERENCES "RootDomain" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "ScanExclusion_rootDomainId_pattern_key" ON "ScanExclusion"("rootDomainId", "pattern");

CREATE TABLE "NotificationSetting" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "organisationId" TEXT NOT NULL,
    "userId" TEXT,
    "minSeverity" TEXT NOT NULL DEFAULT 'HIGH',
    "inAppEnabled" BOOLEAN NOT NULL DEFAULT true,
    "emailEnabled" BOOLEAN NOT NULL DEFAULT false,
    "slackEnabled" BOOLEAN NOT NULL DEFAULT false,
    "teamsEnabled" BOOLEAN NOT NULL DEFAULT false,
    "webhookEnabled" BOOLEAN NOT NULL DEFAULT false,
    "webhookUrl" TEXT,
    "largeIncreaseFrom" INTEGER NOT NULL DEFAULT 15,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    CONSTRAINT "NotificationSetting_organisationId_fkey" FOREIGN KEY ("organisationId") REFERENCES "Organisation" ("id") ON DELETE CASCADE ON UPDATE CASCADE,
    CONSTRAINT "NotificationSetting_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE UNIQUE INDEX "NotificationSetting_organisationId_userId_key" ON "NotificationSetting"("organisationId", "userId");
