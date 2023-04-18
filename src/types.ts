import type { DependencyAuditReport, DependencyAuditOptions } from '@taskworld/platform-audit'

export type SeverityLevel = keyof DependencyAuditReport['vulnerabilities']

export type { DependencyAuditReport, DependencyAuditOptions }
