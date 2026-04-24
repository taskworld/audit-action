import type { PNPMAuditReport, Severity } from 'audit-types'

export type DependencyAuditOptions = {
  path: string
  level?: Severity
  includeDevDeps?: boolean
}

export type DependencyAuditReport = PNPMAuditReport.AuditMetadata
