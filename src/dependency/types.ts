import type { PNPMAuditReport, Severity } from 'audit-types'

export type DependencyAuditOptions = {
  path: string
  level?: Severity
}

export type DependencyAuditReport = PNPMAuditReport.AuditMetadata
