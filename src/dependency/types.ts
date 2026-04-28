import type { PNPMAuditReport, Severity } from 'audit-types'

export type DependencyAuditOptions = {
  path: string
  level?: Severity
  includeDevDeps?: boolean
  detailed?: boolean
}

export type VulnerablePackage = {
  name: string
  version: string
  direct: boolean
}

export type DependencyAuditReport = PNPMAuditReport.AuditMetadata & {
  details?: Partial<Record<Severity, VulnerablePackage[]>>
}
