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
  // Full chain from the direct dependency, e.g. "express@4.17.1 > body-parser@1.19.0 > bytes@3.1.0".
  path?: string
}

export type DependencyAuditReport = PNPMAuditReport.AuditMetadata & {
  details?: Partial<Record<Severity, VulnerablePackage[]>>
}
