import { SEVERITY_LEVELS } from '@taskworld/platform-audit'

import type { PNPMAuditReport } from 'audit-types'

type DependencyAuditReport = PNPMAuditReport.AuditMetadata
type SeverityLevel = keyof DependencyAuditReport['vulnerabilities']

export function countVulnerabilities(report: DependencyAuditReport, level: SeverityLevel = 'low') {
  return SEVERITY_LEVELS.slice(SEVERITY_LEVELS.indexOf(level)).reduce((total, level) => {
    return total + (report.vulnerabilities[level] ?? 0)
  }, 0)
}

export function hasVulnerabilities(
  report: DependencyAuditReport,
  level: SeverityLevel = 'low',
): boolean {
  return countVulnerabilities(report, level) > 0
}
