import type { SeverityLevel, DependencyAuditOptions, DependencyAuditReport } from './types'

const LEVELS = ['info', 'low', 'moderate', 'high', 'critical']

export function countVulnerabilities(report: DependencyAuditReport) {
  return Object.keys(report.vulnerabilities).reduce((total, level) => {
    return total + report.vulnerabilities[level as SeverityLevel]
  }, 0)
}

export function auditReportHasVulnerabilities(
  report: DependencyAuditReport,
  level: DependencyAuditOptions['level'] = 'info',
): boolean {
  const inferredLevels = LEVELS.slice(LEVELS.indexOf(level))

  return inferredLevels.some((level) => report.vulnerabilities[level as SeverityLevel] > 0)
}
