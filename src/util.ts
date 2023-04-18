import type { DependencyAuditReport } from '@taskworld/platform-audit'

type Level = keyof DependencyAuditReport['vulnerabilities']

export function countVulnerabilities(report: DependencyAuditReport) {
  return Object.keys(report.vulnerabilities).reduce((total, level) => {
    return total + report.vulnerabilities[level as Level]
  }, 0)
}
