import { Severity } from 'audit-types'

import type { DependencyAuditReport } from '../dependency/types'

export const SEVERITY_LEVELS: Severity[] = ['info', 'low', 'moderate', 'high', 'critical']

export function isSeverityLevel(arg: any): arg is Severity {
  return SEVERITY_LEVELS.includes(arg)
}

export function countVulnerabilities(report: DependencyAuditReport, level: Severity = 'low') {
  return SEVERITY_LEVELS.slice(SEVERITY_LEVELS.indexOf(level)).reduce((total, level) => {
    return total + (report.vulnerabilities[level] ?? 0)
  }, 0)
}

export function hasVulnerabilities(
  report: DependencyAuditReport,
  level: Severity = 'low',
): boolean {
  return countVulnerabilities(report, level) > 0
}
