import { auditDependencies, DependencyAuditOptions } from '@taskworld/platform-audit'
import * as core from '@actions/core'

import { auditReportHasVulnerabilities } from './util'
import type { SeverityLevel } from './types'

export interface AuditPRResult {
  vulnerabilities: string
  failed: boolean
}

export async function auditPR(
  options: DependencyAuditOptions,
  identifier: string,
  failureLevel?: SeverityLevel,
): Promise<AuditPRResult> {
  core.info(`Options: ${JSON.stringify(options, null, 2)}`)

  const report = await auditDependencies(options)

  core.info(`Report: ${JSON.stringify(report, null, 2)}`)

  const hasVulnabilities = auditReportHasVulnerabilities(report)

  if (!hasVulnabilities) {
    const noVulnerabilities = `
✅ No vulnerabilities found in **${identifier}**.
`

    return { failed: false, vulnerabilities: noVulnerabilities }
  }

  const failed = failureLevel ? auditReportHasVulnerabilities(report, failureLevel) : false

  const renderedVulnerabilities = `
## Vulnerabilities 

Vulnerabilities were found in **${identifier}**.

<table>
  <tbody>
    <tr>
      <th align="left">🔴 Critical</th>
      <td>${report.vulnerabilities.critical}</td>
    </tr>
    <tr>
      <th align="left">🟡 High</th>
      <td>${report.vulnerabilities.high}</td>
    </tr>
    <tr>
      <th align="left">⚪ Moderate</th>
      <td>${report.vulnerabilities.moderate}</td>
    </tr>
  </tbody>
</table>`

  return { failed, vulnerabilities: renderedVulnerabilities }
}
