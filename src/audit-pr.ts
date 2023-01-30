import {
  auditDependencies,
  DependencyAuditOptions,
  DependencyAuditReport,
} from '@taskworld/platform-audit'
import * as core from '@actions/core'

export interface AuditPRResult {
  vulnerabilities: string
}

type Level = keyof DependencyAuditReport['vulnerabilities']

export async function auditPR(
  options: DependencyAuditOptions,
  identifier: string,
): Promise<AuditPRResult> {
  core.info(`Options: ${JSON.stringify(options, null, 2)}`)

  const report = await auditDependencies(options)

  core.info(`Report: ${JSON.stringify(report, null, 2)}`)

  const numVulnabilities = Object.keys(report.vulnerabilities).reduce((total, level) => {
    return total + report.vulnerabilities[level as Level]
  }, 0)

  if (numVulnabilities < 1) {
    const noVulnerabilities = `
✅ No vulnerabilities found in **${identifier}**.
`

    return { vulnerabilities: noVulnerabilities }
  }

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

  return { vulnerabilities: renderedVulnerabilities }
}
