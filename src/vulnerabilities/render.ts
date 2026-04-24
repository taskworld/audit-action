import type { Severity } from 'audit-types'

import type { DependencyAuditReport, VulnerablePackage } from '../dependency/types'

export function noVulnerabilities(packageName: string) {
  return `
  ✅ No vulnerabilities found in **${packageName}**.
`
}

// ---

const SEVERITY_LABELS: Record<Severity, string> = {
  low: '🔵 Low',
  info: '⚪ Info',
  moderate: '🟡 Moderate',
  high: '🟠 High',
  critical: '🔴 Critical',
}

function renderRow(severity: Severity, count: number) {
  return `<tr>
  <th align="left">${SEVERITY_LABELS[severity]}</th>
  <td>${count}</td>
</tr>`
}

function renderDetailedRow(severity: Severity, count: number, packages: string) {
  return `<tr>
  <th align="left">${SEVERITY_LABELS[severity]}</th>
  <td>${count}</td>
  <td>${packages}</td>
</tr>`
}

export function formatPackages(pkgs: VulnerablePackage[]): string {
  const sorted = [...pkgs].sort((a, b) => {
    if (a.name < b.name) return -1
    if (a.name > b.name) return 1
    if (a.version < b.version) return -1
    if (a.version > b.version) return 1
    return 0
  })

  return sorted
    .map((p) => (p.direct ? `\`${p.name}@${p.version}\`` : `\`>${p.name}@${p.version}\``))
    .join(', ')
}

export function someVulnerabilities(packageName: string, report: DependencyAuditReport) {
  const { vulnerabilities, details } = report

  const entries = Object.entries(vulnerabilities) as [Severity, number][]
  const rows = entries.map(([severity, count]) => {
    if (details === undefined) {
      return renderRow(severity, count)
    }
    const entry = details[severity]
    const packages = entry ? formatPackages(entry) : ''
    return renderDetailedRow(severity, count, packages)
  })

  return `
  ## Vulnerabilities

  Vulnerabilities were found in **${packageName}**.

  <table>
    <tbody>
    ${rows.join('\n')}
    </tbody>
  </table>`
}
