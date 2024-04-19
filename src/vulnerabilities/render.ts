import type { Severity } from 'audit-types'

export function noVulnerabilities(packageName: string) {
  return `
  ✅ No vulnerabilities found in **${packageName}**.
`
}

// ---

function lowRenderer(val: number) {
  return `<tr>
  <th align="left">🔵 Low</th>
  <td>${val}</td>
</tr>`
}

function infoRenderer(val: number) {
  return `<tr>
  <th align="left">⚪ Info</th>
  <td>${val}</td>
</tr>`
}

function moderateRenderer(val: number) {
  return `<tr>
  <th align="left">🟡 Moderate</th>
  <td>${val}</td>
</tr>`
}

function highRenderer(val: number) {
  return `<tr>
  <th align="left">🟠 High</th>
  <td>${val}</td>
</tr>`
}

function criticalRenderer(val: number) {
  return `<tr>
  <th align="left">🔴 Critical</th>
  <td>${val}</td>
</tr>`
}

const VULNERABILITY_RENDERERS: Record<Severity, (val: number) => string> = {
  low: lowRenderer,
  info: infoRenderer,
  moderate: moderateRenderer,
  high: highRenderer,
  critical: criticalRenderer,
}

export function someVulnerabilities(
  packageName: string,
  vulnerabilities: Partial<Record<Severity, number>>,
) {
  return `
  ## Vulnerabilities

  Vulnerabilities were found in **${packageName}**.

  <table>
    <tbody>
    ${Object.entries(vulnerabilities)
      // @ts-expect-error
      .map(([k, v]) => VULNERABILITY_RENDERERS[k](v))
      .join('\n')}
    </tbody>
  </table>`
}
