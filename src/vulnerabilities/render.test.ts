import { describe, expect, it } from 'vitest'

import type { DependencyAuditReport } from '../dependency/types'

import { formatPackages, noVulnerabilities, someVulnerabilities } from './render.js'

function makeReport(overrides: Partial<DependencyAuditReport> = {}): DependencyAuditReport {
  return {
    vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0 },
    dependencies: 0,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies: 0,
    ...overrides,
  }
}

describe('noVulnerabilities', () => {
  it('renders a friendly success message', () => {
    const out = noVulnerabilities('my-pkg')
    expect(out).toContain('✅ No vulnerabilities found in **my-pkg**.')
  })
})

describe('formatPackages', () => {
  it('wraps direct packages in backticks without prefix', () => {
    expect(formatPackages([{ name: 'axios', version: '0.21.1', direct: true }])).toBe(
      '`axios@0.21.1`',
    )
  })

  it('wraps indirect packages with a > inside backticks and no space', () => {
    expect(formatPackages([{ name: 'lodash', version: '4.17.20', direct: false }])).toBe(
      '`>lodash@4.17.20`',
    )
  })

  it('joins multiple packages with comma+space', () => {
    const out = formatPackages([
      { name: 'lodash', version: '4.17.20', direct: false },
      { name: 'axios', version: '0.21.1', direct: true },
    ])
    expect(out).toBe('`axios@0.21.1`, `>lodash@4.17.20`')
  })

  it('sorts by name then version (stable, ascending)', () => {
    const out = formatPackages([
      { name: 'zeta', version: '1.0.0', direct: true },
      { name: 'alpha', version: '2.0.0', direct: true },
      { name: 'alpha', version: '1.0.0', direct: true },
      { name: 'alpha', version: '1.2.0', direct: false },
    ])
    expect(out).toBe(
      '`alpha@1.0.0`, `>alpha@1.2.0`, `alpha@2.0.0`, `zeta@1.0.0`',
    )
  })
})

describe('someVulnerabilities', () => {
  it('renders 2-column layout when details is undefined', () => {
    const report = makeReport({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 2, critical: 0 },
    })

    const out = someVulnerabilities('my-pkg', report)

    expect(out).toContain('## Vulnerabilities')
    expect(out).toContain('Vulnerabilities were found in **my-pkg**.')
    expect(out).toContain('<table>')
    expect(out).toContain('<tbody>')
    expect(out).toContain(`<tr>
  <th align="left">🟡 Moderate</th>
  <td>1</td>
</tr>`)
    expect(out).toContain(`<tr>
  <th align="left">🟠 High</th>
  <td>2</td>
</tr>`)
    expect(out).not.toContain('<td></td>')
  })

  it('renders 3-column layout when details is present', () => {
    const report = makeReport({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 2, critical: 0 },
      details: {
        moderate: [{ name: 'axios', version: '0.21.1', direct: true }],
        high: [
          { name: 'lodash', version: '4.17.20', direct: false },
          { name: 'axios', version: '0.21.1', direct: true },
        ],
      },
    })

    const out = someVulnerabilities('my-pkg', report)

    expect(out).toContain(`<tr>
  <th align="left">🟡 Moderate</th>
  <td>1</td>
  <td>\`axios@0.21.1\`</td>
</tr>`)
    expect(out).toContain(`<tr>
  <th align="left">🟠 High</th>
  <td>2</td>
  <td>\`axios@0.21.1\`, \`>lodash@4.17.20\`</td>
</tr>`)
  })

  it('renders an empty third <td> when details entry is missing or empty', () => {
    const report = makeReport({
      vulnerabilities: { info: 1, low: 0, moderate: 1, high: 0, critical: 0 },
      details: {
        moderate: [],
      },
    })

    const out = someVulnerabilities('my-pkg', report)

    expect(out).toContain(`<tr>
  <th align="left">⚪ Info</th>
  <td>1</td>
  <td></td>
</tr>`)
    expect(out).toContain(`<tr>
  <th align="left">🟡 Moderate</th>
  <td>1</td>
  <td></td>
</tr>`)
  })

  it('direct package renders without > prefix inline in row', () => {
    const report = makeReport({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0 },
      details: {
        moderate: [{ name: 'axios', version: '0.21.1', direct: true }],
      },
    })

    const out = someVulnerabilities('my-pkg', report)
    expect(out).toContain('`axios@0.21.1`')
    expect(out).not.toContain('`>axios@0.21.1`')
  })

  it('indirect package renders with > inside backticks and no space', () => {
    const report = makeReport({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 0, critical: 0 },
      details: {
        moderate: [{ name: 'lodash', version: '4.17.20', direct: false }],
      },
    })

    const out = someVulnerabilities('my-pkg', report)
    expect(out).toContain('`>lodash@4.17.20`')
    expect(out).not.toContain('`> lodash@4.17.20`')
  })
})
