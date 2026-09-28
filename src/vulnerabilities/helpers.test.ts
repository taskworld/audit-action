import { describe, expect, it } from 'vitest'

import type { DependencyAuditReport } from '../dependency/types'

import { listVulnerablePackages } from './helpers.js'

const base: DependencyAuditReport = {
  vulnerabilities: { info: 0, low: 1, moderate: 0, high: 2, critical: 1 },
  dependencies: 0,
  devDependencies: 0,
  optionalDependencies: 0,
  totalDependencies: 0,
}

describe('listVulnerablePackages', () => {
  it('returns an empty list without details', () => {
    expect(listVulnerablePackages(base)).toEqual([])
  })

  it('flattens details most severe first, then by name and version', () => {
    const list = listVulnerablePackages({
      ...base,
      details: {
        low: [{ name: 'bytes', version: '3.1.0', direct: false, path: 'a@1 > bytes@3.1.0' }],
        high: [
          { name: 'zeta', version: '1.0.0', direct: true, path: 'zeta@1.0.0' },
          { name: 'axios', version: '0.21.1', direct: true, path: 'axios@0.21.1' },
        ],
        critical: [{ name: 'lodash', version: '4.17.20', direct: true, path: 'lodash@4.17.20' }],
      },
    })

    expect(list.map((p) => `${p.severity}:${p.name}`)).toEqual([
      'critical:lodash',
      'high:axios',
      'high:zeta',
      'low:bytes',
    ])
    expect(list[3]).toEqual({
      severity: 'low',
      name: 'bytes',
      version: '3.1.0',
      direct: false,
      path: 'a@1 > bytes@3.1.0',
    })
  })
})
