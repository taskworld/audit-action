import { describe, expect, it, vi } from 'vitest'

// -- Inline fixtures --

const parseableFixture = [
  '/app',
  '/app/node_modules/express',
  '/app/node_modules/express/node_modules/body-parser',
  '/app/node_modules/express/node_modules/body-parser/node_modules/bytes',
  '/app/node_modules/express/node_modules/cookie',
  '/app/node_modules/axios',
  '/app/node_modules/lodash',
].join('\n')

const bulkAdvisoryFixture = {
  axios: [
    {
      id: 1081813,
      severity: 'high',
      vulnerable_versions: '<0.21.2',
      title: 'Inefficient Regular Expression Complexity in axios',
      url: 'https://github.com/advisories/GHSA-cph5-m8f7-6c5x',
    },
  ],
  lodash: [
    {
      id: 1085000,
      severity: 'critical',
      vulnerable_versions: '<4.17.21',
      title: 'Prototype Pollution in lodash',
      url: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx',
    },
    {
      id: 1085001,
      severity: 'moderate',
      vulnerable_versions: '<4.17.21',
      title: 'Regular Expression Denial of Service in lodash',
      url: 'https://github.com/advisories/GHSA-yyyy-yyyy-yyyy',
    },
  ],
}

const FAKE_PACKAGES: Record<string, { name: string; version: string }> = {
  '/app/node_modules/express': { name: 'express', version: '4.17.1' },
  '/app/node_modules/express/node_modules/body-parser': { name: 'body-parser', version: '1.19.0' },
  '/app/node_modules/express/node_modules/body-parser/node_modules/bytes': { name: 'bytes', version: '3.1.0' },
  '/app/node_modules/express/node_modules/cookie': { name: 'cookie', version: '0.4.1' },
  '/app/node_modules/axios': { name: 'axios', version: '0.21.1' },
  '/app/node_modules/lodash': { name: 'lodash', version: '4.17.20' },
}

// Mock node:fs readFileSync used by buildDependencyMap to read package.json files.
vi.mock('node:fs', () => ({
  readFileSync: vi.fn((path: string) => {
    const dir = path.replace(/\/package\.json$/, '')
    const pkg = FAKE_PACKAGES[dir]
    if (!pkg) throw new Error(`ENOENT: ${path}`)
    return JSON.stringify(pkg)
  }),
}))

import { buildDependencyMap, mapToAuditMetadata, pnpmBulkAuditor } from './pnpmBulkAuditor.js'

let execOutput: { stdout?: string; stderr?: string } = {}

vi.mock('../utils.js', () => ({
  $: vi.fn(async () => execOutput),
}))

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

describe('buildDependencyMap', () => {
  it('parses parseable output and collects unique packages', () => {
    const deps = buildDependencyMap(parseableFixture)

    expect([...deps.keys()].sort()).toEqual(['axios', 'body-parser', 'bytes', 'cookie', 'express', 'lodash'])
    expect(deps.get('express')).toEqual(new Set(['4.17.1']))
    expect(deps.get('body-parser')).toEqual(new Set(['1.19.0']))
    expect(deps.get('bytes')).toEqual(new Set(['3.1.0']))
  })

  it('returns empty map for empty output', () => {
    expect(buildDependencyMap('')).toEqual(new Map())
  })

  it('skips lines without node_modules', () => {
    const deps = buildDependencyMap('/app\n/app/node_modules/express\n')
    expect(deps.size).toBe(1)
    expect(deps.has('express')).toBe(true)
  })

  it('deduplicates same package appearing at multiple paths', () => {
    const input = ['/app/node_modules/express', '/app/other/node_modules/express'].join('\n')
    const deps = buildDependencyMap(input)
    expect(deps.get('express')).toEqual(new Set(['4.17.1']))
  })
})

describe('mapToAuditMetadata', () => {
  it('counts advisories by severity', () => {
    const deps = new Map([
      ['axios', new Set(['0.21.1'])],
      ['lodash', new Set(['4.17.20'])],
    ])

    const metadata = mapToAuditMetadata(deps, bulkAdvisoryFixture)

    expect(metadata.vulnerabilities).toEqual({
      info: 0,
      low: 0,
      moderate: 1,
      high: 1,
      critical: 1,
    })
    expect(metadata.dependencies).toBe(2)
    expect(metadata.totalDependencies).toBe(2)
    expect(metadata.devDependencies).toBe(0)
    expect(metadata.optionalDependencies).toBe(0)
  })

  it('returns all zeros when no advisories found', () => {
    const deps = new Map([['express', new Set(['4.18.2'])]])
    const metadata = mapToAuditMetadata(deps, {})

    expect(metadata.vulnerabilities).toEqual({
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
    })
    expect(metadata.dependencies).toBe(1)
  })

  it('ignores unknown severity values', () => {
    const deps = new Map([['foo', new Set(['1.0.0'])]])
    const advisories = {
      foo: [{ severity: 'unknown', vulnerable_versions: '*', title: 'test' }],
    }
    const metadata = mapToAuditMetadata(deps, advisories)

    expect(metadata.vulnerabilities).toEqual({
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
    })
  })
})

describe('pnpmBulkAuditor', () => {
  it('collects deps and fetches advisories end-to-end', async () => {
    execOutput = { stdout: parseableFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => bulkAdvisoryFixture,
    })

    const report = await pnpmBulkAuditor()

    expect(report).toEqual({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 1, critical: 1 },
      dependencies: 6,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 6,
    })
  })

  it('returns zero vulnerabilities when registry has no advisories', async () => {
    execOutput = { stdout: parseableFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    })

    const report = await pnpmBulkAuditor()

    expect(report.vulnerabilities).toEqual({
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
    })
  })

  it('throws when pnpm list fails', async () => {
    execOutput = { stdout: '', stderr: 'ERR_PNPM_NO_MATCHING_VERSION' }

    await expect(pnpmBulkAuditor()).rejects.toThrow(/pnpm list failed/)
  })

  it('throws when registry returns non-200', async () => {
    execOutput = { stdout: parseableFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      text: async () => 'Service Unavailable',
    })

    await expect(pnpmBulkAuditor()).rejects.toThrow(/Registry returned 503/)
  })
})
