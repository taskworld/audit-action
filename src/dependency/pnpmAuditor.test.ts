import { readFileSync } from 'fs'
import { resolve } from 'path'
import { describe, expect, it, vi } from 'vitest'

import { buildDependencyMap, mapToAuditMetadata, pnpmAuditor } from './pnpmAuditor.js'

const pnpmListFixture = readFileSync(resolve(__dirname, './pnpmAuditor.fixture.json'), 'utf8')
const bulkAdvisoryFixture = readFileSync(resolve(__dirname, './bulkAdvisory.fixture.json'), 'utf8')

let execOutput: { stdout?: string; stderr?: string } = {}

vi.mock('../utils.js', () => ({
  $: vi.fn(async () => execOutput),
}))

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

describe('buildDependencyMap', () => {
  it('walks dependency tree and collects unique packages', () => {
    const projects = JSON.parse(pnpmListFixture)
    const deps = buildDependencyMap(projects)

    expect(Object.keys(deps)).toEqual(['express', 'body-parser', 'bytes', 'cookie', 'axios', 'lodash'])
    expect(deps['express']).toEqual(['4.17.1'])
    expect(deps['body-parser']).toEqual(['1.19.0'])
    expect(deps['bytes']).toEqual(['3.1.0'])
  })

  it('returns empty map for empty project list', () => {
    expect(buildDependencyMap([])).toEqual({})
  })

  it('deduplicates packages seen at multiple paths', () => {
    const projects = [
      {
        dependencies: {
          shared: {
            version: '1.0.0',
            dependencies: {},
          },
        },
      },
      {
        dependencies: {
          shared: {
            version: '1.0.0',
            dependencies: {},
          },
        },
      },
    ]
    const deps = buildDependencyMap(projects)
    expect(deps['shared']).toEqual(['1.0.0'])
  })
})

describe('mapToAuditMetadata', () => {
  it('counts advisories by severity', () => {
    const deps = { axios: ['0.21.1'], lodash: ['4.17.20'] }
    const advisories = JSON.parse(bulkAdvisoryFixture)

    const metadata = mapToAuditMetadata(deps, advisories)

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
    const deps = { express: ['4.18.2'] }
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
    const deps = { foo: ['1.0.0'] }
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

describe('pnpmAuditor', () => {
  it('collects deps and fetches advisories end-to-end', async () => {
    execOutput = { stdout: pnpmListFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => JSON.parse(bulkAdvisoryFixture),
    })

    const report = await pnpmAuditor()

    expect(report).toEqual({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 1, critical: 1 },
      dependencies: 6,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 6,
    })
  })

  it('returns zero vulnerabilities when registry has no advisories', async () => {
    execOutput = { stdout: pnpmListFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => ({}),
    })

    const report = await pnpmAuditor()

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

    await expect(pnpmAuditor()).rejects.toThrow(/pnpm list failed/)
  })

  it('throws when registry returns non-200', async () => {
    execOutput = { stdout: pnpmListFixture, stderr: '' }
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      text: async () => 'Service Unavailable',
    })

    await expect(pnpmAuditor()).rejects.toThrow(/Registry returned 503/)
  })
})
