import { describe, expect, it, vi } from 'vitest'

// -- Inline fixtures --

// A minimal pnpm-lock.yaml (v9) whose production closure is:
// express -> body-parser -> bytes, express -> cookie, plus axios and lodash.
const lockfileYaml = `
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      express:
        specifier: ^4.17.1
        version: 4.17.1
      axios:
        specifier: ^0.21.1
        version: 0.21.1
      lodash:
        specifier: ^4.17.20
        version: 4.17.20
    devDependencies:
      vitest:
        specifier: ^4.0.0
        version: 4.0.0

snapshots:

  express@4.17.1:
    dependencies:
      body-parser: 1.19.0
      cookie: 0.4.1

  body-parser@1.19.0:
    dependencies:
      bytes: 3.1.0

  cookie@0.4.1: {}

  bytes@3.1.0: {}

  axios@0.21.1: {}

  lodash@4.17.20: {}

  vitest@4.0.0:
    dependencies:
      lodash: 4.17.21
`

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

let rootPackageJson: object | null = null
let lockfileExists = true

// Mock node:fs: findLockfile probes existsSync, then readFileSync loads the
// lockfile and (in detailed mode) the project package.json.
vi.mock('node:fs', () => ({
  existsSync: vi.fn((path: string) => lockfileExists && path.endsWith('pnpm-lock.yaml')),
  readFileSync: vi.fn((path: string) => {
    if (path.endsWith('pnpm-lock.yaml')) return lockfileYaml
    if (rootPackageJson && path.endsWith('package.json')) return JSON.stringify(rootPackageJson)
    throw new Error(`ENOENT: ${path}`)
  }),
}))

import {
  collectFromLockfile,
  mapToAuditMetadata,
  pnpmBulkAuditor,
  toImporterKey,
} from './pnpmBulkAuditor.js'

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

describe('toImporterKey', () => {
  it('returns "." when the target is the lockfile directory', () => {
    expect(toImporterKey('/repo', '/repo')).toBe('.')
  })

  it('returns a POSIX-relative path for workspace members', () => {
    expect(toImporterKey('/repo', '/repo/client')).toBe('client')
    expect(toImporterKey('/repo', '/repo/packages/api')).toBe('packages/api')
  })
})

describe('collectFromLockfile', () => {
  const lockfile = {
    importers: {
      '.': {
        dependencies: {
          express: { specifier: '^4.17.1', version: '4.17.1' },
          axios: { specifier: '^0.21.1', version: '0.21.1' },
          lodash: { specifier: '^4.17.20', version: '4.17.20' },
        },
        devDependencies: {
          vitest: { specifier: '^4.0.0', version: '4.0.0' },
        },
      },
    },
    snapshots: {
      'express@4.17.1': { dependencies: { 'body-parser': '1.19.0', cookie: '0.4.1' } },
      'body-parser@1.19.0': { dependencies: { bytes: '3.1.0' } },
      'cookie@0.4.1': {},
      'bytes@3.1.0': {},
      'axios@0.21.1': {},
      'lodash@4.17.20': {},
      'vitest@4.0.0': { dependencies: { lodash: '4.17.21' } },
    },
  }

  it('walks the production closure transitively', () => {
    const deps = collectFromLockfile(lockfile, '.', false)

    expect([...deps.keys()].sort()).toEqual([
      'axios',
      'body-parser',
      'bytes',
      'cookie',
      'express',
      'lodash',
    ])
    expect(deps.get('bytes')).toEqual(new Set(['3.1.0']))
  })

  it('excludes devDependencies and their subtree by default', () => {
    const deps = collectFromLockfile(lockfile, '.', false)

    expect(deps.has('vitest')).toBe(false)
    // lodash@4.17.21 is only reachable through the dev-only vitest snapshot.
    expect(deps.get('lodash')).toEqual(new Set(['4.17.20']))
  })

  it('includes devDependencies (and their subtree) when requested', () => {
    const deps = collectFromLockfile(lockfile, '.', true)

    expect(deps.has('vitest')).toBe(true)
    expect(deps.get('lodash')).toEqual(new Set(['4.17.20', '4.17.21']))
  })

  it('strips peer/patch suffixes from snapshot versions', () => {
    const withSuffix = {
      importers: {
        '.': { dependencies: { foo: { specifier: '^1', version: '1.2.3(react@18.3.1)' } } },
      },
      snapshots: { 'foo@1.2.3(react@18.3.1)': {} },
    }
    const deps = collectFromLockfile(withSuffix, '.', false)
    expect(deps.get('foo')).toEqual(new Set(['1.2.3']))
  })

  it('skips workspace link / file references', () => {
    const withLink = {
      importers: {
        '.': { dependencies: { '@repo/ui': { specifier: 'workspace:*', version: 'link:../ui' } } },
      },
      snapshots: {},
    }
    const deps = collectFromLockfile(withLink, '.', false)
    expect(deps.size).toBe(0)
  })

  it('throws when the importer key is missing', () => {
    expect(() => collectFromLockfile(lockfile, 'client', false)).toThrow(
      /Importer 'client' not found/,
    )
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

  describe('detailed mode', () => {
    it('assigns direct/indirect flags based on directSet', () => {
      const deps = new Map([
        ['axios', new Set(['0.21.1'])],
        ['lodash', new Set(['4.17.20'])],
      ])
      const directSet = new Set(['axios'])

      const metadata = mapToAuditMetadata(deps, bulkAdvisoryFixture, directSet)

      expect(metadata.details?.high).toEqual([{ name: 'axios', version: '0.21.1', direct: true }])
      expect(metadata.details?.critical).toEqual([
        { name: 'lodash', version: '4.17.20', direct: false },
      ])
      expect(metadata.details?.moderate).toEqual([
        { name: 'lodash', version: '4.17.20', direct: false },
      ])
    })

    it('deduplicates when a package has multiple advisories of the same severity', () => {
      const deps = new Map([['lodash', new Set(['4.17.20'])]])
      const advisories = {
        lodash: [
          { severity: 'critical', vulnerable_versions: '<4.17.21', title: 'A' },
          { severity: 'critical', vulnerable_versions: '<4.17.22', title: 'B' },
        ],
      }

      const metadata = mapToAuditMetadata(deps, advisories, new Set())

      expect(metadata.details?.critical).toEqual([
        { name: 'lodash', version: '4.17.20', direct: false },
      ])
      expect(metadata.vulnerabilities.critical).toBe(2)
    })

    it('filters out advisories whose vulnerable_versions do not match any installed version', () => {
      const deps = new Map([['axios', new Set(['1.5.0'])]])
      const advisories = {
        axios: [{ severity: 'high', vulnerable_versions: '<0.21.2', title: 'old only' }],
      }

      const metadata = mapToAuditMetadata(deps, advisories, new Set(['axios']))

      expect(metadata.details?.high).toBeUndefined()
      expect(metadata.vulnerabilities.high).toBe(0)
    })

    it('includes multiple installed versions when all match', () => {
      const deps = new Map([['lodash', new Set(['4.17.20', '4.17.19'])]])
      const advisories = {
        lodash: [{ severity: 'critical', vulnerable_versions: '<4.17.21', title: 'A' }],
      }

      const metadata = mapToAuditMetadata(deps, advisories, new Set())

      expect(metadata.details?.critical).toEqual(
        expect.arrayContaining([
          { name: 'lodash', version: '4.17.20', direct: false },
          { name: 'lodash', version: '4.17.19', direct: false },
        ]),
      )
      expect(metadata.details?.critical).toHaveLength(2)
    })
  })
})

describe('pnpmBulkAuditor', () => {
  it('collects the prod closure from the lockfile and fetches advisories end-to-end', async () => {
    lockfileExists = true
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
    lockfileExists = true
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

  it('throws when no lockfile can be found', async () => {
    lockfileExists = false
    try {
      await expect(pnpmBulkAuditor()).rejects.toThrow(/Could not find pnpm-lock\.yaml/)
    } finally {
      lockfileExists = true
    }
  })

  it('throws when the registry returns non-200', async () => {
    lockfileExists = true
    fetchMock.mockResolvedValueOnce({
      ok: false,
      status: 503,
      text: async () => 'Service Unavailable',
    })

    await expect(pnpmBulkAuditor()).rejects.toThrow(/Registry returned 503/)
  })

  it('produces a detailed report with direct/indirect flags when options.detailed is true', async () => {
    lockfileExists = true
    fetchMock.mockResolvedValueOnce({
      ok: true,
      json: async () => bulkAdvisoryFixture,
    })
    rootPackageJson = { dependencies: { axios: '^0.21', express: '^4' } }

    try {
      const report = await pnpmBulkAuditor({ path: '/app', detailed: true })

      expect(report.details?.high).toEqual([{ name: 'axios', version: '0.21.1', direct: true }])
      expect(report.details?.critical).toEqual([
        { name: 'lodash', version: '4.17.20', direct: false },
      ])
      expect(report.details?.moderate).toEqual([
        { name: 'lodash', version: '4.17.20', direct: false },
      ])
      expect(report.vulnerabilities).toEqual({
        info: 0,
        low: 0,
        moderate: 1,
        high: 1,
        critical: 1,
      })
    } finally {
      rootPackageJson = null
    }
  })
})
