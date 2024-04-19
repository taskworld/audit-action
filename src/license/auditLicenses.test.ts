import { readFileSync } from 'fs'
import checker from 'license-checker'
import { resolve } from 'path'
import { afterEach, describe, expect, it, Mock, vi } from 'vitest'

import { auditLicenses } from './auditLicenses.js'

const AUDIT_PATH = resolve(__dirname, '../../')

vi.mock('license-checker', async (importOriginal) => {
  const actual = (await importOriginal()) as any

  const init = vi.fn((_, callback) => {
    const licenses = JSON.parse(readFileSync(resolve(__dirname, './licenses.fixture.json'), 'utf8'))

    callback(null, licenses)
  })

  return {
    ...actual,
    default: {
      ...actual.default,
      init,
    },
    init,
  }
})

describe('auditLicenses', () => {
  afterEach(() => {
    vi.restoreAllMocks()
  })

  it('audits licenses with license-checker', async () => {
    const result = await auditLicenses({
      path: AUDIT_PATH,
    })

    expect(result.licenses).toHaveLength(40)
    expect(checker.init).toHaveBeenCalled()
  })

  it('excludes packages by scopes', async () => {
    const result = await auditLicenses({
      path: AUDIT_PATH,
      excludePackageScopes: ['@taskworld'],
    })

    expect(result.licenses).toHaveLength(35)
  })

  it('excludes licenses', async () => {
    await auditLicenses({
      path: AUDIT_PATH,
      excludeLicenses: ['MIT', 'Apache-2.0'],
    })

    expect((checker.init as Mock).mock.lastCall[0].exclude).toBe('MIT,Apache-2.0')
  })
})
