import { readFileSync } from 'fs'
import { resolve } from 'path'
import { describe, expect, it, vi } from 'vitest'

import { pnpmAuditor } from './pnpmAuditor.js'

let output = {}

vi.mock('../utils.js', () => ({
  $: vi.fn(async () => output),
}))

describe('pnpmAuditor', () => {
  it('performs audit with PNPM', async () => {
    output = {
      stdout: readFileSync(resolve(__dirname, './pnpmAuditor.fixture.json'), 'utf8'),
      stderr: '',
    }

    const report = await pnpmAuditor()

    expect(report).toEqual({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 4, critical: 0 },
      dependencies: 302,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 302,
    })
  })

  it('performs audit with PNPM', async () => {
    output = {
      stderr: '!',
    }

    await expect(pnpmAuditor()).rejects.toThrow(/pnpm audit failed/)
  })

  it('returns detailed report when detailed option is enabled', async () => {
    output = {
      stdout: readFileSync(resolve(__dirname, './pnpmAuditor.fixture.json'), 'utf8'),
      stderr: '',
    }

    const report = await pnpmAuditor({ path: '.', detailed: true })

    expect(report.vulnerabilities).toEqual({ info: 0, low: 0, moderate: 1, high: 4, critical: 0 })
    expect(report.details?.moderate).toEqual([{ name: 'class-validator', version: '0.13.1', direct: false }])
    expect(report.details?.high).toEqual([
      { name: 'dicer', version: '0.2.5', direct: false },
      { name: 'axios', version: '0.21.1', direct: false },
      { name: 'mongoose', version: '6.2.2', direct: true },
      { name: 'protobufjs', version: '6.11.2', direct: false },
    ])
    expect(report.details?.low).toBeUndefined()
    expect(report.details?.critical).toBeUndefined()
    expect(report.details?.info).toBeUndefined()
  })
})
