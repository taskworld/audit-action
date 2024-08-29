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
})
