import { readFileSync } from 'fs'
import { resolve } from 'path'
import { describe, expect, it, vi } from 'vitest'

import { pnpmAuditor } from './pnpmAuditor.js'

vi.mock('../utils.js', () => ({
  $: vi.fn(async () => ({
    stdout: readFileSync(resolve(__dirname, './pnpmAuditor.fixture.json'), 'utf8'),
  })),
}))

describe('pnpmAuditor', () => {
  it('performs audit with PNPM', async () => {
    const report = await pnpmAuditor()

    expect(report).toEqual({
      vulnerabilities: { info: 0, low: 0, moderate: 1, high: 4, critical: 0 },
      dependencies: 302,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 302,
    })
  })
})
