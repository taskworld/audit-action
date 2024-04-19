import { readFileSync } from 'fs'
import { resolve } from 'path'
import { describe, expect, it, vi } from 'vitest'

import { yarnAuditor } from './yarnAuditor.js'

vi.mock('../utils.js', () => ({
  $: vi.fn(async () => ({
    stdout: readFileSync(resolve(__dirname, './yarnAuditor.fixture.json'), 'utf8'),
  })),
}))

describe('yarnAuditor', () => {
  it('performs audit with Yarn', async () => {
    const report = await yarnAuditor()

    expect(report).toEqual({
      vulnerabilities: { info: 0, low: 0, moderate: 7, high: 8, critical: 1 },
      dependencies: 664,
      devDependencies: 0,
      optionalDependencies: 0,
      totalDependencies: 664,
    })
  })
})
