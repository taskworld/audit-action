import type { PNPMAuditReport } from 'audit-types'

import { $ } from '../utils.js'

import type { DependencyAuditOptions } from './types.js'

export async function pnpmAuditor(options?: DependencyAuditOptions) {
  const level = options?.level ?? 'low'

  const { stdout, stderr } = await $(`pnpm audit --audit-level ${level} --prod --json || true`, {
    cwd: options?.path,
  })

  if (stderr?.length > 0) {
    throw new Error(`pnpm audit failed (${stderr})`)
  }

  const report = JSON.parse(stdout) as PNPMAuditReport.Audit

  return report?.metadata
}
