import type { PNPMAuditReport } from 'audit-types'

import { $ } from '../utils.js'

import type { DependencyAuditOptions } from './types.js'

export interface YarnAuditReport {
  type: 'auditSummary'
  data: PNPMAuditReport.AuditMetadata
}

function isYarnAuditSummary(arg: unknown): arg is YarnAuditReport {
  return (
    !!arg &&
    typeof arg === 'object' &&
    'type' in arg &&
    arg.type === 'auditSummary' &&
    'data' in arg &&
    !!arg.data
  )
}

export async function yarnAuditor(options?: DependencyAuditOptions) {
  const level = options?.level ?? 'low'

  const { stdout } = await $(`yarn audit --level ${level} --groups dependencies --json`, {
    cwd: options?.path,
  })

  const report = stdout
    .split(/\n|\n\r/)
    .filter(Boolean)
    .map((json) => JSON.parse(json))
    .find(({ type }) => type === 'auditSummary')

  if (!isYarnAuditSummary(report)) {
    throw new Error('audit summary is not found')
  }

  return report.data
}
