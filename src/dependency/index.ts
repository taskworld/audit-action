import type { DependencyAuditOptions } from './types.js'

import { pnpmBulkAuditor } from './pnpmBulkAuditor.js'
import { yarnAuditor } from './yarnAuditor.js'

const DEPENDENCY_AUDITORS = {
  pnpm: pnpmBulkAuditor,
  yarn: yarnAuditor,
}

export async function auditDependencies(
  type: keyof typeof DEPENDENCY_AUDITORS,
  options?: DependencyAuditOptions,
) {
  return DEPENDENCY_AUDITORS[type](options)
}
