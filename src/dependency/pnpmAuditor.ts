import type { PNPMAuditReport, Severity } from 'audit-types'

import { $ } from '../utils.js'

import type { DependencyAuditOptions, DependencyAuditReport, VulnerablePackage } from './types.js'

export async function pnpmAuditor(options?: DependencyAuditOptions): Promise<DependencyAuditReport> {
  const level = options?.level ?? 'low'
  const scope = options?.includeDevDeps ? '' : '--prod'

  const { stdout, stderr } = await $(`pnpm audit --audit-level ${level} ${scope} --json || true`, {
    cwd: options?.path,
  })

  if (stderr?.length > 0) {
    throw new Error(`pnpm audit failed (${stderr})`)
  }

  const report = JSON.parse(stdout) as PNPMAuditReport.Audit

  if (!options?.detailed) {
    return report?.metadata
  }

  return { ...report.metadata, details: buildDetails(report.advisories) }
}

function buildDetails(
  advisories: PNPMAuditReport.Audit['advisories'] | undefined,
): Partial<Record<Severity, VulnerablePackage[]>> {
  const details: Partial<Record<Severity, VulnerablePackage[]>> = {}
  const entries = Object.values(advisories ?? {}) as PNPMAuditReport.Advisory[]

  for (const advisory of entries) {
    const severity = advisory.severity
    for (const finding of advisory.findings ?? []) {
      const direct = (finding.paths ?? []).some((path: string) => (path.match(/>/g) ?? []).length === 1)
      const bucket = (details[severity] ??= [])
      const existing = bucket.find((pkg) => pkg.name === advisory.module_name && pkg.version === finding.version)
      if (existing) {
        existing.direct = existing.direct || direct
      } else {
        bucket.push({ name: advisory.module_name, version: finding.version, direct })
      }
    }
  }

  return details
}
