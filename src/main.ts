import * as core from '@actions/core'
import { context } from '@actions/github'
import { auditPR } from './audit-pr'
import type { DependencyAuditOptions, SeverityLevel } from './types'

async function run(): Promise<void> {
  try {
    const path: string = core.getInput('path') ?? (process.env.GITHUB_WORKSPACE as string)
    const packageManager: DependencyAuditOptions['packageManager'] =
      (core.getInput('package-manager') as DependencyAuditOptions['packageManager']) ?? 'pnpm'
    const identifier = core.getInput('identifier') ?? context.repo.repo

    if (context.eventName === 'pull_request') {
      const failureLevel =
        core.getInput('failureLevel') !== ''
          ? (core.getInput('failureLevel') as SeverityLevel)
          : undefined

      const result = await auditPR(
        { packageManager, path, level: 'moderate' },
        identifier,
        failureLevel,
      )

      core.setOutput('vulnerabilities', result.vulnerabilities)
      core.setOutput('failed', result.failed)
    }
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}

run()
