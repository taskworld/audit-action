import * as core from '@actions/core'
import { context } from '@actions/github'
import { auditPR } from './audit-pr'
import type { DependencyAuditOptions } from '@taskworld/platform-audit'

async function run(): Promise<void> {
  try {
    const packageManager: DependencyAuditOptions['packageManager'] = core.getInput(
      'package-manager',
    ) as DependencyAuditOptions['packageManager']
    const identifier = core.getInput('identifier') ?? context.repo.repo

    if (context.eventName === 'pull_request') {
      const result = await auditPR(
        { path: process.env.GITHUB_WORKSPACE as string, packageManager },
        identifier,
      )

      core.setOutput('vulnerabilities', result.vulnerabilities)
    }
  } catch (error) {
    if (error instanceof Error) core.setFailed(error.message)
  }
}

run()
