import * as core from '@actions/core'
import { context } from '@actions/github'

import { auditDependencies, RegistryUnavailableError } from './dependency/index.js'

import {
  hasVulnerabilities,
  isSeverityLevel,
  listVulnerablePackages,
  noVulnerabilities,
  SEVERITY_LEVELS,
  someVulnerabilities,
} from './vulnerabilities/index.js'

function isPackageManager(str: string): str is 'pnpm' | 'yarn' {
  return ['pnpm', 'yarn'].includes(str)
}

async function run() {
  const fail = core.getInput('failure-level') || 'low'
  const name = core.getInput('package-name') || context.repo.repo
  const pm = core.getInput('package-manager')
  const includeDevDeps = core.getInput('include-dev-deps').toLowerCase() === 'true'
  const detailed = core.getInput('detailed-report').toLowerCase() === 'true'

  if (!isSeverityLevel(fail)) {
    throw new Error(`failure-level should be one of [${SEVERITY_LEVELS.join(', ')}]`)
  }

  if (!isPackageManager(pm)) {
    throw new Error(`'${pm}' is neither 'pnpm' or 'yarn'`)
  }

  const report = await auditDependencies(pm, {
    level: 'moderate',
    path: core.getInput('path') || process.env.GITHUB_WORKSPACE!,
    includeDevDeps,
    detailed,
  }).catch((error: unknown) => {
    if (error instanceof RegistryUnavailableError) {
      core.setOutput('registry-unavailable', 'true')
      throw new Error(
        `The audit could not run: the npm advisory registry was unreachable. This is an infrastructure failure, not a vulnerability. ${error.message}`,
        { cause: error },
      )
    }
    throw error
  })

  core.setOutput('registry-unavailable', 'false')
  core.info(`Report: ${JSON.stringify(report, null, 2)}`)
  core.setOutput('vulnerable-packages', JSON.stringify(listVulnerablePackages(report)))

  if (!hasVulnerabilities(report)) {
    core.setOutput('failed', 'false')
    core.setOutput('vulnerabilities', noVulnerabilities(name))
    return
  }

  core.setOutput('vulnerabilities', someVulnerabilities(name, report))
  core.setOutput('failed', String(hasVulnerabilities(report, fail)))
}

// bootstrap
if (context.eventName === 'pull_request') {
  run().catch((error) => {
    if (typeof error === 'string' || error instanceof Error) {
      if (error instanceof Error && error.cause) core.info(`Caused by: ${String(error.cause)}`)
      core.setFailed(error)
    } else {
      console.error(error)
    }
  })
}
