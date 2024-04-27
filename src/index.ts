import * as core from '@actions/core'
import { context } from '@actions/github'

import { auditDependencies } from './dependency/index.js'

import {
  hasVulnerabilities,
  isSeverityLevel,
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

  if (!isSeverityLevel(fail)) {
    throw new Error(`failure-level should be one of [${SEVERITY_LEVELS.join(', ')}]`)
  }

  if (!isPackageManager(pm)) {
    throw new Error(`'${pm}' is neither 'pnpm' or 'yarn'`)
  }

  const report = await auditDependencies(pm, {
    level: 'moderate',
    path: core.getInput('path') || process.env.GITHUB_WORKSPACE!,
  })

  core.info(`Report: ${JSON.stringify(report, null, 2)}`)

  if (!hasVulnerabilities(report)) {
    core.setOutput('vulnerabilities', noVulnerabilities(name))
    return
  }

  core.setOutput('vulnerabilities', someVulnerabilities(name, report.vulnerabilities))

  if (hasVulnerabilities(report, fail)) {
    core.setFailed('The audit concluded that vulnerabilities were too critical to be allowed.')
  }
}

// bootstrap
if (context.eventName === 'pull_request') {
  try {
    run()
  } catch (error) {
    if (typeof error === 'string' || error instanceof Error) {
      core.setFailed(error)
    } else {
      console.error(error)
    }
  }
}
