import type { PNPMAuditReport, Severity } from 'audit-types'

import { $ } from '../utils.js'

import type { DependencyAuditOptions } from './types.js'

const BULK_ENDPOINT = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
const REQUEST_TIMEOUT_MS = 10_000
const MAX_BUFFER = 50 * 1024 * 1024

// -- Types for pnpm list output --

interface PnpmListEntry {
  dependencies?: Record<string, PnpmDepNode>
}

interface PnpmDepNode {
  version: string
  dependencies?: Record<string, PnpmDepNode>
}

// -- Types for bulk advisory response --

interface BulkAdvisory {
  severity: string
  vulnerable_versions: string
  title: string
}

type BulkAdvisoryResponse = Record<string, BulkAdvisory[]>

// ---------------------------------------------------------------------------
// Phase A: Collect all transitive production dependencies via pnpm list
// ---------------------------------------------------------------------------

export function buildDependencyMap(projects: PnpmListEntry[]): Record<string, string[]> {
  const deps: Record<string, string[]> = {}
  const seen = new Set<string>()

  function walk(tree: Record<string, PnpmDepNode> | undefined) {
    for (const [name, info] of Object.entries(tree ?? {})) {
      const key = `${name}@${info.version}`
      if (seen.has(key)) continue
      seen.add(key)
      if (!deps[name]) deps[name] = []
      if (!deps[name].includes(info.version)) deps[name].push(info.version)
      walk(info.dependencies)
    }
  }

  for (const project of projects) walk(project.dependencies)
  return deps
}

async function collectDependencies(cwd?: string): Promise<Record<string, string[]>> {
  const { stdout, stderr } = await $('pnpm list --prod --json --depth=Infinity', {
    cwd,
    maxBuffer: MAX_BUFFER,
  })

  if (stderr?.length > 0) {
    throw new Error(`pnpm list failed (${stderr})`)
  }

  const projects: PnpmListEntry[] = JSON.parse(stdout)
  return buildDependencyMap(projects)
}

// ---------------------------------------------------------------------------
// Phase B: POST to the bulk advisory endpoint
// ---------------------------------------------------------------------------

async function fetchAdvisories(deps: Record<string, string[]>): Promise<BulkAdvisoryResponse> {
  const res = await fetch(BULK_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(deps),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  })

  if (!res.ok) {
    const body = await res.text().catch(() => '')
    throw new Error(`Registry returned ${res.status}: ${body}`)
  }

  return res.json()
}

// ---------------------------------------------------------------------------
// Phase C: Map bulk advisory response to AuditMetadata
// ---------------------------------------------------------------------------

const SEVERITY_KEYS: Severity[] = ['info', 'low', 'moderate', 'high', 'critical']

export function mapToAuditMetadata(
  deps: Record<string, string[]>,
  advisories: BulkAdvisoryResponse,
): PNPMAuditReport.AuditMetadata {
  const vulnerabilities: Record<Severity, number> = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 }

  for (const pkg of Object.keys(advisories)) {
    for (const advisory of advisories[pkg]) {
      if (SEVERITY_KEYS.includes(advisory.severity as Severity)) {
        vulnerabilities[advisory.severity as Severity]++
      }
    }
  }

  const totalDependencies = Object.keys(deps).length

  return {
    vulnerabilities,
    dependencies: totalDependencies,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies,
  }
}

// ---------------------------------------------------------------------------
// Main auditor (same signature as before)
// ---------------------------------------------------------------------------

export async function pnpmAuditor(options?: DependencyAuditOptions) {
  const deps = await collectDependencies(options?.path)
  const advisories = await fetchAdvisories(deps)
  return mapToAuditMetadata(deps, advisories)
}
