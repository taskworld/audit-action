import { readFileSync } from 'node:fs'

import type { PNPMAuditReport, Severity } from 'audit-types'

import { $ } from '../utils.js'

import type { DependencyAuditOptions } from './types.js'

const BULK_ENDPOINT = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
const REQUEST_TIMEOUT_MS = 10_000
const MAX_BUFFER = 20 * 1024 * 1024

type DependencyMap = Map<string, Set<string>>

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
// Uses --parseable to get flat file paths instead of --json which produces
// a massive recursive tree with duplicated subtrees for large monorepos.
// Reads each package's package.json for reliable name+version.

export function buildDependencyMap(parseableOutput: string): DependencyMap {
  const deps: DependencyMap = new Map()

  for (const line of parseableOutput.split('\n')) {
    if (!line.includes('/node_modules/')) continue

    let pkg: { name?: string; version?: string }
    try {
      pkg = JSON.parse(readFileSync(line + '/package.json', 'utf8'))
    } catch {
      continue
    }
    if (!pkg.name || !pkg.version) continue

    let versions = deps.get(pkg.name)
    if (!versions) {
      versions = new Set()
      deps.set(pkg.name, versions)
    }
    versions.add(pkg.version)
  }

  return deps
}

async function collectDependencies(cwd?: string): Promise<DependencyMap> {
  const { stdout, stderr } = await $('pnpm list --prod --parseable --depth=Infinity || true', {
    cwd,
    maxBuffer: MAX_BUFFER,
  })

  if (stderr?.length > 0) {
    throw new Error(`pnpm list failed (${stderr})`)
  }

  return buildDependencyMap(stdout)
}

// ---------------------------------------------------------------------------
// Phase B: POST to the bulk advisory endpoint
// ---------------------------------------------------------------------------

function depsToPayload(deps: DependencyMap): Record<string, string[]> {
  const payload: Record<string, string[]> = {}
  for (const [name, versions] of deps) {
    payload[name] = [...versions]
  }
  return payload
}

async function fetchAdvisories(deps: DependencyMap): Promise<BulkAdvisoryResponse> {
  const res = await fetch(BULK_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(depsToPayload(deps)),
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
  deps: DependencyMap,
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

  const totalDependencies = deps.size

  return {
    vulnerabilities,
    dependencies: totalDependencies,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies,
  }
}

// ---------------------------------------------------------------------------
// Main auditor — uses bulk advisory API instead of pnpm audit
// ---------------------------------------------------------------------------

export async function pnpmBulkAuditor(options?: DependencyAuditOptions) {
  const deps = await collectDependencies(options?.path)
  const advisories = await fetchAdvisories(deps)
  return mapToAuditMetadata(deps, advisories)
}
