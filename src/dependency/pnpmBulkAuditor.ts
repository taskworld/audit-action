import { existsSync, readFileSync } from 'node:fs'
import { dirname, join, relative, resolve, sep } from 'node:path'

import type { Severity } from 'audit-types'
import semver from 'semver'
import { parse as parseYaml } from 'yaml'

import type { BulkAdvisoryResponse } from './registryClient.js'
import type { DependencyAuditOptions, DependencyAuditReport, VulnerablePackage } from './types.js'

import { fetchBulkAdvisories } from './registryClient.js'

const LOCKFILE_NAME = 'pnpm-lock.yaml'

type DependencyMap = Map<string, Set<string>>
type ParentMap = Map<string, string | undefined>

// -- Types for the pnpm-lock.yaml sections we consume --

interface LockfileDependency {
  specifier: string
  version: string
}

interface LockfileImporter {
  dependencies?: Record<string, LockfileDependency>
  optionalDependencies?: Record<string, LockfileDependency>
  devDependencies?: Record<string, LockfileDependency>
}

interface LockfileSnapshot {
  dependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
}

interface Lockfile {
  importers?: Record<string, LockfileImporter>
  snapshots?: Record<string, LockfileSnapshot>
}

// ---------------------------------------------------------------------------
// Phase A: Collect the dependency closure from pnpm-lock.yaml
// ---------------------------------------------------------------------------
// The lockfile is the only reliable source of the production closure. Both
// `pnpm list --prod --parseable` (enumerates the shared .pnpm store, so `--prod`
// leaks dev/build packages under a workspace or shamefullyHoist) and
// `pnpm list --prod --json` (deduplicates subtrees, dropping packages that only
// appear under deduped nodes) misreport. We walk `importers.<key>` through the
// `snapshots` graph instead, which is hoisting- and store-layout-independent.

// Walk up from `startDir` until the workspace lockfile is found.
export function findLockfile(startDir: string): string | undefined {
  let dir = resolve(startDir)
  for (;;) {
    const candidate = join(dir, LOCKFILE_NAME)
    if (existsSync(candidate)) return candidate
    const parent = dirname(dir)
    if (parent === dir) return undefined
    dir = parent
  }
}

// Importer keys are POSIX-relative paths from the lockfile directory ('.' = root).
export function toImporterKey(lockfileDir: string, targetDir: string): string {
  const rel = relative(resolve(lockfileDir), resolve(targetDir)).split(sep).join('/')
  return rel === '' ? '.' : rel
}

// Strip pnpm peer/patch suffixes: "1.2.3(react@18.3.1)" -> "1.2.3".
function cleanVersion(version: string): string {
  const paren = version.indexOf('(')
  return (paren === -1 ? version : version.slice(0, paren)).trim()
}

// Workspace links, local files and git refs have no registry advisories.
function isRegistryVersion(version: string): boolean {
  return !version.startsWith('link:') && !version.startsWith('file:') && !version.startsWith('git')
}

export function collectFromLockfile(
  lockfile: Lockfile,
  importerKey: string,
  includeDevDeps: boolean,
  parents?: ParentMap,
): DependencyMap {
  const importer = lockfile.importers?.[importerKey]
  if (!importer) {
    const available = Object.keys(lockfile.importers ?? {}).join(', ') || 'none'
    throw new Error(
      `Importer '${importerKey}' not found in ${LOCKFILE_NAME} (available: ${available})`,
    )
  }

  const snapshots = lockfile.snapshots ?? {}
  const deps: DependencyMap = new Map()
  const visited = new Set<string>()
  const queue: Array<{ name: string; version: string; parent?: string }> = []

  const enqueueDirect = (record?: Record<string, LockfileDependency>) => {
    for (const [name, dep] of Object.entries(record ?? {})) {
      queue.push({ name, version: dep.version })
    }
  }
  enqueueDirect(importer.dependencies)
  enqueueDirect(importer.optionalDependencies)
  if (includeDevDeps) enqueueDirect(importer.devDependencies)

  for (let i = 0; i < queue.length; i++) {
    const { name, version, parent } = queue[i]
    if (!isRegistryVersion(version)) continue

    // Snapshot keys use the full suffixed version (e.g. "foo@1.2.3(react@18.3.1)").
    const snapshotKey = `${name}@${version}`
    if (visited.has(snapshotKey)) continue
    visited.add(snapshotKey)

    const clean = cleanVersion(version)
    if (clean) {
      let versions = deps.get(name)
      if (!versions) {
        versions = new Set()
        deps.set(name, versions)
      }
      versions.add(clean)
    }

    const id = `${name}@${clean}`
    if (parents && !parents.has(id)) parents.set(id, parent)

    const snapshot = snapshots[snapshotKey]
    if (!snapshot) continue
    for (const [childName, childVersion] of Object.entries(snapshot.dependencies ?? {})) {
      queue.push({ name: childName, version: childVersion, parent: id })
    }
    for (const [childName, childVersion] of Object.entries(snapshot.optionalDependencies ?? {})) {
      queue.push({ name: childName, version: childVersion, parent: id })
    }
  }

  return deps
}

export function dependencyPath(parents: ParentMap, id: string): string {
  const chain = [id]
  for (let parent = parents.get(id); parent; parent = parents.get(parent)) chain.unshift(parent)
  return chain.join(' > ')
}

function collectDependencies(
  cwd: string | undefined,
  includeDevDeps: boolean,
  parents?: ParentMap,
): DependencyMap {
  const targetDir = cwd ?? process.cwd()
  const lockfilePath = findLockfile(targetDir)
  if (!lockfilePath) {
    throw new Error(`Could not find ${LOCKFILE_NAME} at or above ${targetDir}`)
  }

  const lockfile = parseYaml(readFileSync(lockfilePath, 'utf8')) as Lockfile
  const importerKey = toImporterKey(dirname(lockfilePath), targetDir)
  return collectFromLockfile(lockfile, importerKey, includeDevDeps, parents)
}

function readDirectDependencies(cwd: string | undefined, includeDevDeps: boolean): Set<string> {
  const base = cwd ?? process.cwd()
  let parsed: {
    dependencies?: Record<string, string>
    optionalDependencies?: Record<string, string>
    devDependencies?: Record<string, string>
  }
  try {
    parsed = JSON.parse(readFileSync(base + '/package.json', 'utf8'))
  } catch {
    return new Set()
  }

  const direct = new Set<string>()
  for (const name of Object.keys(parsed.dependencies ?? {})) direct.add(name)
  for (const name of Object.keys(parsed.optionalDependencies ?? {})) direct.add(name)
  if (includeDevDeps) {
    for (const name of Object.keys(parsed.devDependencies ?? {})) direct.add(name)
  }
  return direct
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

// ---------------------------------------------------------------------------
// Phase C: Map bulk advisory response to AuditMetadata
// ---------------------------------------------------------------------------

const SEVERITY_KEYS: Severity[] = ['info', 'low', 'moderate', 'high', 'critical']

export function mapToAuditMetadata(
  deps: DependencyMap,
  advisories: BulkAdvisoryResponse,
  directSet?: Set<string>,
  parents?: ParentMap,
): DependencyAuditReport {
  const vulnerabilities: Record<Severity, number> = {
    info: 0,
    low: 0,
    moderate: 0,
    high: 0,
    critical: 0,
  }
  const detailed = directSet !== undefined
  const details: Partial<Record<Severity, VulnerablePackage[]>> = {}
  // Track (severity -> name@version) seen to dedup across multiple advisories.
  const seen: Partial<Record<Severity, Set<string>>> = {}

  for (const pkg of Object.keys(advisories)) {
    const installedVersions = deps.get(pkg)
    for (const advisory of advisories[pkg]) {
      if (!SEVERITY_KEYS.includes(advisory.severity as Severity)) continue
      const severity = advisory.severity as Severity

      if (!detailed) {
        vulnerabilities[severity]++
        continue
      }

      if (!installedVersions) continue

      const matching: string[] = []
      for (const version of installedVersions) {
        if (semver.satisfies(version, advisory.vulnerable_versions, { includePrerelease: true })) {
          matching.push(version)
        }
      }
      if (matching.length === 0) continue

      vulnerabilities[severity]++

      const bucket = (details[severity] ??= [])
      const seenBucket = (seen[severity] ??= new Set())
      const isDirect = directSet.has(pkg)
      for (const version of matching) {
        const key = `${pkg}@${version}`
        if (seenBucket.has(key)) continue
        seenBucket.add(key)
        const entry: VulnerablePackage = { name: pkg, version, direct: isDirect }
        if (parents) entry.path = dependencyPath(parents, key)
        bucket.push(entry)
      }
    }
  }

  const totalDependencies = deps.size

  const metadata: DependencyAuditReport = {
    vulnerabilities,
    dependencies: totalDependencies,
    devDependencies: 0,
    optionalDependencies: 0,
    totalDependencies,
  }
  if (detailed) metadata.details = details
  return metadata
}

// ---------------------------------------------------------------------------
// Main auditor — uses bulk advisory API instead of pnpm audit
// ---------------------------------------------------------------------------

export async function pnpmBulkAuditor(
  options?: DependencyAuditOptions,
): Promise<DependencyAuditReport> {
  const includeDevDeps = options?.includeDevDeps ?? false
  const parents: ParentMap | undefined = options?.detailed ? new Map() : undefined
  const deps = collectDependencies(options?.path, includeDevDeps, parents)
  const advisories = await fetchBulkAdvisories(depsToPayload(deps))
  const directSet = options?.detailed
    ? readDirectDependencies(options?.path, includeDevDeps)
    : undefined
  return mapToAuditMetadata(deps, advisories, directSet, parents)
}
