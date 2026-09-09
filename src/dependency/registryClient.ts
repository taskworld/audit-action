import * as core from '@actions/core'

const BULK_ENDPOINT = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
const REQUEST_TIMEOUT_MS = 30_000
const TOTAL_BUDGET_MS = 120_000
const MAX_ATTEMPTS = 4
const RETRY_BASE_DELAY_MS = 500
const MAX_RETRY_DELAY_MS = 8_000
const MAX_RETRY_AFTER_MS = 30_000
const MAX_ERROR_BODY_CHARS = 200
const CHUNK_SIZE = 400
const CONCURRENCY = 3

export interface BulkAdvisory {
  severity: string
  vulnerable_versions: string
  title: string
}

export type BulkAdvisoryResponse = Record<string, BulkAdvisory[]>

// Signals that the audit could not run at all, as opposed to a failed audit:
// callers must not read an empty report as "no vulnerabilities".
export class RegistryUnavailableError extends Error {
  constructor(message: string, options?: { cause?: unknown }) {
    super(message, options)
    this.name = 'RegistryUnavailableError'
  }
}

const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504, 522, 524])

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

function backoffDelay(attempt: number): number {
  return Math.min(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1), MAX_RETRY_DELAY_MS)
}

function retryAfterDelay(res: Response, attempt: number): number {
  const seconds = Number(res.headers.get('retry-after'))
  if (!Number.isFinite(seconds) || seconds <= 0) return backoffDelay(attempt)
  return Math.min(seconds * 1000, MAX_RETRY_AFTER_MS)
}

function truncate(body: string): string {
  return body.length > MAX_ERROR_BODY_CHARS ? `${body.slice(0, MAX_ERROR_BODY_CHARS)}…` : body
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = []
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size))
  return chunks
}

async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  run: (item: T) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (let index = next++; index < items.length; index = next++) {
      results[index] = await run(items[index])
    }
  })
  await Promise.all(workers)
  return results
}

type ChunkOutcome =
  | { advisories: BulkAdvisoryResponse }
  | { error: Error; retryable: false }
  | { error: Error; retryable: true; delay: number }

async function attemptChunk(
  payload: Record<string, string[]>,
  attempt: number,
  timeout: number,
): Promise<ChunkOutcome> {
  try {
    const res = await fetch(BULK_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeout),
    })

    if (res.ok) return { advisories: (await res.json()) as BulkAdvisoryResponse }

    const body = await res.text().catch(() => '')
    const error = new Error(`Registry returned ${res.status}: ${truncate(body)}`)
    // A 4xx other than throttling means the request itself is wrong — a retry cannot help.
    if (!RETRYABLE_STATUS.has(res.status)) return { error, retryable: false }
    return { error, retryable: true, delay: retryAfterDelay(res, attempt) }
  } catch (error) {
    return {
      error: new Error(`Request to the npm advisory endpoint failed: ${String(error)}`, {
        cause: error,
      }),
      retryable: true,
      delay: backoffDelay(attempt),
    }
  }
}

async function postChunk(
  payload: Record<string, string[]>,
  deadline: number,
): Promise<BulkAdvisoryResponse> {
  let lastError: Error | undefined

  for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
    const timeout = Math.min(REQUEST_TIMEOUT_MS, deadline - Date.now())
    if (timeout <= 0) break

    const outcome = await attemptChunk(payload, attempt, timeout)
    if ('advisories' in outcome) return outcome.advisories
    if (!outcome.retryable) throw outcome.error

    lastError = outcome.error
    if (attempt === MAX_ATTEMPTS || Date.now() + outcome.delay >= deadline) break
    core.warning(
      `npm advisory request failed (attempt ${attempt}/${MAX_ATTEMPTS}): ${outcome.error.message}`,
    )
    await sleep(outcome.delay)
  }

  throw new RegistryUnavailableError(
    `npm advisory endpoint unreachable within ${MAX_ATTEMPTS} attempts / ${TOTAL_BUDGET_MS}ms. ${lastError?.message ?? 'budget exhausted'}`,
    { cause: lastError },
  )
}

// The full closure of a large service is hundreds of KB in one body, which makes
// both timeouts and registry 5xx more likely; smaller bodies also retry cheaper.
// A whole-run deadline keeps a degraded registry from stalling the CI step: every
// chunk shares one budget instead of paying the retry ladder on its own.
export async function fetchBulkAdvisories(
  payload: Record<string, string[]>,
): Promise<BulkAdvisoryResponse> {
  const deadline = Date.now() + TOTAL_BUDGET_MS
  const chunks = chunk(Object.keys(payload), CHUNK_SIZE).map((names) => {
    const slice: Record<string, string[]> = {}
    for (const name of names) slice[name] = payload[name]
    return slice
  })

  const responses = await mapWithConcurrency(chunks, CONCURRENCY, (slice) =>
    postChunk(slice, deadline),
  )

  return Object.assign({}, ...responses) as BulkAdvisoryResponse
}
