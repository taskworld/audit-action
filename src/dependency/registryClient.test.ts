import { beforeEach, describe, expect, it, vi } from 'vitest'

import { fetchBulkAdvisories, RegistryUnavailableError } from './registryClient.js'

const fetchMock = vi.fn()
vi.stubGlobal('fetch', fetchMock)

function response(init: {
  ok: boolean
  status?: number
  body?: unknown
  headers?: Record<string, string>
}) {
  return {
    ok: init.ok,
    status: init.status ?? (init.ok ? 200 : 500),
    headers: new Headers(init.headers),
    json: async () => init.body ?? {},
    text: async () => JSON.stringify(init.body ?? ''),
  }
}

// Retries sleep between attempts; drive those timers instead of waiting on them.
async function withFakeTimers<T>(start: () => Promise<T>): Promise<T> {
  vi.useFakeTimers()
  try {
    const pending = start()
    await vi.runAllTimersAsync()
    return await pending
  } finally {
    vi.useRealTimers()
  }
}

function sentPayloadSizes() {
  return fetchMock.mock.calls.map(
    (call) => Object.keys(JSON.parse((call[1] as { body: string }).body)).length,
  )
}

describe('fetchBulkAdvisories', () => {
  beforeEach(() => {
    fetchMock.mockReset()
  })

  it('returns the advisories of a successful request', async () => {
    fetchMock.mockResolvedValueOnce(response({ ok: true, body: { axios: [] } }))

    await expect(fetchBulkAdvisories({ axios: ['0.21.1'] })).resolves.toEqual({ axios: [] })
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('retries transient failures and succeeds', async () => {
    fetchMock
      .mockResolvedValueOnce(response({ ok: false, status: 503 }))
      .mockRejectedValueOnce(new DOMException('timeout', 'TimeoutError'))
      .mockResolvedValueOnce(response({ ok: true, body: { lodash: [] } }))

    const advisories = await withFakeTimers(() => fetchBulkAdvisories({ lodash: ['4.17.20'] }))

    expect(advisories).toEqual({ lodash: [] })
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('gives up after the retry budget and reports the registry as unavailable', async () => {
    fetchMock.mockResolvedValue(response({ ok: false, status: 503 }))

    const error = await withFakeTimers(() =>
      fetchBulkAdvisories({ lodash: ['4.17.20'] }).catch((e) => e),
    )

    expect(error).toBeInstanceOf(RegistryUnavailableError)
    expect((error as Error).message).toMatch(
      /unreachable within 4 attempts.*Registry returned 503/s,
    )
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('does not retry a non-retryable registry response', async () => {
    fetchMock.mockResolvedValue(response({ ok: false, status: 400 }))

    const error = await fetchBulkAdvisories({ lodash: ['4.17.20'] }).catch((e) => e)

    expect(error).not.toBeInstanceOf(RegistryUnavailableError)
    expect((error as Error).message).toMatch(/Registry returned 400/)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })

  it('truncates an oversized registry error body', async () => {
    fetchMock.mockResolvedValue(response({ ok: false, status: 400, body: 'x'.repeat(5000) }))

    const error = await fetchBulkAdvisories({ lodash: ['4.17.20'] }).catch((e) => e)

    expect((error as Error).message.length).toBeLessThan(300)
    expect((error as Error).message).toMatch(/…$/)
  })

  it('honours Retry-After for the next attempt', async () => {
    const attemptedAt: number[] = []
    fetchMock.mockImplementation(async () => {
      attemptedAt.push(Date.now())
      return attemptedAt.length === 1
        ? response({ ok: false, status: 429, headers: { 'retry-after': '5' } })
        : response({ ok: true, body: {} })
    })

    await withFakeTimers(() => fetchBulkAdvisories({ lodash: ['4.17.20'] }))

    expect(attemptedAt).toHaveLength(2)
    expect(attemptedAt[1] - attemptedAt[0]).toBe(5000)
  })

  it('splits large dependency sets into several requests and merges the responses', async () => {
    const payload: Record<string, string[]> = {}
    for (let i = 0; i < 900; i++) payload[`pkg-${i}`] = ['1.0.0']

    fetchMock
      .mockResolvedValueOnce(response({ ok: true, body: { 'pkg-1': [] } }))
      .mockResolvedValueOnce(response({ ok: true, body: { 'pkg-500': [] } }))
      .mockResolvedValueOnce(response({ ok: true, body: { 'pkg-800': [] } }))

    const advisories = await fetchBulkAdvisories(payload)

    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(Object.keys(advisories).sort()).toEqual(['pkg-1', 'pkg-500', 'pkg-800'])
    expect(sentPayloadSizes().sort((a, b) => b - a)).toEqual([400, 400, 100])
  })

  it('stops retrying once the whole-run budget is spent', async () => {
    const payload: Record<string, string[]> = {}
    for (let i = 0; i < 1600; i++) payload[`pkg-${i}`] = ['1.0.0']

    fetchMock.mockImplementation(
      () =>
        new Promise((_resolve, reject) => {
          setTimeout(() => reject(new DOMException('timeout', 'TimeoutError')), 30_000)
        }),
    )

    const error = await withFakeTimers(() => fetchBulkAdvisories(payload).catch((e) => e))

    expect(error).toBeInstanceOf(RegistryUnavailableError)
    // 4 chunks x 4 attempts would be 16; the shared deadline cuts the run short.
    expect(fetchMock.mock.calls.length).toBeLessThan(16)
  })
})
