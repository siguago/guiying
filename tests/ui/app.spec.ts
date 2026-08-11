import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'

const evidenceDir = 'docs/ui-delivery/evidence'

test('landing page communicates the read-only boundary', async ({ page }) => {
  await page.goto('/')

  await expect(page).toHaveTitle(/归影/)
  await expect(page.getByRole('heading', { name: /先看证据/ })).toBeVisible()
  await expect(page.getByText('不主动改文件')).toBeVisible()
  await expect(page.getByRole('button', { name: '请在桌面应用中选择目录' })).toBeDisabled()

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations).toEqual([])

  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/landing-1280x820.png`,
    fullPage: true,
  })
})

test('read-only demo scan exposes progress and exact duplicate evidence', async ({ page }) => {
  await page.goto('/')
  await page.clock.install()

  await page.getByRole('button', { name: '运行合成数据扫描演示' }).click()
  await expect(page.getByRole('heading', { name: '正在建立内容证据' })).toBeVisible()
  await expect(page.getByText('阶段 1 / 5')).toBeVisible()

  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/scanning-1280x820.png`,
    fullPage: true,
  })

  await page.clock.runFor(1_500)

  await expect(page.getByRole('heading', { name: /发现 3 组确定重复/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /IMG_4821\.HEIC/ })).toHaveAttribute('aria-pressed', 'true')
  await expect(page.getByText('D1 · 逐字节确认').first()).toBeVisible()
  await expect(page.getByText('时间：高可信').first()).toBeVisible()
  await expect(page.getByText('不参与重复判定')).toBeVisible()
  await expect(page.locator('code').filter({ hasText: '/Volumes/影像归档/已整理/2021/05/IMG_4821.HEIC' })).toBeVisible()
  await expect(page.locator('code').filter({ hasText: '/Volumes/影像归档/iPhone 全量备份 2024/IMG_4821.HEIC' })).toBeVisible()
  await expect(page.locator('code').filter({ hasText: '/Volumes/影像归档/手机照片 2025/IMG_4821 2.HEIC' })).toBeVisible()
  await expect(page.getByText(/这是合成数据演示/)).toBeVisible()

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations).toEqual([])

  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/results-1280x820.png`,
    fullPage: true,
  })
})

test('core flow remains reachable using only the keyboard', async ({ page }) => {
  await page.goto('/')
  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: '运行合成数据扫描演示' })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('heading', { name: /发现 3 组确定重复/ })).toBeVisible()
})

test('results adapt at the compact desktop boundary', async ({ page }) => {
  await page.setViewportSize({ width: 1024, height: 768 })
  await page.goto('/')
  await page.getByRole('button', { name: '运行合成数据扫描演示' }).click()
  await expect(page.getByRole('heading', { name: /发现 3 组确定重复/ })).toBeVisible()

  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/results-1024x768.png`,
    fullPage: true,
  })
})

test('a transient native status failure keeps cancellation control and recovers', async ({ page }) => {
  await page.addInitScript(() => {
    let callbackId = 0
    let statusQueries = 0
    const callbacks = new Map<number, (...args: unknown[]) => void>()
    const result = {
      schemaVersion: 1,
      scanRunId: '7',
      root: '/Volumes/Test Photos',
      status: 'complete',
      mediaFiles: '0',
      logicalBytes: '0',
      candidateSizeBuckets: '0',
      sampledFiles: '0',
      sampledBytesRead: '0',
      fullHashedFiles: '0',
      fullHashBytesRead: '0',
      verifiedGroups: '0',
      verifiedMembers: '0',
      redundantIndependentFiles: '0',
      comparedPairs: '0',
      comparedBytes: '0',
      logicalReclaimableBytes: '0',
      issues: '0',
    }

    Object.assign(window, {
      isTauri: true,
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: (callback: (...args: unknown[]) => void) => {
          callbackId += 1
          callbacks.set(callbackId, callback)
          return callbackId
        },
        unregisterCallback: (id: number) => callbacks.delete(id),
        invoke: async (command: string) => {
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'plugin:dialog|open') return '/Volumes/Test Photos'
          if (command === 'start_scan') return { jobId: 'scan-fixture' }
          if (command === 'cancel_scan') return undefined
          if (command === 'acknowledge_scan') return { released: true }
          if (command === 'list_duplicate_groups') return { items: [], nextCursor: null }
          if (command === 'list_scan_issues') return { items: [], nextCursor: null }
          if (command === 'get_scan_status') {
            statusQueries += 1
            if (statusQueries <= 2) {
              throw { code: 'IPC_TEMPORARY', message: 'temporary fixture failure' }
            }
            if (statusQueries === 3) {
              return {
                jobId: 'scan-fixture',
                phase: 'running',
                startedAtUnixMs: 1_000,
                finishedAtUnixMs: null,
                scanRunId: null,
                progress: null,
                result: null,
                error: null,
              }
            }
            return {
              jobId: 'scan-fixture',
              phase: 'completed',
              startedAtUnixMs: 1_000,
              finishedAtUnixMs: 1_400,
              scanRunId: '7',
              progress: null,
              result,
              error: null,
            }
          }
          throw new Error(`unexpected fixture command: ${command}`)
        },
      },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '选择照片目录' }).click()
  await page.getByRole('button', { name: '开始只读扫描' }).click()

  await expect(page.getByRole('button', { name: '停止扫描' })).toBeVisible()
  await expect(page.getByText(/暂时无法确认扫描状态/)).toBeVisible()
  await expect(page.getByRole('heading', { name: '发现 0 组确定重复' })).toBeVisible()
  await expect(page.getByText('/Volumes/Test Photos').first()).toBeVisible()
})

test('persistent results page groups, members, and issues without unbounded accumulation', async ({ page }) => {
  await page.addInitScript(() => {
    let callbackId = 0
    let groupSecondPageAttempts = 0
    let memberSecondPageAttempts = 0
    let issueSecondPageAttempts = 0
    const callbacks = new Map<number, (...args: unknown[]) => void>()
    const pagingCalls: Array<{ command: string; payload: Record<string, unknown> }> = []
    const result = {
      schemaVersion: 1,
      scanRunId: '77',
      root: '/Volumes/Test Photos',
      status: 'complete',
      mediaFiles: '3',
      logicalBytes: '12',
      candidateSizeBuckets: '2',
      sampledFiles: '3',
      sampledBytesRead: '12',
      fullHashedFiles: '3',
      fullHashBytesRead: '12',
      verifiedGroups: '2',
      verifiedMembers: '5',
      redundantIndependentFiles: '3',
      comparedPairs: '3',
      comparedBytes: '12',
      logicalReclaimableBytes: '12',
      issues: '2',
    }
    const group = (id: string, name: string, memberCount: string) => ({
      groupBuildId: id,
      groupKeyHex: id.repeat(32).slice(0, 64),
      memberCount,
      independentFileCount: memberCount,
      sizeBytes: '4',
      previewPath: `/Volumes/Test Photos/${name}`,
      logicalReclaimableBytes: memberCount === '3' ? '8' : '4',
      finalizedAtUnixMs: '2000',
    })
    const member = (groupBuildId: string, ordinal: string, name: string) => ({
      groupBuildId,
      ordinal,
      observationId: `${groupBuildId}${ordinal}`,
      displayPath: `/Volumes/Test Photos/${name}`,
      pathEncoding: 'utf8',
      sizeBytes: '4',
      hasStableFileIdentity: true,
      birthTimeSeconds: ordinal === '0' ? '1609459200' : '1735689600',
      birthTimeNanoseconds: '0',
      modifiedTimeSeconds: ordinal === '0' ? '1609459200' : '1735689600',
      modifiedTimeNanoseconds: '0',
      timestampGranularityNs: null,
    })

    Object.assign(window, {
      isTauri: true,
      __PAGING_CALLS__: pagingCalls,
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: (callback: (...args: unknown[]) => void) => {
          callbackId += 1
          callbacks.set(callbackId, callback)
          return callbackId
        },
        unregisterCallback: (id: number) => callbacks.delete(id),
        invoke: async (command: string, payload: Record<string, unknown> = {}) => {
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'plugin:dialog|open') return '/Volumes/Test Photos'
          if (command === 'start_scan') return { jobId: 'scan-paged' }
          if (command === 'acknowledge_scan') return { released: true }
          if (command === 'get_scan_status') {
            return {
              jobId: 'scan-paged',
              phase: 'completed',
              startedAtUnixMs: 1_000,
              finishedAtUnixMs: 2_000,
              scanRunId: '77',
              progress: null,
              result,
              error: null,
            }
          }
          if (command === 'list_duplicate_groups') {
            pagingCalls.push({ command, payload })
            if (payload.cursor === 'groups-2') {
              groupSecondPageAttempts += 1
              if (groupSecondPageAttempts === 1) {
                await new Promise((resolve) => window.setTimeout(resolve, 35))
                throw { code: 'PAGE_TEMPORARY', message: 'group page fixture failure' }
              }
              return { items: [group('102', 'B.JPG', '2')], nextCursor: null }
            }
            return { items: [group('101', 'A.JPG', '3')], nextCursor: 'groups-2' }
          }
          if (command === 'list_duplicate_group_members') {
            pagingCalls.push({ command, payload })
            if (payload.groupBuildId === '102') {
              return {
                items: [member('102', '0', 'B.JPG'), member('102', '1', 'B-copy.JPG')],
                nextCursor: null,
              }
            }
            if (payload.cursor === 'members-a-2') {
              memberSecondPageAttempts += 1
              if (memberSecondPageAttempts === 1) {
                throw { code: 'PAGE_TEMPORARY', message: 'member page fixture failure' }
              }
              return { items: [member('101', '2', 'A-third.JPG')], nextCursor: null }
            }
            return {
              items: [member('101', '0', 'A.JPG'), member('101', '1', 'A-copy.JPG')],
              nextCursor: 'members-a-2',
            }
          }
          if (command === 'list_scan_issues') {
            pagingCalls.push({ command, payload })
            if (payload.cursor === 'issues-2') {
              issueSecondPageAttempts += 1
              if (issueSecondPageAttempts === 1) {
                throw { code: 'PAGE_TEMPORARY', message: 'issue page fixture failure' }
              }
              return {
                items: [{
                  issueId: '2', severity: 'warning', stage: 'enumeration', code: 'ISSUE_TWO',
                  message: 'second page', occurredAtUnixMs: '2', resolved: false,
                }],
                nextCursor: null,
              }
            }
            return {
              items: [{
                issueId: '1', severity: 'warning', stage: 'enumeration', code: 'ISSUE_ONE',
                message: 'first page', occurredAtUnixMs: '1', resolved: false,
              }],
              nextCursor: 'issues-2',
            }
          }
          throw new Error(`unexpected fixture command: ${command}`)
        },
      },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '选择照片目录' }).click()
  await page.getByRole('button', { name: '开始只读扫描' }).click()

  await expect(page.getByRole('heading', { name: '发现 2 组确定重复' })).toBeVisible()
  await expect(page.getByRole('button', { name: /A\.JPG/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /B\.JPG/ })).toHaveCount(0)
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/A-copy.JPG' })).toBeVisible()
  await expect(page.getByText('2021-01-01 00:00:00 UTC').first()).toBeVisible()
  await expect(page.getByText('2025-01-01 00:00:00 UTC').first()).toBeVisible()
  await expect(page.getByText(/文件系统实际时间精度未知/).first()).toBeVisible()
  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/results-paged-1280x820.png`,
    fullPage: true,
  })

  await page.getByLabel('组内文件分页').getByRole('button', { name: '下一页' }).click()
  await expect(page.getByText('member page fixture failure')).toBeVisible()
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/A-copy.JPG' })).toBeVisible()
  await page.getByRole('button', { name: '重试' }).click()
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/A-third.JPG' })).toBeVisible()
  await page.getByLabel('组内文件分页').getByRole('button', { name: '上一页' }).click()
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/A-copy.JPG' })).toBeVisible()

  const groupNext = page.getByLabel('确定重复组分页').getByRole('button', { name: '下一页' })
  await groupNext.evaluate((button) => {
    button.click()
    button.click()
  })
  await expect(page.getByText('group page fixture failure')).toBeVisible()
  await expect(page.getByRole('button', { name: /A\.JPG/ })).toBeVisible()
  await page.getByRole('button', { name: '重试失败页' }).click()
  await expect(page.getByRole('button', { name: /B\.JPG/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /A\.JPG/ })).toHaveCount(0)
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/B.JPG' })).toBeVisible()
  await page.getByLabel('确定重复组分页').getByRole('button', { name: '上一页' }).click()
  await expect(page.getByRole('button', { name: /A\.JPG/ })).toBeVisible()

  await page.getByText('查看 2 条扫描问题记录').click()
  await expect(page.getByText('ISSUE_ONE')).toBeVisible()
  await page.getByLabel('扫描问题分页').getByRole('button', { name: '下一页' }).click()
  await expect(page.getByText('issue page fixture failure')).toBeVisible()
  await expect(page.getByText('ISSUE_ONE')).toBeVisible()
  await page.getByRole('button', { name: '重试' }).click()
  await expect(page.getByText('ISSUE_TWO')).toBeVisible()
  await expect(page.getByText('ISSUE_ONE')).toHaveCount(0)

  const calls = await page.evaluate(() => (
    window as Window & {
      __PAGING_CALLS__: Array<{ command: string; payload: Record<string, unknown> }>
    }
  ).__PAGING_CALLS__)
  expect(calls.filter((call) => call.command === 'list_duplicate_groups')).toHaveLength(4)
  expect(calls.filter((call) => (
    call.command === 'list_duplicate_groups' && call.payload.cursor === 'groups-2'
  ))).toHaveLength(2)
  expect(calls.every((call) => typeof call.payload.limit === 'number')).toBe(true)

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations).toEqual([])
})

test('a malformed terminal summary is acknowledged before the adaptation error is shown', async ({ page }) => {
  await page.addInitScript(() => {
    const fixtureState = { acknowledgements: 0 }
    const result = {
      schemaVersion: 1,
      scanRunId: '88',
      root: '/Volumes/Test Photos',
      status: 'complete',
      mediaFiles: '1',
      logicalBytes: '4',
      candidateSizeBuckets: '0',
      sampledFiles: '0',
      sampledBytesRead: '0',
      fullHashedFiles: '0',
      fullHashBytesRead: '0',
      verifiedGroups: '0',
      verifiedMembers: '0',
      redundantIndependentFiles: 'invalid',
      comparedPairs: '0',
      comparedBytes: '0',
      logicalReclaimableBytes: '0',
      issues: '0',
    }
    Object.assign(window, {
      isTauri: true,
      __TERMINAL_FIXTURE__: fixtureState,
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: () => 1,
        unregisterCallback: () => undefined,
        invoke: async (command: string) => {
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'plugin:dialog|open') return '/Volumes/Test Photos'
          if (command === 'start_scan') return { jobId: 'scan-malformed' }
          if (command === 'get_scan_status') {
            return {
              jobId: 'scan-malformed', phase: 'completed', startedAtUnixMs: 1,
              finishedAtUnixMs: 2, scanRunId: '88', progress: null, result, error: null,
            }
          }
          if (command === 'list_duplicate_groups') return { items: [], nextCursor: null }
          if (command === 'acknowledge_scan') {
            fixtureState.acknowledgements += 1
            return { released: true }
          }
          throw new Error(`unexpected fixture command: ${command}`)
        },
      },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '选择照片目录' }).click()
  await page.getByRole('button', { name: '开始只读扫描' }).click()

  await expect(page.getByRole('heading', { name: '没有执行主动修改操作' })).toBeVisible()
  await expect(page.getByText(/冗余独立副本数量不是有效的非负十进制数/)).toBeVisible()
  const acknowledgements = await page.evaluate(() => (
    window as Window & { __TERMINAL_FIXTURE__: { acknowledgements: number } }
  ).__TERMINAL_FIXTURE__.acknowledgements)
  expect(acknowledgements).toBe(1)
})

test('cancelled work exposes no unsealed duplicate or issue pages', async ({ page }) => {
  await page.addInitScript(() => {
    const fixtureState = { resultPageCalls: 0 }
    const result = {
      schemaVersion: 1,
      scanRunId: '99',
      root: '/Volumes/Test Photos',
      status: 'cancelled',
      mediaFiles: '10',
      logicalBytes: '40',
      candidateSizeBuckets: '1',
      sampledFiles: '2',
      sampledBytesRead: '8',
      fullHashedFiles: '2',
      fullHashBytesRead: '8',
      verifiedGroups: '1',
      verifiedMembers: '2',
      redundantIndependentFiles: '1',
      comparedPairs: '1',
      comparedBytes: '4',
      logicalReclaimableBytes: '4',
      issues: '1',
    }
    Object.assign(window, {
      isTauri: true,
      __CANCELLED_FIXTURE__: fixtureState,
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: () => 1,
        unregisterCallback: () => undefined,
        invoke: async (command: string) => {
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'plugin:dialog|open') return '/Volumes/Test Photos'
          if (command === 'start_scan') return { jobId: 'scan-cancelled' }
          if (command === 'get_scan_status') {
            return {
              jobId: 'scan-cancelled', phase: 'cancelled', startedAtUnixMs: 1,
              finishedAtUnixMs: 2, scanRunId: '99', progress: null, result, error: null,
            }
          }
          if (command === 'acknowledge_scan') return { released: true }
          if (command.startsWith('list_')) {
            fixtureState.resultPageCalls += 1
            throw new Error('cancelled results must not request pages')
          }
          throw new Error(`unexpected fixture command: ${command}`)
        },
      },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '选择照片目录' }).click()
  await page.getByRole('button', { name: '开始只读扫描' }).click()

  await expect(page.getByRole('heading', { name: '发现 0 组确定重复' })).toBeVisible()
  await expect(page.getByText(/取消态不会开放未封印的问题分页/)).toBeVisible()
  await expect(page.getByText('0 B', { exact: true })).toBeVisible()
  const resultPageCalls = await page.evaluate(() => (
    window as Window & { __CANCELLED_FIXTURE__: { resultPageCalls: number } }
  ).__CANCELLED_FIXTURE__.resultPageCalls)
  expect(resultPageCalls).toBe(0)
})
