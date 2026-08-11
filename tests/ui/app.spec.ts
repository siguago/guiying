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
          if (command === 'select_scan_root') return { rootToken: `root-${'a'.repeat(64)}` }
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

test('webview rejects a path-shaped root authority instead of starting a scan', async ({ page }) => {
  await page.addInitScript(() => {
    const fixtureState = { startCalls: 0 }
    Object.assign(window, {
      isTauri: true,
      __ROOT_TOKEN_FIXTURE__: fixtureState,
      __TAURI_INTERNALS__: {
        transformCallback: () => 1,
        unregisterCallback: () => undefined,
        invoke: async (command: string) => {
          if (command === 'select_scan_root') return { rootToken: '/Users/example/.ssh' }
          if (command === 'start_scan') {
            fixtureState.startCalls += 1
            throw new Error('start_scan must not be reached')
          }
          throw new Error(`unexpected fixture command: ${command}`)
        },
      },
    })
  })

  await page.goto('/')
  await page.getByRole('button', { name: '选择照片目录' }).click()

  await expect(page.getByRole('heading', { name: '没有执行主动修改操作' })).toBeVisible()
  await expect(page.getByText(/原生目录授权 token 格式无效/)).toBeVisible()
  const startCalls = await page.evaluate(() => (
    window as Window & { __ROOT_TOKEN_FIXTURE__: { startCalls: number } }
  ).__ROOT_TOKEN_FIXTURE__.startCalls)
  expect(startCalls).toBe(0)
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
      rootPath: {
        encoding: 'unix_bytes',
        rawBase64: 'L1ZvbHVtZXMvVGVzdCBQaG90b3M',
      },
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
      captureTime: {
        status: 'completed',
        groupsSeen: '2',
        groupsWritten: '2',
        evidenceGroups: '1',
        unavailableGroups: '1',
        failedGroups: '0',
        failure: null,
        reservedReadBytes: '24',
        actualReadBytes: '16',
        reservedReadOperations: '8',
        actualReadOperations: '6',
        budgetExhausted: false,
      },
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
          if (command === 'select_scan_root') return { rootToken: `root-${'b'.repeat(64)}` }
          if (command === 'start_scan') {
            pagingCalls.push({ command, payload })
            return { jobId: 'scan-paged' }
          }
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
          if (command === 'get_capture_time_group_summary') {
            const groupId = String(payload.exactGroupBuildId)
            return {
              analysisBuildId: groupId === '101' ? '501' : '502',
              exactGroupBuildId: groupId,
              decision: groupId === '101' ? 'evidence_eligible' : 'no_usable_evidence',
              selectedCandidateOrdinal: groupId === '101' ? '0' : null,
              sourceCount: groupId === '101' ? '1' : '0',
              observationCount: groupId === '101' ? '2' : '0',
              candidateCount: groupId === '101' ? '1' : '0',
              issueCount: groupId === '101' ? '1' : '0',
              memberCount: groupId === '101' ? '3' : '2',
              finalizedAtUnixMs: '2100',
              evidenceOnly: true,
              writeAuthorized: false,
            }
          }
          if (command === 'list_capture_time_candidates') {
            if (payload.exactGroupBuildId !== '101') return { items: [], nextCursor: null }
            return {
              items: [{
                analysisBuildId: '501', ordinal: '0',
                wallTime: { year: '2021', month: '1', day: '1', hour: '8', minute: '0', second: '0', nanosecond: '123000000' },
                semanticKind: 'utc', offsetKind: 'explicit', utcOffsetMinutes: '480',
                utcSeconds: '1609430400', utcNanoseconds: '123000000', precisionNs: '1000000',
                confidence: 'high', evidenceEligible: true, evidenceBlockers: [],
                evidenceKinds: ['exif_date_time_original'], anomalies: [],
                sourceCount: '1', lineageCount: '1', supportingObservationCount: '2',
              }],
              nextCursor: null,
            }
          }
          if (command === 'list_capture_time_members') {
            return {
              items: [{
                analysisBuildId: '501', memberOrdinal: '0', observationId: '1010',
                candidateOrdinal: '0',
                birthTime: { seconds: '1609459200', nanoseconds: '0' },
                modifiedTime: { seconds: '1609459200', nanoseconds: '0' },
                timestampGranularityNs: null,
                birthTimeRelation: 'review_fs_precision_unknown',
                modifiedTimeRelation: 'not_compared', donorEligibility: 'ineligible',
                reasonCode: 'fs_precision_unknown',
              }],
              nextCursor: null,
            }
          }
          if (command === 'list_capture_time_issues') {
            return {
              items: [{
                analysisBuildId: '501', ordinal: '0', code: 'FS_PRECISION_UNKNOWN',
                fieldKind: null, observationCount: '1', sourceCount: '1', lineageCount: '1',
                context: '文件系统实际时间精度未知，因此没有比较文件时间。',
              }],
              nextCursor: null,
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
  await expect(page.getByText(/Unix 原生字节.*无损封存/)).toBeVisible()
  await expect(page.getByRole('button', { name: /A\.JPG/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /B\.JPG/ })).toHaveCount(0)
  await expect(page.locator('code').filter({ hasText: '/Volumes/Test Photos/A-copy.JPG' })).toBeVisible()
  await expect(page.getByText('2021-01-01 00:00:00 UTC').first()).toBeVisible()
  await expect(page.getByText('2025-01-01 00:00:00 UTC').first()).toBeVisible()
  await expect(page.getByText(/文件系统实际时间精度未知/).first()).toBeVisible()
  await expect(page.getByText('拍摄时间证据已封存')).toBeVisible()
  await expect(page.getByText('存在符合证据资格的候选')).toBeVisible()
  await expect(page.getByText('2021-01-01 08:00:00.123000000')).toBeVisible()
  await expect(page.getByText('仅证据资格')).toBeVisible()
  await expect(page.getByText('封印分析选中')).toBeVisible()
  await expect(page.getByText('尚未选择保留副本')).toBeVisible()
  await expect(page.getByText('暂定保留')).toHaveCount(0)
  await page.getByText('文件时间关系（3 项）').click()
  await expect(page.getByText('文件系统实际精度未知，需人工审阅')).toBeVisible()
  await page.getByText('时间问题（1 项）').click()
  await expect(page.getByText('FS_PRECISION_UNKNOWN', { exact: true })).toBeVisible()
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
  expect(calls.filter((call) => call.command === 'start_scan')).toEqual([{
    command: 'start_scan',
    payload: { rootToken: `root-${'b'.repeat(64)}` },
  }])
  expect(calls
    .filter((call) => call.command !== 'start_scan')
    .every((call) => typeof call.payload.limit === 'number')).toBe(true)

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations).toEqual([])
})

test('sealed raw metadata stays lazy, scoped, byte-exact, and fail-closed', async ({ page }) => {
  await page.addInitScript(() => {
    let callbackId = 0
    let reportSecondPageAttempts = 0
    let rawNativePathAttempt = 0
    let rawListAttempt = 0
    const callbacks = new Map<number, (...args: unknown[]) => void>()
    const calls: Array<{ command: string; payload: Record<string, unknown> }> = []
    const digest = 'a'.repeat(64)
    const manifestDigest = 'b'.repeat(64)
    const fieldDigest = 'c'.repeat(64)
    const result = {
      schemaVersion: 1,
      scanRunId: '77',
      root: '/Volumes/Test Photos',
      status: 'complete',
      mediaFiles: '4',
      logicalBytes: '16',
      candidateSizeBuckets: '1',
      sampledFiles: '4',
      sampledBytesRead: '16',
      fullHashedFiles: '4',
      fullHashBytesRead: '16',
      verifiedGroups: '2',
      verifiedMembers: '4',
      redundantIndependentFiles: '2',
      comparedPairs: '2',
      comparedBytes: '8',
      logicalReclaimableBytes: '8',
      issues: '0',
      captureTime: {
        status: 'completed', groupsSeen: '2', groupsWritten: '2', evidenceGroups: '2',
        unavailableGroups: '0', failedGroups: '0', failure: null,
        reservedReadBytes: '32', actualReadBytes: '24',
        reservedReadOperations: '8', actualReadOperations: '6', budgetExhausted: false,
      },
    }
    const group = (id: string, name: string) => ({
      groupBuildId: id,
      groupKeyHex: id.repeat(32).slice(0, 64),
      memberCount: '2',
      independentFileCount: '2',
      sizeBytes: '4',
      previewPath: `/Volumes/Test Photos/${name}`,
      logicalReclaimableBytes: '4',
      finalizedAtUnixMs: '1900',
    })
    const member = (groupBuildId: string, ordinal: string, name: string) => ({
      groupBuildId,
      ordinal,
      observationId: `${groupBuildId}${ordinal}`,
      displayPath: `/Volumes/Test Photos/${name}`,
      pathEncoding: 'utf8',
      sizeBytes: '4',
      hasStableFileIdentity: true,
      birthTimeSeconds: '1609459200',
      birthTimeNanoseconds: '0',
      modifiedTimeSeconds: '1609459200',
      modifiedTimeNanoseconds: '0',
      timestampGranularityNs: '1000000000',
    })
    const report = (
      analysisBuildId: string,
      exactGroupBuildId: string,
      sourceOrdinal: string,
      reportId: string,
      name: string,
      fieldCount: string,
    ) => ({
      analysisBuildId,
      exactGroupBuildId,
      sourceOrdinal,
      reportId,
      observationId: exactGroupBuildId === '201' ? '2010' : '2020',
      displayPath: `/Volumes/Test Photos/${name}`,
      pathEncoding: 'utf8',
      probeOrdinal: sourceOrdinal,
      sourceSizeBytes: '100',
      reportParserName: 'guiying-metadata',
      reportParserVersion: '1.0.0',
      detectedFormat: 'tiff',
      extractionStatus: 'extracted_unvalidated',
      fieldCount,
      extractionIssueCount: '0',
      retainedFieldBytes: fieldCount === '3' ? '10' : fieldCount === '2' ? '7' : '3',
      bytesRead: '4',
      readOperations: '1',
      retainedReportDigestHex: digest,
      sealedManifestDigestHex: manifestDigest,
      firstReportDigestHex: digest,
      secondReportDigestHex: digest,
      doubleExtractionConsistent: true,
      descriptorRevalidated: true,
      pathRevalidated: true,
      sessionRevalidated: true,
      trustScope: 'historical_proof_only',
      revalidatedAtUnixMs: '2000',
      finalizedAtUnixMs: '2100',
      evidenceOnly: true,
      writeAuthorized: false,
    })
    const field = (
      sourceOrdinal: string,
      reportId: string,
      fieldId: string,
      ordinal: string,
      fieldKind: string,
      byteLength: string,
    ) => ({
      analysisBuildId: '602',
      sourceOrdinal,
      reportId,
      fieldId,
      ordinal,
      parserName: 'guiying-tiff',
      parserVersion: '1.0.0',
      fieldKind,
      encoding: 'declared_ascii',
      byteLength,
      rawDigestHex: fieldDigest,
      containerKind: 'tiff',
      absoluteOffset: ordinal === '0' ? '42' : '45',
      rawAvailable: true,
    })
    const rawDetail = (
      reportValue: ReturnType<typeof report>,
      fieldValue: ReturnType<typeof field>,
      rawBase64: string,
      nativePathRawBase64: string,
      locatorHeaderOffset = '0',
    ) => ({
      scanRunId: '77',
      exactGroupBuildId: reportValue.exactGroupBuildId,
      analysisBuildId: reportValue.analysisBuildId,
      sourceOrdinal: reportValue.sourceOrdinal,
      reportId: reportValue.reportId,
      fieldOrdinal: fieldValue.ordinal,
      fieldId: fieldValue.fieldId,
      observationId: reportValue.observationId,
      displayPath: reportValue.displayPath,
      nativePath: { encoding: 'utf8', rawBase64: nativePathRawBase64 },
      probeOrdinal: reportValue.probeOrdinal,
      sourceSizeBytes: reportValue.sourceSizeBytes,
      reportParserName: reportValue.reportParserName,
      reportParserVersion: reportValue.reportParserVersion,
      detectedFormat: reportValue.detectedFormat,
      extractionStatus: reportValue.extractionStatus,
      fieldCount: reportValue.fieldCount,
      extractionIssueCount: reportValue.extractionIssueCount,
      retainedFieldBytes: reportValue.retainedFieldBytes,
      bytesRead: reportValue.bytesRead,
      readOperations: reportValue.readOperations,
      retainedReportDigestHex: reportValue.retainedReportDigestHex,
      sealedManifestDigestHex: reportValue.sealedManifestDigestHex,
      firstReportDigestHex: reportValue.firstReportDigestHex,
      secondReportDigestHex: reportValue.secondReportDigestHex,
      doubleExtractionConsistent: true,
      descriptorRevalidated: true,
      pathRevalidated: true,
      sessionRevalidated: true,
      trustScope: 'historical_proof_only',
      revalidatedAtUnixMs: reportValue.revalidatedAtUnixMs,
      finalizedAtUnixMs: reportValue.finalizedAtUnixMs,
      evidenceOnly: true,
      writeAuthorized: false,
      parserName: fieldValue.parserName,
      parserVersion: fieldValue.parserVersion,
      fieldKind: fieldValue.fieldKind,
      encoding: fieldValue.encoding,
      byteLength: fieldValue.byteLength,
      rawBase64,
      rawDigestHex: fieldValue.rawDigestHex,
      absoluteOffset: fieldValue.absoluteOffset,
      locator: {
        kind: 'tiff', headerOffset: locatorHeaderOffset, ifdOffset: '8', tag: '36867',
        byteOrder: 'little_endian',
      },
    })

    Object.assign(window, {
      isTauri: true,
      __RAW_METADATA_FIXTURE__: { calls },
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: (callback: (...args: unknown[]) => void) => {
          callbackId += 1
          callbacks.set(callbackId, callback)
          return callbackId
        },
        unregisterCallback: (id: number) => callbacks.delete(id),
        invoke: async (command: string, payload: Record<string, unknown> = {}) => {
          calls.push({ command, payload })
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'select_scan_root') return { rootToken: `root-${'f'.repeat(64)}` }
          if (command === 'start_scan') return { jobId: 'scan-raw-metadata' }
          if (command === 'acknowledge_scan') return { released: true }
          if (command === 'get_scan_status') {
            return {
              jobId: 'scan-raw-metadata', phase: 'completed', startedAtUnixMs: 1000,
              finishedAtUnixMs: 2200, scanRunId: '77', progress: null, result, error: null,
            }
          }
          if (command === 'list_duplicate_groups') {
            return { items: [group('201', 'A.JPG'), group('202', 'B.JPG')], nextCursor: null }
          }
          if (command === 'list_duplicate_group_members') {
            const groupId = String(payload.groupBuildId)
            return {
              items: [
                member(groupId, '0', groupId === '201' ? 'A.JPG' : 'B.JPG'),
                member(groupId, '1', groupId === '201' ? 'A-copy.JPG' : 'B-copy.JPG'),
              ],
              nextCursor: null,
            }
          }
          if (command === 'get_capture_time_group_summary') {
            const groupId = String(payload.exactGroupBuildId)
            return {
              analysisBuildId: groupId === '201' ? '601' : '602',
              exactGroupBuildId: groupId,
              decision: 'review_required', selectedCandidateOrdinal: null,
              sourceCount: groupId === '201' ? '1' : '3', observationCount: '2',
              candidateCount: '0', issueCount: '0', memberCount: '2',
              finalizedAtUnixMs: '2100', evidenceOnly: true, writeAuthorized: false,
            }
          }
          if (command === 'list_capture_time_candidates') return { items: [], nextCursor: null }
          if (command === 'list_capture_time_metadata_reports') {
            const groupId = String(payload.exactGroupBuildId)
            if (groupId === '201') {
              await new Promise((resolve) => window.setTimeout(resolve, 180))
              return { items: [report('601', '201', '0', '701', 'A.JPG', '1')], nextCursor: null }
            }
            if (payload.cursor === 'reports-2') {
              reportSecondPageAttempts += 1
              if (reportSecondPageAttempts === 1) {
                throw { code: 'PAGE_TEMPORARY', message: 'metadata report page fixture failure' }
              }
              return {
                items: [report('602', '202', '2', '703', 'B-three.JPG', '1')],
                nextCursor: 'reports-raw',
              }
            }
            if (payload.cursor === 'reports-raw') {
              rawListAttempt += 1
              return {
                items: rawListAttempt === 1
                  ? [{
                      ...report('602', '202', '3', '704', 'B-malicious.JPG', '1'),
                      rawBase64: 'AP/DKA==',
                    }]
                  : [{
                      ...report('602', '202', '3', '704', 'B-malicious.JPG', '1'),
                      rawValue: 'AP/DKA==',
                    }],
                nextCursor: null,
              }
            }
            return {
              items: [
                report('602', '202', '0', '701', 'B-one.JPG', '1'),
                report('602', '202', '1', '702', 'B-two.JPG', '3'),
              ],
              nextCursor: 'reports-2',
            }
          }
          if (command === 'list_capture_time_metadata_fields') {
            if (payload.cursor === 'fields-overflow') {
              return {
                items: [{
                  ...field('1', '702', '804', '2', 'exif_modify_date', '3'),
                  absoluteOffset: '99',
                }],
                nextCursor: null,
              }
            }
            if (payload.reportId === '701') {
              await new Promise((resolve) => window.setTimeout(resolve, 180))
              return {
                items: [field('0', '701', '801', '0', 'exif_create_date', '3')],
                nextCursor: null,
              }
            }
            return {
              items: [
                field('1', '702', '802', '0', 'exif_date_time_original', '3'),
                field('1', '702', '803', '1', 'exif_offset_time_original', '4'),
              ],
              nextCursor: 'fields-overflow',
            }
          }
          if (command === 'get_capture_time_metadata_field_raw_detail') {
            const reportValue = report('602', '202', '1', '702', 'B-two.JPG', '3')
            if (payload.fieldId === '802') {
              await new Promise((resolve) => window.setTimeout(resolve, 180))
              return rawDetail(
                reportValue,
                field('1', '702', '802', '0', 'exif_date_time_original', '3'),
                'QUJD',
                'AAA',
              )
            }
            rawNativePathAttempt += 1
            return rawDetail(
              reportValue,
              field('1', '702', '803', '1', 'exif_offset_time_original', '4'),
              'AP/DKA==',
              rawNativePathAttempt === 1
                ? 'AB'
                : rawNativePathAttempt === 2
                  ? 'AAB'
                  : rawNativePathAttempt === 3 ? '////' : 'AA',
              rawNativePathAttempt === 4 ? '101' : '0',
            )
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

  const metadataCalls = async (command: string) => page.evaluate((target) => (
    window as Window & {
      __RAW_METADATA_FIXTURE__: {
        calls: Array<{ command: string; payload: Record<string, unknown> }>
      }
    }
  ).__RAW_METADATA_FIXTURE__.calls.filter((call) => call.command === target), command)

  expect(await metadataCalls('list_capture_time_metadata_reports')).toHaveLength(0)
  expect(await metadataCalls('list_capture_time_metadata_fields')).toHaveLength(0)
  expect(await metadataCalls('get_capture_time_metadata_field_raw_detail')).toHaveLength(0)

  await page.getByText('原始元数据证据（1 个来源）').click()
  await expect.poll(async () => (
    await metadataCalls('list_capture_time_metadata_reports')
  ).length).toBe(1)
  expect(await metadataCalls('list_capture_time_metadata_fields')).toHaveLength(0)
  expect(await metadataCalls('get_capture_time_metadata_field_raw_detail')).toHaveLength(0)

  await page.getByRole('button', { name: /B\.JPG/ }).click()
  await expect(page.getByText('原始元数据证据（3 个来源）')).toBeVisible()
  await page.getByText('原始元数据证据（3 个来源）').click()
  await expect(page.getByRole('button', { name: /B-one\.JPG/ })).toBeVisible()
  await page.waitForTimeout(220)
  await expect(page.getByRole('button', { name: /A\.JPG.*guiying-metadata/ })).toHaveCount(0)

  await page.getByRole('button', { name: /B-one\.JPG/ }).click()
  await expect.poll(async () => (
    await metadataCalls('list_capture_time_metadata_fields')
  ).length).toBe(1)
  expect(await metadataCalls('get_capture_time_metadata_field_raw_detail')).toHaveLength(0)
  await page.getByRole('button', { name: /B-two\.JPG/ }).click()
  await expect(page.getByRole('button', { name: /EXIF OffsetTimeOriginal/ })).toBeVisible()
  await page.waitForTimeout(220)
  await expect(page.getByRole('button', { name: /EXIF CreateDate/ })).toHaveCount(0)

  await page.getByRole('button', { name: /EXIF DateTimeOriginal/ }).click()
  await expect.poll(async () => (
    await metadataCalls('get_capture_time_metadata_field_raw_detail')
  ).length).toBe(1)
  await page.getByRole('button', { name: /EXIF OffsetTimeOriginal/ }).click()
  await expect(page.getByText(/原生路径字节不是有界、规范的 Base64/)).toBeVisible()
  await page.getByRole('button', { name: '重试原始字段' }).click()
  await expect.poll(async () => (
    await metadataCalls('get_capture_time_metadata_field_raw_detail')
  ).length).toBe(3)
  await expect(page.getByText(/原生路径字节不是有界、规范的 Base64/)).toBeVisible()
  await page.getByRole('button', { name: '重试原始字段' }).click()
  await expect(page.getByText(/原生路径字节不是有效 UTF-8/)).toBeVisible()
  await page.getByRole('button', { name: '重试原始字段' }).click()
  await expect(page.getByText(/TIFF 定位器偏移超过来源文件大小/)).toBeVisible()
  await page.getByRole('button', { name: '重试原始字段' }).click()
  const rawCode = page.getByLabel('字段原始字节 Base64')
  await expect(rawCode).toHaveText('AP/DKA==')
  await page.waitForTimeout(220)
  await expect(rawCode).toHaveText('AP/DKA==')
  await expect(page.getByText('QUJD', { exact: true })).toHaveCount(0)
  await expect(page.locator('.metadata-raw-detail')).not.toContainText('�')
  await expect(page.getByText(/历史证明 · 只读展示/)).toBeVisible()
  await expect(page.getByText(/不构成 keeper、时间 donor 或任何文件写入授权/)).toBeVisible()
  await expect(page.getByRole('button', { name: /复制|下载|写入|应用|设为保留|时间 donor/i })).toHaveCount(0)

  await page.getByRole('button', { name: /EXIF DateTimeOriginal/ }).click()
  await expect(rawCode).toHaveText('QUJD')
  await page.getByRole('button', { name: /EXIF OffsetTimeOriginal/ }).click()
  await expect(rawCode).toHaveText('AP/DKA==')

  const accessibility = await new AxeBuilder({ page }).analyze()
  expect(accessibility.violations).toEqual([])
  await page.screenshot({
    animations: 'disabled',
    path: `${evidenceDir}/results-raw-metadata-1280x820.png`,
  })

  await page.getByLabel('原始元数据字段摘要分页').getByRole('button', { name: '下一页' }).click()
  await expect(page.getByText(/偏移与长度超过来源文件大小/)).toBeVisible()
  await expect(page.getByRole('button', { name: /EXIF OffsetTimeOriginal/ })).toBeVisible()

  await page.getByLabel('原始元数据报告分页').getByRole('button', { name: '下一页' }).click()
  await expect(page.getByText('metadata report page fixture failure')).toBeVisible()
  await expect(page.getByRole('button', { name: /B-two\.JPG/ })).toBeVisible()
  await page.getByRole('alert')
    .filter({ hasText: 'metadata report page fixture failure' })
    .getByRole('button', { name: '重试失败页' })
    .click()
  await expect(page.getByRole('button', { name: /B-three\.JPG/ })).toBeVisible()
  const secondPageCalls = (await metadataCalls('list_capture_time_metadata_reports'))
    .filter((call) => call.payload.cursor === 'reports-2')
  expect(secondPageCalls).toHaveLength(2)

  await page.getByLabel('原始元数据报告分页').getByRole('button', { name: '下一页' }).click()
  await expect(page.getByText(/列表夹带了原始字节字段 rawBase64/)).toBeVisible()
  await expect(page.getByRole('button', { name: /B-three\.JPG/ })).toBeVisible()
  await expect(page.getByRole('button', { name: /B-malicious\.JPG/ })).toHaveCount(0)
  await page.getByRole('alert')
    .filter({ hasText: '列表夹带了原始字节字段 rawBase64' })
    .getByRole('button', { name: '重试失败页' })
    .click()
  await expect(page.getByText(/列表夹带了原始字节字段 rawValue/)).toBeVisible()
  await expect(page.getByRole('button', { name: /B-malicious\.JPG/ })).toHaveCount(0)
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
          if (command === 'select_scan_root') return { rootToken: `root-${'c'.repeat(64)}` }
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

test('a permanently failing acknowledgement still delivers the sealed report and can be retried', async ({ page }) => {
  await page.addInitScript(() => {
    const fixtureState = { acknowledgements: 0, allowAcknowledgement: false }
    const result = {
      schemaVersion: 1,
      scanRunId: '98',
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
      __ACK_RETRY_FIXTURE__: fixtureState,
      __TAURI_EVENT_PLUGIN_INTERNALS__: { unregisterListener: () => undefined },
      __TAURI_INTERNALS__: {
        transformCallback: () => 1,
        unregisterCallback: () => undefined,
        invoke: async (command: string) => {
          if (command === 'plugin:event|listen') return 1
          if (command === 'plugin:event|unlisten') return undefined
          if (command === 'select_scan_root') return { rootToken: `root-${'e'.repeat(64)}` }
          if (command === 'start_scan') return { jobId: 'scan-ack-pending' }
          if (command === 'get_scan_status') {
            return {
              jobId: 'scan-ack-pending', phase: 'completed', startedAtUnixMs: 1,
              finishedAtUnixMs: 2, scanRunId: '98', progress: null, result, error: null,
            }
          }
          if (command === 'list_duplicate_groups') return { items: [], nextCursor: null }
          if (command === 'acknowledge_scan') {
            fixtureState.acknowledgements += 1
            if (!fixtureState.allowAcknowledgement) {
              throw { code: 'IPC_UNAVAILABLE', message: 'ack fixture unavailable' }
            }
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

  await expect(page.getByRole('heading', { name: '发现 0 组确定重复' })).toBeVisible()
  await expect(page.getByText('报告已封存，但任务回执仍待确认。')).toBeVisible()
  expect(await page.evaluate(() => (
    window as Window & { __ACK_RETRY_FIXTURE__: { acknowledgements: number } }
  ).__ACK_RETRY_FIXTURE__.acknowledgements)).toBe(4)

  await page.evaluate(() => {
    (window as Window & {
      __ACK_RETRY_FIXTURE__: { allowAcknowledgement: boolean }
    }).__ACK_RETRY_FIXTURE__.allowAcknowledgement = true
  })
  await page.getByRole('button', { name: '重试确认' }).click()
  await expect(page.getByText('报告已封存，但任务回执仍待确认。')).toHaveCount(0)
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
          if (command === 'select_scan_root') return { rootToken: `root-${'d'.repeat(64)}` }
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
