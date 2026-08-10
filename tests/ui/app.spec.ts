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
    path: `${evidenceDir}/landing-1280x820.png`,
    fullPage: true,
  })
})

test('read-only demo scan exposes progress and exact duplicate evidence', async ({ page }) => {
  await page.goto('/')

  await page.getByRole('button', { name: '运行合成数据扫描演示' }).click()
  await expect(page.getByRole('heading', { name: '正在建立内容证据' })).toBeVisible()

  await page.screenshot({
    path: `${evidenceDir}/scanning-1280x820.png`,
    fullPage: true,
  })

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
    path: `${evidenceDir}/results-1024x768.png`,
    fullPage: true,
  })
})

test('a transient native status failure keeps cancellation control and recovers', async ({ page }) => {
  await page.addInitScript(() => {
    let callbackId = 0
    let statusQueries = 0
    const callbacks = new Map<number, (...args: unknown[]) => void>()
    const report = {
      schema_version: 3,
      roots: [{ display: '/Volumes/Test Photos', encoding: 'unix_bytes', raw_base64: 'L1ZvbHVtZXMvVGVzdCBQaG90b3M' }],
      files: [],
      duplicate_groups: [],
      issues: [],
      stats: {
        entries_seen: 0,
        media_files: 0,
        files_sampled: 0,
        duplicate_files: 0,
        logical_reclaimable_bytes: 0,
        directory_identity_revisits_skipped: 0,
      },
      status: 'complete',
      cancelled: false,
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
                progress: null,
                report: null,
                error: null,
              }
            }
            return {
              jobId: 'scan-fixture',
              phase: 'completed',
              startedAtUnixMs: 1_000,
              finishedAtUnixMs: 1_400,
              progress: null,
              report,
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
