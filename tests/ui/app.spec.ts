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
