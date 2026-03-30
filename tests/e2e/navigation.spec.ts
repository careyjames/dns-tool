import { test, expect } from '@playwright/test';

test.describe('Navigation', () => {
  test('all navbar links are present and clickable', async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');

    const toggler = page.locator('.navbar-toggler');
    if (await toggler.isVisible()) {
      await toggler.click();
      await page.waitForTimeout(500);
    }

    const navLinks = [
      { text: 'Analyze', href: '/' },
      { text: 'IP Intelligence', href: '/investigate' },
      { text: 'Email Header', href: '/email-header' },
      { text: 'History', href: '/history' },
      { text: 'Statistics', href: '/stats' },
      { text: 'Sources', href: '/sources' },
    ];

    for (const link of navLinks) {
      const el = page.locator(`nav a:has-text("${link.text}")`).first();
      await expect(el).toBeVisible({ timeout: 10000 });
    }
  });

  test('history page loads', async ({ page }) => {
    await page.goto('/history');
    await expect(page).toHaveTitle(/DNS Tool/i);
    await expect(page.locator('h1')).toBeVisible();
  });

  test('IP Intelligence page loads with input form', async ({ page }) => {
    await page.goto('/investigate');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });

  test('sources page loads', async ({ page }) => {
    await page.goto('/sources');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });

  test('stats page loads', async ({ page }) => {
    await page.goto('/stats');
    await expect(page).toHaveTitle(/DNS Tool/i);
  });
});

test.describe('Responsive Layout', () => {
  test('page is usable at mobile width', async ({ page }) => {
    test.skip(test.info().project.name.includes('iphone') || test.info().project.name.includes('ipad'), 'viewport fixed by device profile');
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto('/');
    await expect(page.locator('#domainForm')).toBeVisible();
    await expect(page.locator('#domain')).toBeVisible();
  });

  test('page is usable at tablet width', async ({ page }) => {
    test.skip(test.info().project.name.includes('iphone') || test.info().project.name.includes('ipad'), 'viewport fixed by device profile');
    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto('/');
    await expect(page.locator('#domainForm')).toBeVisible();
  });
});
