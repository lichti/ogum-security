import { test, expect } from "@playwright/test";

/**
 * Findings page E2E tests — critical path.
 */
test.describe("Findings", () => {
  test.skip("findings table renders with severity badges", async ({ page }) => {
    // Implement when Ogum.Static CSPM scan results are available in test env
    // await page.goto("/findings");
    // await expect(page.locator("table")).toBeVisible();
    // await expect(page.locator('[data-testid="severity-badge"]').first()).toBeVisible();
  });

  test.skip("severity filter shows only CRITICAL findings", async ({ page }) => {
    // await page.goto("/findings");
    // await page.selectOption('[data-testid="severity-filter"]', "CRITICAL");
    // const badges = page.locator('[data-testid="severity-badge"]');
    // const count = await badges.count();
    // for (let i = 0; i < count; i++) {
    //   await expect(badges.nth(i)).toHaveText("CRITICAL");
    // }
  });

  test.skip("clicking a finding opens the detail panel", async ({ page }) => {
    // await page.goto("/findings");
    // await page.locator("tbody tr").first().click();
    // await expect(page.locator('[data-testid="detail-panel"]')).toBeVisible();
    // await expect(page.locator('[data-testid="finding-title"]')).toBeVisible();
  });

  test.skip("Generate PR button is visible for CRITICAL findings", async ({ page }) => {
    // await page.goto("/findings");
    // await page.locator('[data-severity="CRITICAL"]').first().click();
    // await expect(
    //   page.locator('[data-testid="generate-pr-button"]')
    // ).toBeVisible();
  });

  test.skip("findings count updates after filter change", async ({ page }) => {
    // Implement when filter state management is wired to API
  });
});
