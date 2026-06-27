import { test, expect } from "@playwright/test";

/**
 * Inventory page E2E tests — critical path.
 * Assumes Docker Compose stack running with at least one cloud account connected.
 */
test.describe("Inventory", () => {
  test.skip("inventory table renders after successful discovery", async ({ page }) => {
    // Implement when Ogum.Inventory is complete and a test account is seeded
    // await page.goto("/inventory");
    // await expect(page.locator("table")).toBeVisible();
    // await expect(page.locator("tbody tr").first()).toBeVisible();
  });

  test.skip("provider tab filter shows only AWS resources", async ({ page }) => {
    // await page.goto("/inventory");
    // await page.click('[data-testid="provider-tab-aws"]');
    // const rows = page.locator("tbody tr");
    // const count = await rows.count();
    // expect(count).toBeGreaterThan(0);
    // for (let i = 0; i < count; i++) {
    //   await expect(rows.nth(i).locator('[data-provider]')).toHaveAttribute("data-provider", "aws");
    // }
  });

  test.skip("clicking a resource opens the detail panel", async ({ page }) => {
    // await page.goto("/inventory");
    // await page.locator("tbody tr").first().click();
    // await expect(page.locator('[data-testid="detail-panel"]')).toBeVisible();
  });

  test.skip("search filters resources by name", async ({ page }) => {
    // await page.goto("/inventory");
    // await page.fill('[data-testid="inventory-search"]', "web-server");
    // await expect(page.locator("tbody tr")).toHaveCount(1);
  });

  test.skip("empty state renders when no accounts connected", async ({ page }) => {
    // Requires a clean tenant with no accounts
    // await page.goto("/inventory");
    // await expect(page.locator('[data-testid="empty-state"]')).toBeVisible();
  });
});
