import { test, expect } from "@playwright/test";

/**
 * Authentication flow — critical path E2E tests.
 * These tests assume the full Docker Compose stack is running.
 */
test.describe("Authentication", () => {
  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/dashboard");
    await expect(page).toHaveURL(/\/login/);
  });

  test.skip("valid credentials redirect to dashboard", async ({ page }) => {
    // Implement when auth is wired to real OIDC provider in dev mode
    // await page.goto("/login");
    // await page.fill('[name="email"]', "admin@example.com");
    // await page.fill('[name="password"]', "test-password");
    // await page.click('[type="submit"]');
    // await expect(page).toHaveURL("/dashboard");
    // await expect(page.locator("h1")).toContainText("Dashboard");
  });

  test.skip("expired token triggers re-authentication", async ({ page }) => {
    // Implement when JWT refresh flow is in place
  });
});
