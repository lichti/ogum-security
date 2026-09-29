import { test, expect } from "@playwright/test";

/**
 * US-13.11 — smoke E2E real (noturno, contra o stack completo do compose).
 *
 * Pré-condições (provisionadas pelo workflow nightly-e2e.yml):
 * - backend em http://localhost:8000 (AUTH_ENABLED=true)
 * - frontend em http://localhost:3000
 * - tenant `dev` registrado com token emitido (OGUM_E2E_API_TOKEN)
 *
 * Sem login UI ainda (Epic 06 Sprint 2): o token interim vai ao localStorage
 * (`ogum_api_token`), mesma fonte que `lib/api.ts` lê.
 */

const API = process.env.API_URL ?? "http://localhost:8000";
const TOKEN = process.env.OGUM_E2E_API_TOKEN ?? "";

test.describe("API health", () => {
  test("backend responde /health sem autenticação", async ({ request }) => {
    const res = await request.get(`${API}/health`);
    expect(res.status()).toBe(200);
    const body = await res.json();
    expect(body.status).toBe("ok");
  });

  test("rota protegida sem token → 401 (gate interim ativo)", async ({ request }) => {
    const res = await request.get(`${API}/api/v1/inventory`);
    expect(res.status()).toBe(401);
    expect(res.headers()["www-authenticate"]).toBe("Bearer");
  });

  test("rota protegida com token → 200 (resolver estrito: tenant dev registrado)", async ({ request }) => {
    test.skip(!TOKEN, "OGUM_E2E_API_TOKEN não provisionado pelo workflow");
    const res = await request.get(`${API}/api/v1/inventory`, {
      headers: { Authorization: `Bearer ${TOKEN}` },
    });
    expect(res.status()).toBe(200);
  });
});

test.describe("UI smoke", () => {
  test.use({
    storageState: async () => {
      // injeta o token interim antes de qualquer navegação
      return {
        cookies: [],
        origins: [
          {
            origin: process.env.BASE_URL ?? "http://localhost:3000",
            localStorage: TOKEN
              ? [{ name: "ogum_api_token", value: TOKEN }]
              : [],
          },
        ],
      };
    },
  });

  test("dashboard carrega com sidebar e métricas", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("aside")).toBeVisible();
    await expect(page.locator("header")).toBeVisible();
  });

  test("/findings renderiza a página (com token do tenant dev)", async ({ page }) => {
    test.skip(!TOKEN, "OGUM_E2E_API_TOKEN não provisionado pelo workflow");
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    await page.goto("/findings");
    await expect(page.locator("table, [data-testid='findings-empty'], main").first()).toBeVisible();
    expect(errors, "nenhum pageerror no carregamento").toEqual([]);
  });
});
