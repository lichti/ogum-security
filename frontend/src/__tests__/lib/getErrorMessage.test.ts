import { getErrorMessage } from "@/lib/api"

describe("getErrorMessage (US-14.25)", () => {
  it("extrai detail string do corpo da resposta axios", () => {
    const error = {
      isAxiosError: true,
      response: { data: { detail: "Provider not found" } },
      message: "Request failed with status code 404",
    }
    expect(getErrorMessage(error)).toBe("Provider not found")
  })

  it("cai para a mensagem do axios quando não há detail", () => {
    const error = {
      isAxiosError: true,
      response: { data: {} },
      message: "Network Error",
    }
    expect(getErrorMessage(error)).toBe("Network Error")
  })

  it("usa o fallback para erros desconhecidos", () => {
    expect(getErrorMessage(undefined, "Fallback")).toBe("Fallback")
    expect(getErrorMessage("boom", "Fallback")).toBe("Fallback")
  })

  it("preserva mensagens de Error genéricos", () => {
    expect(getErrorMessage(new Error("algo quebrou"))).toBe("algo quebrou")
  })
})
