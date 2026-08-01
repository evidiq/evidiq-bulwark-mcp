export function extractPaymentHeader(headers: Record<string, string | string[] | undefined>): string | null {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "payment-signature") {
      if (Array.isArray(value)) return value[0];
      if (typeof value === "string") return value;
    }
  }
  return null;
}
