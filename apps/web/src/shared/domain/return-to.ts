const SAFE_PATH_PREFIX = "/";

export function safeReturnTo(value: unknown, fallback = "/overview"): string {
  if (typeof value !== "string" || !value.startsWith(SAFE_PATH_PREFIX)) return fallback;
  if (value.startsWith("//") || value.includes("\\") || value.includes("\0")) return fallback;

  try {
    const base = new URL("https://jw-agent.invalid");
    const target = new URL(value, base);
    if (target.origin !== base.origin) return fallback;
    if (target.pathname === "/login") return fallback;
    return `${target.pathname}${target.search}${target.hash}`;
  } catch {
    return fallback;
  }
}
