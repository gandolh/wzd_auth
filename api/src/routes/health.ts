import type { FastifyInstance } from "fastify";

/**
 * `GET /health` — the only route brief 00 adds. pm2 and any uptime check hit
 * this, so it stays cheap and dependency-free: no database touch, no auth,
 * nothing that can go slow or fail for a reason unrelated to "is the process
 * up." Later briefs add their own routes as separate plugins registered by
 * `buildApp` (see `api/src/app.ts`); this file does not grow to cover them.
 */
export async function healthRoutes(app: FastifyInstance): Promise<void> {
  app.get("/health", async () => {
    return { status: "ok" };
  });
}
