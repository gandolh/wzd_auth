import type Database from "better-sqlite3";
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from "fastify";
import { afterEach, beforeEach, expect, it } from "vitest";

import { createApp, setPublicRegistration } from "../db/apps.js";
import { freshDb, seedApps } from "../db/test-support.js";
import { publicAppsRoutes } from "./public-apps.js";

/**
 * `GET /apps` — anonymous, and the two things worth asserting are that it is
 * genuinely anonymous and that it says nothing about a closed app.
 */

let db: Database.Database;
let app: FastifyInstance;

beforeEach(async () => {
  db = freshDb();

  app = Fastify({ logger: false });
  await app.register(publicAppsRoutes, { db });
  await app.ready();
});

afterEach(async () => {
  await app.close();
  db.close();
});

const list = (): Promise<LightMyRequestResponse> => app.inject({ method: "GET", url: "/apps" });

it("answers an anonymous caller with only the open apps", async () => {
  // `seedApps` opens `prm` and leaves `atrium` and `newspapper` closed.
  seedApps(db);

  const response = await list();
  expect(response.statusCode).toBe(200);
  expect(response.json()).toEqual([{ slug: "prm", name: "Public Resource Map" }]);
});

it("needs no cookie, no console session and no token", async () => {
  seedApps(db);

  // No headers at all — the point of the route.
  const response = await app.inject({ method: "GET", url: "/apps" });
  expect(response.statusCode).toBe(200);
});

/**
 * **The baseline role is authority and an anonymous caller has no use for it.**
 * Filtered by a serialisation schema rather than by a mapper, so a future change
 * that returned whole `AppRow`s still could not put it on the wire.
 */
it("returns only slug and name, never the baseline role or the timestamps", async () => {
  createApp(db, {
    slug: "open-app",
    name: "Open App",
    publicRegistration: true,
    baselineRole: "contributor",
  });

  const response = await list();
  const [entry] = response.json() as Record<string, unknown>[];

  expect(Object.keys(entry!).sort()).toEqual(["name", "slug"]);
  expect(response.body).not.toContain("contributor");
  expect(response.body).not.toContain("baseline");
  expect(response.body).not.toContain("createdAt");
});

/**
 * The oracle worth protecting is the *closed* estate. `/register` answers
 * `registration_closed` identically for a closed app and one that does not
 * exist, so it is not an app-discovery oracle either; this route must not
 * become one behind its back.
 */
it("says nothing at all about a closed app", async () => {
  createApp(db, { slug: "atrium", name: "Atrium" });
  createApp(db, { slug: "secret-thing", name: "Secret Thing" });

  const response = await list();
  expect(response.json()).toEqual([]);
  expect(response.body).not.toContain("atrium");
  expect(response.body).not.toContain("secret-thing");
});

it("follows the flag when an app is opened and closed again", async () => {
  createApp(db, { slug: "atrium", name: "Atrium" });
  expect((await list()).json()).toEqual([]);

  setPublicRegistration(db, "atrium", true, "reader");
  expect((await list()).json()).toEqual([{ slug: "atrium", name: "Atrium" }]);

  setPublicRegistration(db, "atrium", false);
  expect((await list()).json()).toEqual([]);
});

/**
 * A fresh estate has no apps: `seedApps` is test support and production seeds
 * nothing. `[]` is a **state**, not a failure — brief 07 records the same trap
 * for `/register`, where it "looks like a bug".
 */
it("answers an empty estate with an empty array and a 200", async () => {
  const response = await list();
  expect(response.statusCode).toBe(200);
  expect(response.json()).toEqual([]);
});

it("sends no-store, so closing an app takes effect on the next request", async () => {
  const response = await app.inject({ method: "GET", url: "/apps" });
  expect(response.headers["cache-control"]).toBe("no-store");
});
