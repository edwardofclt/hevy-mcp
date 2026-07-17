import { randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import cookieParser from "cookie-parser";
import express from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Db } from "../utils/db.js";
import { deriveCookieSecret } from "../utils/session.js";

const verifyAppleIdToken = vi.fn();
const buildAppleAuthUrl = vi.fn();

vi.mock("../utils/apple.js", () => ({
	buildAppleAuthUrl: (...args: unknown[]) => buildAppleAuthUrl(...args),
	verifyAppleIdToken: (...args: unknown[]) => verifyAppleIdToken(...args),
}));

const { createAuthRoutes } = await import("./auth.js");

const MASTER_KEY = randomBytes(32);
const APPLE_CONFIG = {
	teamId: "team1",
	clientId: "client1",
	keyId: "key1",
	privateKey: "unused-in-tests",
	redirectUri: "https://example.com/auth/apple/callback",
};

interface FakeUser {
	id: string;
	appleSub: string;
	email?: string;
}

function createFakeDb(): Db {
	const usersBySub = new Map<string, FakeUser>();
	const hevyKeys = new Map<string, { plaintext: string; updatedAt: number }>();
	const webSessions = new Map<string, { userId: string; expiresAt: number }>();
	let nextId = 1;

	return {
		upsertUser(appleSub: string, email: string | undefined) {
			const existing = usersBySub.get(appleSub);
			if (existing) {
				existing.email = email;
				return { id: existing.id };
			}
			const id = `user-${nextId++}`;
			usersBySub.set(appleSub, { id, appleSub, email });
			return { id };
		},
		getUserByAppleSub: () => {
			throw new Error("not implemented");
		},
		saveHevyKey(userId: string, plaintext: string) {
			hevyKeys.set(userId, { plaintext, updatedAt: Date.now() });
		},
		getHevyKeyStatus(userId: string) {
			const row = hevyKeys.get(userId);
			if (!row) return { configured: false };
			return { configured: true, updatedAt: row.updatedAt };
		},
		getDecryptedHevyKey: () => {
			throw new Error("not implemented");
		},
		createWebSession(userId: string, ttlMs: number, now: number = Date.now()) {
			const id = randomBytes(16).toString("base64url");
			const expiresAt = now + ttlMs;
			webSessions.set(id, { userId, expiresAt });
			return { id, expiresAt };
		},
		getWebSession(sessionId: string, now: number = Date.now()) {
			const row = webSessions.get(sessionId);
			if (!row || row.expiresAt <= now) return undefined;
			return { userId: row.userId };
		},
		deleteWebSession(sessionId: string) {
			webSessions.delete(sessionId);
		},
		createAuthCode: () => {
			throw new Error("not implemented");
		},
		consumeAuthCode: () => {
			throw new Error("not implemented");
		},
		createMcpToken: () => {
			throw new Error("not implemented");
		},
		getMcpToken: () => {
			throw new Error("not implemented");
		},
		gcExpired: () => {
			throw new Error("not implemented");
		},
		close: () => {},
	};
}

async function startApp(db: Db): Promise<{
	base: string;
	close: () => Promise<void>;
}> {
	const app = express();
	app.use(express.urlencoded({ extended: false }));
	app.use(cookieParser(deriveCookieSecret(MASTER_KEY)));
	const router = createAuthRoutes({
		db,
		masterKey: MASTER_KEY,
		apple: APPLE_CONFIG,
	});
	app.use(router);
	const server: Server = await new Promise((resolve) => {
		const s = app.listen(0, "127.0.0.1", () => resolve(s));
	});
	const { port } = server.address() as AddressInfo;
	return {
		base: `http://127.0.0.1:${port}`,
		close: () =>
			new Promise<void>((resolve, reject) =>
				server.close((err) => (err ? reject(err) : resolve())),
			),
	};
}

function extractCookie(headers: Headers): string | undefined {
	const raw = headers.get("set-cookie");
	if (!raw) return undefined;
	return raw.split(";")[0];
}

let db: Db;
let app: Awaited<ReturnType<typeof startApp>>;

beforeEach(async () => {
	vi.clearAllMocks();
	db = createFakeDb();
	app = await startApp(db);
});

afterEach(async () => {
	await app.close();
});

describe("GET /login", () => {
	it("renders a Sign in with Apple button linking to the (mocked) Apple auth URL", async () => {
		buildAppleAuthUrl.mockReturnValue("https://appleid.apple.com/auth/x");
		const r = await fetch(`${app.base}/login`);
		expect(r.status).toBe(200);
		const text = await r.text();
		expect(text).toContain("Sign in with Apple");
		expect(text).toContain('href="https://appleid.apple.com/auth/x"');
		expect(buildAppleAuthUrl).toHaveBeenCalled();
	});
});

describe("POST /auth/apple/callback", () => {
	it("creates a user, sets a session cookie, and redirects to /account by default", async () => {
		verifyAppleIdToken.mockResolvedValue({ sub: "sub-1", email: "a@b.com" });
		const r = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state: "" }),
		});
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toBe("/account");
		expect(extractCookie(r.headers)).toBeTruthy();
	});

	it("redirects to a same-origin next path decoded from state", async () => {
		verifyAppleIdToken.mockResolvedValue({ sub: "sub-2" });
		const state = Buffer.from(
			JSON.stringify({ next: "/authorize?client_id=c1" }),
		).toString("base64url");
		const r = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state }),
		});
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toBe("/authorize?client_id=c1");
	});

	it("401s and sets no cookie when verification throws", async () => {
		verifyAppleIdToken.mockRejectedValue(new Error("bad token"));
		const r = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state: "" }),
		});
		expect(r.status).toBe(401);
		expect(extractCookie(r.headers)).toBeFalsy();
	});
});

describe("GET /account", () => {
	it("redirects to /login when there is no session cookie", async () => {
		const r = await fetch(`${app.base}/account`, { redirect: "manual" });
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toContain("/login");
	});

	it("shows the not-configured state for a signed-in user with no key", async () => {
		verifyAppleIdToken.mockResolvedValue({ sub: "sub-3" });
		const login = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state: "" }),
		});
		const cookie = extractCookie(login.headers) as string;

		const r = await fetch(`${app.base}/account`, {
			headers: { cookie },
		});
		expect(r.status).toBe(200);
		const text = await r.text();
		expect(text).toContain("No Hevy API key configured yet.");
		expect(text).not.toMatch(/hevy_[a-zA-Z0-9]{10,}/);
	});
});

describe("POST /account/hevy-key", () => {
	async function signIn(sub: string): Promise<string> {
		verifyAppleIdToken.mockResolvedValue({ sub });
		const login = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state: "" }),
		});
		return extractCookie(login.headers) as string;
	}

	it("saves the key and redirects to /account, which then shows configured", async () => {
		const cookie = await signIn("sub-4");
		const r = await fetch(`${app.base}/account/hevy-key`, {
			method: "POST",
			redirect: "manual",
			headers: {
				cookie,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ hevy_api_key: "  my-secret-key  " }),
		});
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toBe("/account");

		const saveSpy = db.saveHevyKey as unknown;
		expect(typeof saveSpy).toBe("function");

		const accountR = await fetch(`${app.base}/account`, {
			headers: { cookie },
		});
		const text = await accountR.text();
		expect(text).toContain("Hevy API key: configured");
	});

	it("passes the trimmed plaintext to db.saveHevyKey", async () => {
		const spy = vi.spyOn(db, "saveHevyKey");
		const cookie = await signIn("sub-5");
		await fetch(`${app.base}/account/hevy-key`, {
			method: "POST",
			redirect: "manual",
			headers: {
				cookie,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ hevy_api_key: "  trimmed-key  " }),
		});
		expect(spy).toHaveBeenCalledWith(
			expect.any(String),
			"trimmed-key",
			MASTER_KEY,
		);
	});

	it("400s on an empty key", async () => {
		const cookie = await signIn("sub-6");
		const r = await fetch(`${app.base}/account/hevy-key`, {
			method: "POST",
			headers: {
				cookie,
				"content-type": "application/x-www-form-urlencoded",
			},
			body: new URLSearchParams({ hevy_api_key: "   " }),
		});
		expect(r.status).toBe(400);
	});
});

describe("POST /account/logout", () => {
	it("clears the cookie, redirects to /login, and invalidates the session", async () => {
		verifyAppleIdToken.mockResolvedValue({ sub: "sub-7" });
		const login = await fetch(`${app.base}/auth/apple/callback`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({ id_token: "fake-token", state: "" }),
		});
		const cookie = extractCookie(login.headers) as string;

		const r = await fetch(`${app.base}/account/logout`, {
			method: "POST",
			redirect: "manual",
			headers: { cookie },
		});
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toBe("/login");

		const after = await fetch(`${app.base}/account`, {
			headers: { cookie },
			redirect: "manual",
		});
		expect(after.status).toBe(302);
		expect(after.headers.get("location")).toContain("/login");
	});
});
