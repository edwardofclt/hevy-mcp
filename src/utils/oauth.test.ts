import { createHash, randomBytes } from "node:crypto";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import express, { type RequestHandler } from "express";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { AuthCodeParams, AuthCodeRecord, Db } from "./db.js";
import { createOAuthShim } from "./oauth.js";

const TEST_USER = "user-1";

function pkcePair(): { verifier: string; challenge: string } {
	const verifier = randomBytes(32).toString("base64url");
	const challenge = createHash("sha256")
		.update(verifier)
		.digest("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
	return { verifier, challenge };
}

function createFakeDb(): Db {
	const authCodes = new Map<string, AuthCodeRecord & { expiresAt: number }>();
	const tokens = new Map<string, { userId: string; expiresAt: number }>();

	return {
		upsertUser: () => {
			throw new Error("not implemented");
		},
		getUserByAppleSub: () => {
			throw new Error("not implemented");
		},
		saveHevyKey: () => {
			throw new Error("not implemented");
		},
		getHevyKeyStatus: () => {
			throw new Error("not implemented");
		},
		getDecryptedHevyKey: () => {
			throw new Error("not implemented");
		},
		createWebSession: () => {
			throw new Error("not implemented");
		},
		getWebSession: () => {
			throw new Error("not implemented");
		},
		deleteWebSession: () => {
			throw new Error("not implemented");
		},
		createAuthCode(params: AuthCodeParams): { code: string } {
			const code = randomBytes(32).toString("base64url");
			const now = params.now ?? Date.now();
			authCodes.set(code, {
				userId: params.userId,
				redirectUri: params.redirectUri,
				codeChallenge: params.codeChallenge,
				codeChallengeMethod: params.codeChallengeMethod,
				clientId: params.clientId,
				expiresAt: now + params.ttlMs,
			});
			return { code };
		},
		consumeAuthCode(
			code: string,
			now: number = Date.now(),
		): AuthCodeRecord | undefined {
			const record = authCodes.get(code);
			authCodes.delete(code);
			if (!record || record.expiresAt <= now) return undefined;
			const { expiresAt, ...rest } = record;
			return rest;
		},
		createMcpToken(
			userId: string,
			ttlMs: number,
			now: number = Date.now(),
		): { token: string; expiresAt: number } {
			const token = randomBytes(32).toString("base64url");
			const expiresAt = now + ttlMs;
			tokens.set(token, { userId, expiresAt });
			return { token, expiresAt };
		},
		getMcpToken(
			token: string,
			now: number = Date.now(),
		): { userId: string } | undefined {
			const record = tokens.get(token);
			if (!record || record.expiresAt <= now) return undefined;
			return { userId: record.userId };
		},
		gcExpired(now: number = Date.now()): void {
			for (const [k, v] of authCodes)
				if (v.expiresAt <= now) authCodes.delete(k);
			for (const [k, v] of tokens) if (v.expiresAt <= now) tokens.delete(k);
		},
		close: () => {},
	};
}

const fakeRequireWebSession: RequestHandler = (req, res, next) => {
	const userId = req.header("x-test-user-id");
	if (!userId) {
		const next_ = encodeURIComponent(req.originalUrl);
		res.redirect(302, `/login?next=${next_}`);
		return;
	}
	res.locals.userId = userId;
	next();
};

async function startApp(): Promise<{
	base: string;
	close: () => Promise<void>;
}> {
	const app = express();
	app.use(express.json());
	app.use(express.urlencoded({ extended: false }));
	const oauth = createOAuthShim({ db: createFakeDb() });
	oauth.mount(app, fakeRequireWebSession);
	app.get("/protected", oauth.requireBearer, (_req, res) => {
		res.json({ ok: true, userId: res.locals.userId });
	});
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

let app: Awaited<ReturnType<typeof startApp>>;

beforeEach(async () => {
	app = await startApp();
});

afterEach(async () => {
	await app.close();
});

describe("oauth discovery", () => {
	it("serves protected-resource metadata", async () => {
		const r = await fetch(`${app.base}/.well-known/oauth-protected-resource`);
		expect(r.status).toBe(200);
		const body = (await r.json()) as Record<string, unknown>;
		expect(body.authorization_servers).toEqual([app.base]);
	});

	it("serves authorization-server metadata", async () => {
		const r = await fetch(`${app.base}/.well-known/oauth-authorization-server`);
		expect(r.status).toBe(200);
		const body = (await r.json()) as Record<string, unknown>;
		expect(body.authorization_endpoint).toBe(`${app.base}/authorize`);
		expect(body.token_endpoint).toBe(`${app.base}/token`);
		expect(body.code_challenge_methods_supported).toContain("S256");
	});
});

describe("dynamic registration", () => {
	it("returns a client_id", async () => {
		const r = await fetch(`${app.base}/register`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ redirect_uris: ["https://example.com/cb"] }),
		});
		expect(r.status).toBe(201);
		const body = (await r.json()) as Record<string, unknown>;
		expect(body.client_id).toMatch(/^mcp-/);
	});
});

describe("authorize", () => {
	it("redirects to /login when not signed in", async () => {
		const url = `${app.base}/authorize?response_type=code&redirect_uri=${encodeURIComponent("https://example.com/cb")}&code_challenge=abc&code_challenge_method=S256&state=xyz&client_id=c1`;
		const r = await fetch(url, { redirect: "manual" });
		expect(r.status).toBe(302);
		const loc = r.headers.get("location") as string;
		expect(loc).toContain("/login");
		expect(loc).toContain(encodeURIComponent("/authorize"));
	});

	it("renders a consent screen when signed in", async () => {
		const url = `${app.base}/authorize?response_type=code&redirect_uri=${encodeURIComponent("https://example.com/cb")}&code_challenge=abc&code_challenge_method=S256&state=xyz&client_id=c1`;
		const r = await fetch(url, {
			headers: { "x-test-user-id": TEST_USER },
		});
		expect(r.status).toBe(200);
		const text = await r.text();
		expect(text).not.toContain('name="secret"');
		expect(text).toContain("c1");
		expect(text).toContain("Authorize");
	});

	it("400s when redirect_uri missing", async () => {
		const r = await fetch(
			`${app.base}/authorize?response_type=code&code_challenge=abc`,
			{ headers: { "x-test-user-id": TEST_USER } },
		);
		expect(r.status).toBe(400);
	});

	it("POST redirects to /login when not signed in", async () => {
		const r = await fetch(`${app.base}/authorize`, {
			method: "POST",
			redirect: "manual",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				redirect_uri: "https://example.com/cb",
				code_challenge: "abc",
				code_challenge_method: "S256",
				state: "xyz",
				client_id: "c1",
			}).toString(),
		});
		expect(r.status).toBe(302);
		expect(r.headers.get("location")).toContain("/login");
	});

	it("POST redirects with code when signed in", async () => {
		const { challenge } = pkcePair();
		const r = await fetch(`${app.base}/authorize`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				"x-test-user-id": TEST_USER,
			},
			body: new URLSearchParams({
				redirect_uri: "https://example.com/cb",
				code_challenge: challenge,
				code_challenge_method: "S256",
				state: "xyz",
				client_id: "c1",
			}).toString(),
		});
		expect(r.status).toBe(302);
		const loc = r.headers.get("location");
		expect(loc).toBeTruthy();
		const url = new URL(loc as string);
		expect(url.origin + url.pathname).toBe("https://example.com/cb");
		expect(url.searchParams.get("state")).toBe("xyz");
		expect(url.searchParams.get("code")).toBeTruthy();
	});
});

async function getCode(challenge: string): Promise<string> {
	const r = await fetch(`${app.base}/authorize`, {
		method: "POST",
		redirect: "manual",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-test-user-id": TEST_USER,
		},
		body: new URLSearchParams({
			redirect_uri: "https://example.com/cb",
			code_challenge: challenge,
			code_challenge_method: "S256",
			state: "",
			client_id: "c1",
		}).toString(),
	});
	const url = new URL(r.headers.get("location") as string);
	return url.searchParams.get("code") as string;
}

describe("token + bearer", () => {
	it("exchanges code for token with valid PKCE and resolves the user", async () => {
		const { verifier, challenge } = pkcePair();
		const code = await getCode(challenge);
		const r = await fetch(`${app.base}/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://example.com/cb",
				code_verifier: verifier,
			}).toString(),
		});
		expect(r.status).toBe(200);
		const body = (await r.json()) as Record<string, unknown>;
		expect(body.token_type).toBe("Bearer");
		expect(typeof body.access_token).toBe("string");

		const ok = await fetch(`${app.base}/protected`, {
			headers: { authorization: `Bearer ${body.access_token}` },
		});
		expect(ok.status).toBe(200);
		const okBody = (await ok.json()) as Record<string, unknown>;
		expect(okBody.userId).toBe(TEST_USER);
	});

	it("rejects token exchange with wrong verifier", async () => {
		const { challenge } = pkcePair();
		const code = await getCode(challenge);
		const r = await fetch(`${app.base}/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://example.com/cb",
				code_verifier: "not-the-verifier",
			}).toString(),
		});
		expect(r.status).toBe(400);
	});

	it("rejects reuse of an authorization code", async () => {
		const { verifier, challenge } = pkcePair();
		const code = await getCode(challenge);
		const ok = await fetch(`${app.base}/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://example.com/cb",
				code_verifier: verifier,
			}).toString(),
		});
		expect(ok.status).toBe(200);
		const dupe = await fetch(`${app.base}/token`, {
			method: "POST",
			headers: { "content-type": "application/x-www-form-urlencoded" },
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: "https://example.com/cb",
				code_verifier: verifier,
			}).toString(),
		});
		expect(dupe.status).toBe(400);
	});

	it("401s requests without bearer", async () => {
		const r = await fetch(`${app.base}/protected`);
		expect(r.status).toBe(401);
		expect(r.headers.get("www-authenticate")).toMatch(/^Bearer /);
	});

	it("401s requests with unknown token", async () => {
		const r = await fetch(`${app.base}/protected`, {
			headers: { authorization: "Bearer not-a-real-token" },
		});
		expect(r.status).toBe(401);
	});
});
