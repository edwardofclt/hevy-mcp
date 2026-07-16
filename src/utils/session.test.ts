import { randomBytes } from "node:crypto";
import type { Request, Response } from "express";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Db } from "./db.js";
import {
	clearSessionCookie,
	createRequireWebSession,
	deriveCookieSecret,
	SESSION_COOKIE_NAME,
	setSessionCookie,
} from "./session.js";

describe("deriveCookieSecret", () => {
	it("is deterministic", () => {
		const key = randomBytes(32);
		const secret1 = deriveCookieSecret(key);
		const secret2 = deriveCookieSecret(key);
		expect(secret1).toBe(secret2);
	});

	it("produces different secrets for different keys", () => {
		const key1 = randomBytes(32);
		const key2 = randomBytes(32);
		const secret1 = deriveCookieSecret(key1);
		const secret2 = deriveCookieSecret(key2);
		expect(secret1).not.toBe(secret2);
	});

	it("output is never equal to the masterKey's hex representation", () => {
		const key = randomBytes(32);
		const secret = deriveCookieSecret(key);
		expect(secret).not.toBe(key.toString("hex"));
	});

	it("output is never equal to the masterKey's base64 representation", () => {
		const key = randomBytes(32);
		const secret = deriveCookieSecret(key);
		expect(secret).not.toBe(key.toString("base64"));
	});
});

describe("createRequireWebSession", () => {
	let mockDb: Db;
	let mockReq: Partial<Request>;
	let mockRes: Partial<Response>;
	let nextFn: ReturnType<typeof vi.fn> & ((err?: unknown) => void);

	beforeEach(() => {
		nextFn = vi.fn() as ReturnType<typeof vi.fn> & ((err?: unknown) => void);

		mockDb = {
			getWebSession: vi.fn(),
		} as unknown as Db;

		mockReq = {
			signedCookies: {},
			originalUrl: "/account",
		};

		mockRes = {
			redirect: vi.fn(),
			locals: {},
		};
	});

	it("calls next() and sets userId for valid session cookie", () => {
		const sessionId = "valid-session";
		const userId = "user-123";

		mockReq.signedCookies![SESSION_COOKIE_NAME] = sessionId;
		(mockDb.getWebSession as ReturnType<typeof vi.fn>).mockReturnValue({
			userId,
		});

		const middleware = createRequireWebSession(mockDb);
		middleware(
			mockReq as Request,
			mockRes as Response,
			nextFn as unknown as (err?: unknown) => void,
		);

		expect(nextFn).toHaveBeenCalled();
		expect(mockRes.locals!.userId).toBe(userId);
		expect(mockRes.redirect).not.toHaveBeenCalled();
	});

	it("redirects to login for missing cookie", () => {
		mockReq.signedCookies![SESSION_COOKIE_NAME] = undefined;

		const middleware = createRequireWebSession(mockDb);
		middleware(
			mockReq as Request,
			mockRes as Response,
			nextFn as unknown as (err?: unknown) => void,
		);

		expect(mockRes.redirect).toHaveBeenCalledWith(
			302,
			expect.stringContaining("/login?next="),
		);
		expect(nextFn).not.toHaveBeenCalled();
	});

	it("redirects to login for tampered cookie (signedCookies === false)", () => {
		mockReq.signedCookies![SESSION_COOKIE_NAME] = false as unknown as string;

		const middleware = createRequireWebSession(mockDb);
		middleware(
			mockReq as Request,
			mockRes as Response,
			nextFn as unknown as (err?: unknown) => void,
		);

		expect(mockRes.redirect).toHaveBeenCalledWith(
			302,
			expect.stringContaining("/login?next="),
		);
		expect(nextFn).not.toHaveBeenCalled();
	});

	it("redirects to login for expired/unknown session", () => {
		const sessionId = "expired-session";

		mockReq.signedCookies![SESSION_COOKIE_NAME] = sessionId;
		(mockDb.getWebSession as ReturnType<typeof vi.fn>).mockReturnValue(
			undefined,
		);

		const middleware = createRequireWebSession(mockDb);
		middleware(
			mockReq as Request,
			mockRes as Response,
			nextFn as unknown as (err?: unknown) => void,
		);

		expect(mockRes.redirect).toHaveBeenCalledWith(
			302,
			expect.stringContaining("/login?next="),
		);
		expect(nextFn).not.toHaveBeenCalled();
	});

	it("encodes the original URL in the next parameter", () => {
		mockReq.originalUrl = "/account?tab=settings";
		mockReq.signedCookies![SESSION_COOKIE_NAME] = undefined;

		const middleware = createRequireWebSession(mockDb);
		middleware(
			mockReq as Request,
			mockRes as Response,
			nextFn as unknown as (err?: unknown) => void,
		);

		const redirectCall = (mockRes.redirect as ReturnType<typeof vi.fn>).mock
			.calls[0];
		const redirectUrl = redirectCall[1] as string;
		expect(redirectUrl).toContain("next=");
		expect(redirectUrl).toContain("%2F");
	});
});

describe("setSessionCookie", () => {
	let mockRes: Partial<Response>;
	const originalNodeEnv = process.env.NODE_ENV;

	beforeEach(() => {
		mockRes = {
			cookie: vi.fn().mockReturnThis(),
		};
	});

	afterEach(() => {
		process.env.NODE_ENV = originalNodeEnv;
	});

	it("sets cookie with correct options in production", () => {
		process.env.NODE_ENV = "production";

		const sessionId = "session-123";
		const expiresAt = Date.now() + 86400000;

		setSessionCookie(mockRes as Response, sessionId, expiresAt);

		expect(mockRes.cookie).toHaveBeenCalledWith(
			SESSION_COOKIE_NAME,
			sessionId,
			{
				httpOnly: true,
				sameSite: "lax",
				secure: true,
				signed: true,
				expires: new Date(expiresAt),
			},
		);
	});

	it("sets cookie without secure flag in non-production", () => {
		process.env.NODE_ENV = "development";

		const sessionId = "session-123";
		const expiresAt = Date.now() + 86400000;

		setSessionCookie(mockRes as Response, sessionId, expiresAt);

		expect(mockRes.cookie).toHaveBeenCalledWith(
			SESSION_COOKIE_NAME,
			sessionId,
			{
				httpOnly: true,
				sameSite: "lax",
				secure: false,
				signed: true,
				expires: new Date(expiresAt),
			},
		);
	});
});

describe("clearSessionCookie", () => {
	let mockRes: Partial<Response>;

	beforeEach(() => {
		mockRes = {
			clearCookie: vi.fn().mockReturnThis(),
		};
	});

	it("clears the session cookie", () => {
		clearSessionCookie(mockRes as Response);

		expect(mockRes.clearCookie).toHaveBeenCalledWith(SESSION_COOKIE_NAME);
	});
});
