import { randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Db, openDb } from "./db.js";

describe("db", () => {
	let db: Db;

	beforeEach(() => {
		db = openDb(":memory:");
	});

	afterEach(() => {
		db.close();
	});

	describe("upsertUser", () => {
		it("is idempotent for the same apple_sub", () => {
			const first = db.upsertUser("apple-sub-1", "a@example.com");
			const second = db.upsertUser("apple-sub-1", "a@example.com");
			expect(second.id).toBe(first.id);

			const found = db.getUserByAppleSub("apple-sub-1");
			expect(found?.id).toBe(first.id);
		});

		it("does not duplicate the row", () => {
			db.upsertUser("apple-sub-2", "b@example.com");
			db.upsertUser("apple-sub-2", "b-updated@example.com");
			const found = db.getUserByAppleSub("apple-sub-2");
			expect(found?.email).toBe("b-updated@example.com");
		});

		it("returns undefined for an unknown apple_sub", () => {
			expect(db.getUserByAppleSub("nonexistent")).toBeUndefined();
		});
	});

	describe("hevy keys", () => {
		it("reports not configured before a key is saved", () => {
			const { id: userId } = db.upsertUser("apple-sub-3", undefined);
			const status = db.getHevyKeyStatus(userId);
			expect(status.configured).toBe(false);
		});

		it("reports configured after saving and never exposes key material", () => {
			const { id: userId } = db.upsertUser("apple-sub-4", undefined);
			const masterKey = randomBytes(32);
			db.saveHevyKey(userId, "hevy-api-key", masterKey);

			const status = db.getHevyKeyStatus(userId);
			expect(status.configured).toBe(true);
			expect(status.updatedAt).toBeTypeOf("number");
			expect(status).not.toHaveProperty("ciphertext");
			expect(status).not.toHaveProperty("iv");
			expect(status).not.toHaveProperty("authTag");
		});

		it("round-trips the exact plaintext through the real crypto module", () => {
			const { id: userId } = db.upsertUser("apple-sub-5", undefined);
			const masterKey = randomBytes(32);
			db.saveHevyKey(userId, "super-secret-value", masterKey);

			const decrypted = db.getDecryptedHevyKey(userId, masterKey);
			expect(decrypted).toBe("super-secret-value");
		});

		it("returns null from getDecryptedHevyKey when no key exists", () => {
			const { id: userId } = db.upsertUser("apple-sub-6", undefined);
			const masterKey = randomBytes(32);
			expect(db.getDecryptedHevyKey(userId, masterKey)).toBeNull();
		});

		it("overwrite updates updatedAt and returns the latest plaintext", async () => {
			const { id: userId } = db.upsertUser("apple-sub-7", undefined);
			const masterKey = randomBytes(32);

			db.saveHevyKey(userId, "first-value", masterKey);
			const firstStatus = db.getHevyKeyStatus(userId);

			await new Promise((resolve) => setTimeout(resolve, 5));

			db.saveHevyKey(userId, "second-value", masterKey);
			const secondStatus = db.getHevyKeyStatus(userId);

			expect(secondStatus.updatedAt).toBeGreaterThan(
				firstStatus.updatedAt as number,
			);
			expect(db.getDecryptedHevyKey(userId, masterKey)).toBe("second-value");
		});
	});

	describe("web sessions", () => {
		it("creates and retrieves a session", () => {
			const { id: userId } = db.upsertUser("apple-sub-8", undefined);
			const session = db.createWebSession(userId, 60_000, 1000);
			expect(session.expiresAt).toBe(61_000);

			const found = db.getWebSession(session.id, 2000);
			expect(found?.userId).toBe(userId);
		});

		it("returns undefined for an expired session", () => {
			const { id: userId } = db.upsertUser("apple-sub-9", undefined);
			const session = db.createWebSession(userId, 1000, 0);
			expect(db.getWebSession(session.id, 100_000)).toBeUndefined();
		});

		it("returns undefined for a missing session", () => {
			expect(db.getWebSession("nonexistent")).toBeUndefined();
		});

		it("deletes a session", () => {
			const { id: userId } = db.upsertUser("apple-sub-10", undefined);
			const session = db.createWebSession(userId, 60_000, 0);
			db.deleteWebSession(session.id);
			expect(db.getWebSession(session.id, 0)).toBeUndefined();
		});
	});

	describe("auth codes", () => {
		it("creates and consumes a code", () => {
			const { id: userId } = db.upsertUser("apple-sub-11", undefined);
			const { code } = db.createAuthCode({
				userId,
				redirectUri: "https://example.com/callback",
				codeChallenge: "challenge",
				codeChallengeMethod: "S256",
				clientId: "client-1",
				ttlMs: 60_000,
				now: 1000,
			});

			const consumed = db.consumeAuthCode(code, 2000);
			expect(consumed).toEqual({
				userId,
				redirectUri: "https://example.com/callback",
				codeChallenge: "challenge",
				codeChallengeMethod: "S256",
				clientId: "client-1",
			});
		});

		it("is single-use", () => {
			const { id: userId } = db.upsertUser("apple-sub-12", undefined);
			const { code } = db.createAuthCode({
				userId,
				redirectUri: "https://example.com/callback",
				codeChallenge: "challenge",
				codeChallengeMethod: "S256",
				clientId: "client-1",
				ttlMs: 60_000,
				now: 1000,
			});

			db.consumeAuthCode(code, 2000);
			expect(db.consumeAuthCode(code, 2000)).toBeUndefined();
		});

		it("returns undefined for an expired code", () => {
			const { id: userId } = db.upsertUser("apple-sub-13", undefined);
			const { code } = db.createAuthCode({
				userId,
				redirectUri: "https://example.com/callback",
				codeChallenge: "challenge",
				codeChallengeMethod: "S256",
				clientId: "client-1",
				ttlMs: 1000,
				now: 0,
			});

			expect(db.consumeAuthCode(code, 100_000)).toBeUndefined();
		});

		it("returns undefined for a missing code", () => {
			expect(db.consumeAuthCode("nonexistent")).toBeUndefined();
		});
	});

	describe("mcp tokens", () => {
		it("creates and retrieves a token", () => {
			const { id: userId } = db.upsertUser("apple-sub-14", undefined);
			const { token, expiresAt } = db.createMcpToken(userId, 60_000, 1000);
			expect(expiresAt).toBe(61_000);

			const found = db.getMcpToken(token, 2000);
			expect(found?.userId).toBe(userId);
		});

		it("returns undefined for an expired token", () => {
			const { id: userId } = db.upsertUser("apple-sub-15", undefined);
			const { token } = db.createMcpToken(userId, 1000, 0);
			expect(db.getMcpToken(token, 100_000)).toBeUndefined();
		});

		it("returns undefined for a missing token", () => {
			expect(db.getMcpToken("nonexistent")).toBeUndefined();
		});
	});

	describe("gcExpired", () => {
		it("removes expired sessions, codes, and tokens", () => {
			const { id: userId } = db.upsertUser("apple-sub-16", undefined);
			const session = db.createWebSession(userId, 1000, 0);
			const { code } = db.createAuthCode({
				userId,
				redirectUri: "https://example.com/callback",
				codeChallenge: "challenge",
				codeChallengeMethod: "S256",
				clientId: "client-1",
				ttlMs: 1000,
				now: 0,
			});
			const { token } = db.createMcpToken(userId, 1000, 0);

			db.gcExpired(100_000);

			expect(db.getWebSession(session.id, 100_000)).toBeUndefined();
			expect(db.consumeAuthCode(code, 100_000)).toBeUndefined();
			expect(db.getMcpToken(token, 100_000)).toBeUndefined();
		});

		it("keeps unexpired rows", () => {
			const { id: userId } = db.upsertUser("apple-sub-17", undefined);
			const session = db.createWebSession(userId, 60_000, 0);

			db.gcExpired(0);

			expect(db.getWebSession(session.id, 0)?.userId).toBe(userId);
		});
	});
});
