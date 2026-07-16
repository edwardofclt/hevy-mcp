import { randomBytes, randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { decryptSecret, encryptSecret } from "./crypto.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  apple_sub TEXT UNIQUE NOT NULL,
  email TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS hevy_keys (
  user_id TEXT PRIMARY KEY REFERENCES users(id),
  ciphertext BLOB NOT NULL,
  iv BLOB NOT NULL,
  auth_tag BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS web_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_auth_codes (
  code TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  code_challenge_method TEXT NOT NULL,
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS mcp_tokens (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL
);
`;

export interface AuthCodeParams {
	userId: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	clientId: string;
	ttlMs: number;
	now?: number;
}

export interface AuthCodeRecord {
	userId: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	clientId: string;
}

export interface Db {
	upsertUser(appleSub: string, email: string | undefined): { id: string };
	getUserByAppleSub(
		appleSub: string,
	): { id: string; email?: string } | undefined;
	saveHevyKey(userId: string, plaintext: string, masterKey: Buffer): void;
	getHevyKeyStatus(userId: string): {
		configured: boolean;
		updatedAt?: number;
	};
	getDecryptedHevyKey(userId: string, masterKey: Buffer): string | null;
	createWebSession(
		userId: string,
		ttlMs: number,
		now?: number,
	): { id: string; expiresAt: number };
	getWebSession(
		sessionId: string,
		now?: number,
	): { userId: string } | undefined;
	deleteWebSession(sessionId: string): void;
	createAuthCode(params: AuthCodeParams): { code: string };
	consumeAuthCode(code: string, now?: number): AuthCodeRecord | undefined;
	createMcpToken(
		userId: string,
		ttlMs: number,
		now?: number,
	): { token: string; expiresAt: number };
	getMcpToken(token: string, now?: number): { userId: string } | undefined;
	gcExpired(now?: number): void;
	close(): void;
}

export function openDb(databasePath: string): Db {
	const database = new DatabaseSync(databasePath);
	database.exec(SCHEMA);

	function upsertUser(
		appleSub: string,
		email: string | undefined,
	): { id: string } {
		const existing = database
			.prepare("SELECT id FROM users WHERE apple_sub = ?")
			.get(appleSub) as { id: string } | undefined;
		if (existing) {
			database
				.prepare("UPDATE users SET email = ? WHERE id = ?")
				.run(email ?? null, existing.id);
			return { id: existing.id };
		}
		const id = randomUUID();
		database
			.prepare(
				"INSERT INTO users (id, apple_sub, email, created_at) VALUES (?, ?, ?, ?)",
			)
			.run(id, appleSub, email ?? null, Date.now());
		return { id };
	}

	function getUserByAppleSub(
		appleSub: string,
	): { id: string; email?: string } | undefined {
		const row = database
			.prepare("SELECT id, email FROM users WHERE apple_sub = ?")
			.get(appleSub) as { id: string; email: string | null } | undefined;
		if (!row) return undefined;
		return { id: row.id, email: row.email ?? undefined };
	}

	function saveHevyKey(
		userId: string,
		plaintext: string,
		masterKey: Buffer,
	): void {
		const { ciphertext, iv, authTag } = encryptSecret(plaintext, masterKey);
		const now = Date.now();
		const existing = database
			.prepare("SELECT created_at FROM hevy_keys WHERE user_id = ?")
			.get(userId) as { created_at: number } | undefined;
		const createdAt = existing ? existing.created_at : now;
		database
			.prepare(
				`INSERT INTO hevy_keys (user_id, ciphertext, iv, auth_tag, created_at, updated_at)
				 VALUES (?, ?, ?, ?, ?, ?)
				 ON CONFLICT(user_id) DO UPDATE SET
					ciphertext = excluded.ciphertext,
					iv = excluded.iv,
					auth_tag = excluded.auth_tag,
					updated_at = excluded.updated_at`,
			)
			.run(userId, ciphertext, iv, authTag, createdAt, now);
	}

	function getHevyKeyStatus(userId: string): {
		configured: boolean;
		updatedAt?: number;
	} {
		const row = database
			.prepare("SELECT updated_at FROM hevy_keys WHERE user_id = ?")
			.get(userId) as { updated_at: number } | undefined;
		if (!row) return { configured: false };
		return { configured: true, updatedAt: row.updated_at };
	}

	function getDecryptedHevyKey(
		userId: string,
		masterKey: Buffer,
	): string | null {
		const row = database
			.prepare(
				"SELECT ciphertext, iv, auth_tag FROM hevy_keys WHERE user_id = ?",
			)
			.get(userId) as
			| { ciphertext: Uint8Array; iv: Uint8Array; auth_tag: Uint8Array }
			| undefined;
		if (!row) return null;
		return decryptSecret(
			{
				ciphertext: Buffer.from(row.ciphertext),
				iv: Buffer.from(row.iv),
				authTag: Buffer.from(row.auth_tag),
			},
			masterKey,
		);
	}

	function createWebSession(
		userId: string,
		ttlMs: number,
		now: number = Date.now(),
	): { id: string; expiresAt: number } {
		const id = randomBytes(32).toString("base64url");
		const expiresAt = now + ttlMs;
		database
			.prepare(
				"INSERT INTO web_sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
			)
			.run(id, userId, expiresAt);
		return { id, expiresAt };
	}

	function getWebSession(
		sessionId: string,
		now: number = Date.now(),
	): { userId: string } | undefined {
		const row = database
			.prepare("SELECT user_id, expires_at FROM web_sessions WHERE id = ?")
			.get(sessionId) as { user_id: string; expires_at: number } | undefined;
		if (!row || row.expires_at <= now) return undefined;
		return { userId: row.user_id };
	}

	function deleteWebSession(sessionId: string): void {
		database.prepare("DELETE FROM web_sessions WHERE id = ?").run(sessionId);
	}

	function createAuthCode(params: AuthCodeParams): { code: string } {
		const code = randomBytes(32).toString("base64url");
		const now = params.now ?? Date.now();
		database
			.prepare(
				`INSERT INTO mcp_auth_codes
					(code, user_id, redirect_uri, code_challenge, code_challenge_method, client_id, expires_at)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			)
			.run(
				code,
				params.userId,
				params.redirectUri,
				params.codeChallenge,
				params.codeChallengeMethod,
				params.clientId,
				now + params.ttlMs,
			);
		return { code };
	}

	function consumeAuthCode(
		code: string,
		now: number = Date.now(),
	): AuthCodeRecord | undefined {
		const row = database
			.prepare(
				`SELECT user_id, redirect_uri, code_challenge, code_challenge_method, client_id, expires_at
				 FROM mcp_auth_codes WHERE code = ?`,
			)
			.get(code) as
			| {
					user_id: string;
					redirect_uri: string;
					code_challenge: string;
					code_challenge_method: string;
					client_id: string;
					expires_at: number;
			  }
			| undefined;
		database.prepare("DELETE FROM mcp_auth_codes WHERE code = ?").run(code);
		if (!row || row.expires_at <= now) return undefined;
		return {
			userId: row.user_id,
			redirectUri: row.redirect_uri,
			codeChallenge: row.code_challenge,
			codeChallengeMethod: row.code_challenge_method,
			clientId: row.client_id,
		};
	}

	function createMcpToken(
		userId: string,
		ttlMs: number,
		now: number = Date.now(),
	): { token: string; expiresAt: number } {
		const token = randomBytes(32).toString("base64url");
		const expiresAt = now + ttlMs;
		database
			.prepare(
				"INSERT INTO mcp_tokens (token, user_id, expires_at) VALUES (?, ?, ?)",
			)
			.run(token, userId, expiresAt);
		return { token, expiresAt };
	}

	function getMcpToken(
		token: string,
		now: number = Date.now(),
	): { userId: string } | undefined {
		const row = database
			.prepare("SELECT user_id, expires_at FROM mcp_tokens WHERE token = ?")
			.get(token) as { user_id: string; expires_at: number } | undefined;
		if (!row || row.expires_at <= now) return undefined;
		return { userId: row.user_id };
	}

	function gcExpired(now: number = Date.now()): void {
		database.prepare("DELETE FROM web_sessions WHERE expires_at <= ?").run(now);
		database
			.prepare("DELETE FROM mcp_auth_codes WHERE expires_at <= ?")
			.run(now);
		database.prepare("DELETE FROM mcp_tokens WHERE expires_at <= ?").run(now);
	}

	function close(): void {
		database.close();
	}

	return {
		upsertUser,
		getUserByAppleSub,
		saveHevyKey,
		getHevyKeyStatus,
		getDecryptedHevyKey,
		createWebSession,
		getWebSession,
		deleteWebSession,
		createAuthCode,
		consumeAuthCode,
		createMcpToken,
		getMcpToken,
		gcExpired,
		close,
	};
}
