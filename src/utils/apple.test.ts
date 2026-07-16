import {
	exportJWK,
	exportPKCS8,
	generateKeyPair,
	type JWTVerifyGetKey,
	jwtVerify,
	SignJWT,
} from "jose";
import { describe, expect, it } from "vitest";
import {
	buildAppleAuthUrl,
	buildAppleClientSecret,
	verifyAppleIdToken,
} from "./apple.js";

const APPLE_ISSUER = "https://appleid.apple.com";

async function localJwks(publicKey: CryptoKey): Promise<JWTVerifyGetKey> {
	const jwk = await exportJWK(publicKey);
	return async () => {
		const { importJWK } = await import("jose");
		return importJWK({ ...jwk, alg: "ES256" }, "ES256") as Promise<CryptoKey>;
	};
}

describe("buildAppleAuthUrl", () => {
	it("includes all expected query params", () => {
		const url = new URL(
			buildAppleAuthUrl("my-state", {
				APPLE_CLIENT_ID: "com.example.app",
				APPLE_REDIRECT_URI: "https://example.com/auth/apple/callback",
			}),
		);
		expect(url.origin + url.pathname).toBe(
			"https://appleid.apple.com/auth/authorize",
		);
		expect(url.searchParams.get("client_id")).toBe("com.example.app");
		expect(url.searchParams.get("redirect_uri")).toBe(
			"https://example.com/auth/apple/callback",
		);
		expect(url.searchParams.get("response_type")).toBe("code id_token");
		expect(url.searchParams.get("scope")).toBe("name email");
		expect(url.searchParams.get("response_mode")).toBe("form_post");
		expect(url.searchParams.get("state")).toBe("my-state");
	});
});

describe("buildAppleClientSecret", () => {
	it("produces a correctly claimed and signed ES256 JWT", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const privatePem = await exportPKCS8(privateKey);

		const beforeIat = Math.floor(Date.now() / 1000);
		const jwt = await buildAppleClientSecret({
			APPLE_TEAM_ID: "TEAM123",
			APPLE_CLIENT_ID: "com.example.app",
			APPLE_KEY_ID: "KEY456",
			APPLE_PRIVATE_KEY: privatePem,
		});

		const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
			issuer: "TEAM123",
			audience: APPLE_ISSUER,
			subject: "com.example.app",
		});

		expect(protectedHeader.alg).toBe("ES256");
		expect(protectedHeader.kid).toBe("KEY456");
		expect(payload.iss).toBe("TEAM123");
		expect(payload.aud).toBe(APPLE_ISSUER);
		expect(payload.sub).toBe("com.example.app");
		expect(payload.iat).toBeGreaterThanOrEqual(beforeIat);
		expect(payload.exp).toBeDefined();
		expect((payload.exp as number) - (payload.iat as number)).toBe(300);
	});
});

describe("verifyAppleIdToken", () => {
	async function signIdToken(
		privateKey: CryptoKey,
		claims: Record<string, unknown>,
		kid = "KEY1",
	): Promise<string> {
		return new SignJWT(claims)
			.setProtectedHeader({ alg: "ES256", kid })
			.sign(privateKey);
	}

	it("accepts a valid token and returns sub/email", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const jwks = await localJwks(publicKey);
		const iat = Math.floor(Date.now() / 1000);
		const token = await signIdToken(privateKey, {
			iss: APPLE_ISSUER,
			aud: "com.example.app",
			sub: "apple-sub-123",
			email: "user@example.com",
			iat,
			exp: iat + 3600,
		});

		const result = await verifyAppleIdToken(
			token,
			{ APPLE_CLIENT_ID: "com.example.app" },
			jwks,
		);
		expect(result.sub).toBe("apple-sub-123");
		expect(result.email).toBe("user@example.com");
	});

	it("rejects an expired token", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const jwks = await localJwks(publicKey);
		const iat = Math.floor(Date.now() / 1000) - 7200;
		const token = await signIdToken(privateKey, {
			iss: APPLE_ISSUER,
			aud: "com.example.app",
			sub: "apple-sub-123",
			iat,
			exp: iat + 3600,
		});

		await expect(
			verifyAppleIdToken(token, { APPLE_CLIENT_ID: "com.example.app" }, jwks),
		).rejects.toThrow();
	});

	it("rejects a token with the wrong issuer", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const jwks = await localJwks(publicKey);
		const iat = Math.floor(Date.now() / 1000);
		const token = await signIdToken(privateKey, {
			iss: "https://not-apple.example.com",
			aud: "com.example.app",
			sub: "apple-sub-123",
			iat,
			exp: iat + 3600,
		});

		await expect(
			verifyAppleIdToken(token, { APPLE_CLIENT_ID: "com.example.app" }, jwks),
		).rejects.toThrow();
	});

	it("rejects a token with the wrong audience", async () => {
		const { privateKey, publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const jwks = await localJwks(publicKey);
		const iat = Math.floor(Date.now() / 1000);
		const token = await signIdToken(privateKey, {
			iss: APPLE_ISSUER,
			aud: "com.other.app",
			sub: "apple-sub-123",
			iat,
			exp: iat + 3600,
		});

		await expect(
			verifyAppleIdToken(token, { APPLE_CLIENT_ID: "com.example.app" }, jwks),
		).rejects.toThrow();
	});

	it("rejects a token signed with a different key", async () => {
		const { publicKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const { privateKey: otherPrivateKey } = await generateKeyPair("ES256", {
			extractable: true,
		});
		const jwks = await localJwks(publicKey);
		const iat = Math.floor(Date.now() / 1000);
		const token = await signIdToken(otherPrivateKey, {
			iss: APPLE_ISSUER,
			aud: "com.example.app",
			sub: "apple-sub-123",
			iat,
			exp: iat + 3600,
		});

		await expect(
			verifyAppleIdToken(token, { APPLE_CLIENT_ID: "com.example.app" }, jwks),
		).rejects.toThrow();
	});
});
