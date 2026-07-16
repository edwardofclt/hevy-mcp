import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { decryptSecret, encryptSecret, loadMasterKey } from "./crypto.js";

function env(vars: Record<string, string | undefined>): NodeJS.ProcessEnv {
	return { ...process.env, ...vars } as NodeJS.ProcessEnv;
}

describe("encryptSecret / decryptSecret", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("round-trips the original plaintext", () => {
		const masterKey = randomBytes(32);
		const plaintext = "hevy-api-key-value";
		const encrypted = encryptSecret(plaintext, masterKey);
		expect(decryptSecret(encrypted, masterKey)).toBe(plaintext);
	});

	it("uses a random iv per call", () => {
		const masterKey = randomBytes(32);
		const a = encryptSecret("same-plaintext", masterKey);
		const b = encryptSecret("same-plaintext", masterKey);
		expect(a.iv.equals(b.iv)).toBe(false);
	});

	it("throws when decrypting with the wrong key", () => {
		const masterKey = randomBytes(32);
		const wrongKey = randomBytes(32);
		const encrypted = encryptSecret("secret", masterKey);
		expect(() => decryptSecret(encrypted, wrongKey)).toThrow();
	});

	it("throws when the authTag is tampered with", () => {
		const masterKey = randomBytes(32);
		const encrypted = encryptSecret("secret", masterKey);
		const tampered = Buffer.from(encrypted.authTag);
		tampered[0] ^= 0xff;
		expect(() =>
			decryptSecret({ ...encrypted, authTag: tampered }, masterKey),
		).toThrow();
	});

	it("throws when the ciphertext is tampered with", () => {
		const masterKey = randomBytes(32);
		const encrypted = encryptSecret("secret", masterKey);
		const tampered = Buffer.from(encrypted.ciphertext);
		tampered[0] ^= 0xff;
		expect(() =>
			decryptSecret({ ...encrypted, ciphertext: tampered }, masterKey),
		).toThrow();
	});
});

describe("loadMasterKey", () => {
	afterEach(() => {
		vi.restoreAllMocks();
	});

	it("returns a 32-byte buffer for a valid base64 key", () => {
		const key = randomBytes(32).toString("base64");
		const result = loadMasterKey(env({ ENCRYPTION_KEY: key }));
		expect(result.length).toBe(32);
	});

	function mockExit() {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation((code?: string | number | null) => {
				expect(code).toBe(1);
				throw new Error("process.exit called");
			});
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
		return { exitSpy, errorSpy };
	}

	it("exits the process when ENCRYPTION_KEY is missing", () => {
		const { exitSpy } = mockExit();
		expect(() => loadMasterKey(env({ ENCRYPTION_KEY: undefined }))).toThrow(
			"process.exit called",
		);
		expect(exitSpy).toHaveBeenCalledWith(1);
	});

	it("exits the process when ENCRYPTION_KEY is malformed", () => {
		const { exitSpy } = mockExit();
		expect(() =>
			loadMasterKey(env({ ENCRYPTION_KEY: "not-valid-base64-!!!" })),
		).toThrow("process.exit called");
		expect(exitSpy).toHaveBeenCalledWith(1);
	});

	it("exits the process when ENCRYPTION_KEY decodes to the wrong length", () => {
		const { exitSpy } = mockExit();
		const shortKey = randomBytes(16).toString("base64");
		expect(() => loadMasterKey(env({ ENCRYPTION_KEY: shortKey }))).toThrow(
			"process.exit called",
		);
		expect(exitSpy).toHaveBeenCalledWith(1);
	});
});
