import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const IV_LENGTH = 12;
const KEY_LENGTH = 32;

export interface EncryptedSecret {
	ciphertext: Buffer;
	iv: Buffer;
	authTag: Buffer;
}

export function encryptSecret(
	plaintext: string,
	masterKey: Buffer,
): EncryptedSecret {
	const iv = randomBytes(IV_LENGTH);
	const cipher = createCipheriv("aes-256-gcm", masterKey, iv);
	const ciphertext = Buffer.concat([
		cipher.update(plaintext, "utf8"),
		cipher.final(),
	]);
	return { ciphertext, iv, authTag: cipher.getAuthTag() };
}

export function decryptSecret(
	fields: EncryptedSecret,
	masterKey: Buffer,
): string {
	const decipher = createDecipheriv("aes-256-gcm", masterKey, fields.iv);
	decipher.setAuthTag(fields.authTag);
	return Buffer.concat([
		decipher.update(fields.ciphertext),
		decipher.final(),
	]).toString("utf8");
}

export function loadMasterKey(env: NodeJS.ProcessEnv): Buffer {
	const encoded = env.ENCRYPTION_KEY;
	if (!encoded) {
		console.error(
			"ENCRYPTION_KEY environment variable is required. Generate one with: openssl rand -base64 32",
		);
		process.exit(1);
	}
	const key = Buffer.from(encoded as string, "base64");
	if (key.length !== KEY_LENGTH) {
		console.error(
			`ENCRYPTION_KEY must decode to exactly ${KEY_LENGTH} bytes for AES-256 (got ${key.length}). Generate one with: openssl rand -base64 32`,
		);
		process.exit(1);
	}
	return key;
}
