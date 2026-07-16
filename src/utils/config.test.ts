import { describe, expect, it, vi } from "vitest";
import { assertHttpEnv, parseConfig } from "./config.js";

function env(vars: Record<string, string | undefined>): NodeJS.ProcessEnv {
	return { ...process.env, ...vars } as NodeJS.ProcessEnv;
}

describe("parseConfig", () => {
	it("prefers --hevy-api-key= over env", () => {
		const cfg = parseConfig(
			["--hevy-api-key=cliKey"],
			env({ HEVY_API_KEY: "envKey" }),
		);
		expect(cfg.apiKey).toBe("cliKey");
	});

	it("supports --hevyApiKey= camelCase form", () => {
		const cfg = parseConfig(
			["--hevyApiKey=camelKey"],
			env({ HEVY_API_KEY: "envKey" }),
		);
		expect(cfg.apiKey).toBe("camelKey");
	});

	it("supports bare hevy-api-key= form", () => {
		const cfg = parseConfig(["hevy-api-key=bareKey"], env({}));
		expect(cfg.apiKey).toBe("bareKey");
	});

	it("falls back to env HEVY_API_KEY", () => {
		const cfg = parseConfig([], env({ HEVY_API_KEY: "envOnly" }));
		expect(cfg.apiKey).toBe("envOnly");
	});

	it("reads database path and Apple env vars into config", () => {
		const cfg = parseConfig(
			[],
			env({
				DATABASE_PATH: "/data/hevy-mcp.sqlite",
				ENCRYPTION_KEY: "enc-key",
				APPLE_TEAM_ID: "team-id",
				APPLE_CLIENT_ID: "apple-client-id",
				APPLE_KEY_ID: "key-id",
				APPLE_PRIVATE_KEY: "private-key",
				APPLE_REDIRECT_URI: "https://example.com/callback",
			}),
		);
		expect(cfg.databasePath).toBe("/data/hevy-mcp.sqlite");
		expect(cfg.encryptionKey).toBe("enc-key");
		expect(cfg.appleTeamId).toBe("team-id");
		expect(cfg.appleClientId).toBe("apple-client-id");
		expect(cfg.appleKeyId).toBe("key-id");
		expect(cfg.applePrivateKey).toBe("private-key");
		expect(cfg.appleRedirectUri).toBe("https://example.com/callback");
	});

	it("defaults databasePath to ./hevy-mcp.sqlite when unset", () => {
		const cfg = parseConfig([], env({ DATABASE_PATH: undefined }));
		expect(cfg.databasePath).toBe("./hevy-mcp.sqlite");
	});
});

describe("assertHttpEnv", () => {
	const validEnv = {
		DATABASE_PATH: "./hevy-mcp.sqlite",
		ENCRYPTION_KEY: "enc-key",
		APPLE_TEAM_ID: "team-id",
		APPLE_CLIENT_ID: "apple-client-id",
		APPLE_KEY_ID: "key-id",
		APPLE_PRIVATE_KEY: "private-key",
		APPLE_REDIRECT_URI: "https://example.com/callback",
		MCP_HTTP: "1",
	};

	it("does not exit when all required env vars are present", () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation(() => undefined as never);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const cfg = parseConfig([], env(validEnv));
		assertHttpEnv(cfg);

		expect(exitSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();

		exitSpy.mockRestore();
		errorSpy.mockRestore();
	});

	it("does not exit when http mode is disabled, even if vars are missing", () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation(() => undefined as never);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const cfg = parseConfig([], env({ MCP_HTTP: undefined }));
		assertHttpEnv(cfg);

		expect(exitSpy).not.toHaveBeenCalled();
		expect(errorSpy).not.toHaveBeenCalled();

		exitSpy.mockRestore();
		errorSpy.mockRestore();
	});

	it("exits with 1 and names each missing env var", () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation(() => undefined as never);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const cfg = parseConfig(
			[],
			env({
				...validEnv,
				ENCRYPTION_KEY: undefined,
				APPLE_TEAM_ID: undefined,
			}),
		);
		assertHttpEnv(cfg);

		expect(exitSpy).toHaveBeenCalledWith(1);
		expect(errorSpy).toHaveBeenCalledTimes(1);
		const message = errorSpy.mock.calls[0][0] as string;
		expect(message).toContain("ENCRYPTION_KEY");
		expect(message).toContain("APPLE_TEAM_ID");
		expect(message).not.toContain("APPLE_CLIENT_ID");

		exitSpy.mockRestore();
		errorSpy.mockRestore();
	});

	it("exits with 1 when a single env var is missing", () => {
		const exitSpy = vi
			.spyOn(process, "exit")
			.mockImplementation(() => undefined as never);
		const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});

		const cfg = parseConfig(
			[],
			env({ ...validEnv, APPLE_REDIRECT_URI: undefined }),
		);
		assertHttpEnv(cfg);

		expect(exitSpy).toHaveBeenCalledWith(1);
		const message = errorSpy.mock.calls[0][0] as string;
		expect(message).toContain("APPLE_REDIRECT_URI");

		exitSpy.mockRestore();
		errorSpy.mockRestore();
	});
});
