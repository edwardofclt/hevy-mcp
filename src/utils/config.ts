export interface HevyConfig {
	apiKey?: string;
	http: boolean;
	port: number;
	databasePath?: string;
	encryptionKey?: string;
	appleTeamId?: string;
	appleClientId?: string;
	appleKeyId?: string;
	applePrivateKey?: string;
	appleRedirectUri?: string;
}

const DEFAULT_HTTP_PORT = 3000;

/**
 * Parse CLI arguments and environment to derive configuration.
 * Priority order for API key: CLI flag forms > environment variable.
 * Supported CLI arg forms:
 *   --hevy-api-key=KEY
 *   --hevyApiKey=KEY
 *   hevy-api-key=KEY (bare, e.g. when passed after npm start -- )
 */
export function parseConfig(
	argv: string[],
	env: NodeJS.ProcessEnv,
): HevyConfig {
	let apiKey = "";
	const apiKeyArgPatterns = [
		/^--hevy-api-key=(.+)$/i,
		/^--hevyApiKey=(.+)$/i,
		/^hevy-api-key=(.+)$/i,
	];
	for (const raw of argv) {
		for (const pattern of apiKeyArgPatterns) {
			const m = raw.match(pattern);
			if (m) {
				apiKey = m[1];
				break;
			}
		}
		if (apiKey) break;
	}
	if (!apiKey) {
		apiKey = env.HEVY_API_KEY || "";
	}

	let http = false;
	let port = 0;
	for (const raw of argv) {
		if (raw === "--http") {
			http = true;
			continue;
		}
		const portMatch = raw.match(/^--port=(\d+)$/i);
		if (portMatch) {
			port = Number.parseInt(portMatch[1], 10);
		}
	}
	if (env.MCP_HTTP === "1" || env.MCP_HTTP === "true") {
		http = true;
	}
	if (!port && env.PORT) {
		const envPort = Number.parseInt(env.PORT, 10);
		if (Number.isFinite(envPort)) port = envPort;
	}
	if (port && !http) http = true;
	if (http && !port) port = DEFAULT_HTTP_PORT;

	const databasePath = env.DATABASE_PATH || "./hevy-mcp.sqlite";
	const encryptionKey = env.ENCRYPTION_KEY || undefined;
	const appleTeamId = env.APPLE_TEAM_ID || undefined;
	const appleClientId = env.APPLE_CLIENT_ID || undefined;
	const appleKeyId = env.APPLE_KEY_ID || undefined;
	const applePrivateKey = env.APPLE_PRIVATE_KEY || undefined;
	const appleRedirectUri = env.APPLE_REDIRECT_URI || undefined;

	return {
		apiKey,
		http,
		port,
		databasePath,
		encryptionKey,
		appleTeamId,
		appleClientId,
		appleKeyId,
		applePrivateKey,
		appleRedirectUri,
	};
}

export function assertHttpEnv(cfg: HevyConfig): asserts cfg is HevyConfig & {
	encryptionKey: string;
	appleTeamId: string;
	appleClientId: string;
	appleKeyId: string;
	applePrivateKey: string;
	appleRedirectUri: string;
} {
	if (cfg.http) {
		const missing: string[] = [];
		if (!cfg.encryptionKey) missing.push("ENCRYPTION_KEY");
		if (!cfg.appleTeamId) missing.push("APPLE_TEAM_ID");
		if (!cfg.appleClientId) missing.push("APPLE_CLIENT_ID");
		if (!cfg.appleKeyId) missing.push("APPLE_KEY_ID");
		if (!cfg.applePrivateKey) missing.push("APPLE_PRIVATE_KEY");
		if (!cfg.appleRedirectUri) missing.push("APPLE_REDIRECT_URI");

		if (missing.length > 0) {
			console.error(
				`HTTP mode requires the following environment variables: ${missing.join(", ")}`,
			);
			process.exit(1);
		}
	}
}

export function assertApiKey(
	apiKey: string | undefined,
): asserts apiKey is string {
	if (!apiKey) {
		console.error(
			"Hevy API key is required. Provide it via the HEVY_API_KEY environment variable or the --hevy-api-key=YOUR_KEY command argument.",
		);
		process.exit(1);
	}
}
