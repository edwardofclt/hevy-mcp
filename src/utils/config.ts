export interface HevyConfig {
	apiKey?: string;
	http: boolean;
	port: number;
	clientId?: string;
	clientSecret?: string;
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

	const clientId = env.MCP_CLIENT_ID || undefined;
	const clientSecret = env.MCP_CLIENT_SECRET || undefined;

	return {
		apiKey,
		http,
		port,
		clientId,
		clientSecret,
	};
}

export function assertHttpCreds(
	cfg: HevyConfig,
): asserts cfg is HevyConfig & { clientId: string; clientSecret: string } {
	if (!cfg.clientId || !cfg.clientSecret) {
		console.error(
			"HTTP mode requires MCP_CLIENT_ID and MCP_CLIENT_SECRET environment variables.",
		);
		process.exit(1);
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
