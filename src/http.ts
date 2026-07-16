import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cookieParser from "cookie-parser";
import cors from "cors";
import express, { type Request, type Response } from "express";
import { buildServer } from "./index.js";
import { createAuthRoutes } from "./routes/auth.js";
import { loadMasterKey } from "./utils/crypto.js";
import { openDb } from "./utils/db.js";
import { createOAuthShim } from "./utils/oauth.js";
import {
	createRequireWebSession,
	deriveCookieSecret,
} from "./utils/session.js";

const SESSION_HEADER = "mcp-session-id";
const GC_INTERVAL_MS = 30 * 60 * 1000;

export interface HttpConfig {
	databasePath: string;
	encryptionKey: string;
	apple: {
		teamId: string;
		clientId: string;
		keyId: string;
		privateKey: string;
		redirectUri: string;
	};
}

export async function runHttpServer(
	port: number,
	cfg: HttpConfig,
): Promise<void> {
	const masterKey = loadMasterKey({
		ENCRYPTION_KEY: cfg.encryptionKey,
	} as NodeJS.ProcessEnv);
	const db = openDb(cfg.databasePath);

	const gcTimer = setInterval(() => db.gcExpired(), GC_INTERVAL_MS);
	gcTimer.unref();

	const app = express();
	app.use(
		cors({
			origin: true,
			exposedHeaders: [SESSION_HEADER],
			allowedHeaders: ["content-type", SESSION_HEADER, "mcp-protocol-version"],
		}),
	);
	app.use(express.json({ limit: "4mb" }));
	app.use(express.urlencoded({ extended: false, limit: "64kb" }));
	app.use(cookieParser(deriveCookieSecret(masterKey)));
	app.set("trust proxy", true);

	const transports = new Map<string, StreamableHTTPServerTransport>();

	app.get("/health", (_req, res) => {
		res.json({ status: "ok" });
	});

	app.use(
		createAuthRoutes({
			db,
			masterKey,
			apple: {
				teamId: cfg.apple.teamId,
				clientId: cfg.apple.clientId,
				keyId: cfg.apple.keyId,
				privateKey: cfg.apple.privateKey,
				redirectUri: cfg.apple.redirectUri,
			},
		}),
	);

	const oauth = createOAuthShim({ db });
	oauth.mount(app, createRequireWebSession(db));

	app.post("/mcp", oauth.requireBearer, async (req: Request, res: Response) => {
		const userId = res.locals.userId as string;
		const apiKey = db.getDecryptedHevyKey(userId, masterKey);
		if (!apiKey) {
			res.status(403).json({
				jsonrpc: "2.0",
				error: {
					code: -32003,
					message:
						"No Hevy API key configured. Visit /account to add one before connecting.",
				},
				id: null,
			});
			return;
		}

		const sessionId = req.header(SESSION_HEADER);
		let transport = sessionId ? transports.get(sessionId) : undefined;

		if (!transport) {
			if (sessionId || !isInitializeRequest(req.body)) {
				res.status(400).json({
					jsonrpc: "2.0",
					error: {
						code: -32000,
						message:
							"Bad Request: no valid session ID, and request is not an initialize request",
					},
					id: null,
				});
				return;
			}
			const newTransport = new StreamableHTTPServerTransport({
				sessionIdGenerator: () => randomUUID(),
				onsessioninitialized: (sid) => {
					transports.set(sid, newTransport);
				},
			});
			newTransport.onclose = () => {
				const sid = newTransport.sessionId;
				if (sid) transports.delete(sid);
			};
			const server = buildServer(apiKey);
			await server.connect(newTransport);
			transport = newTransport;
		}

		await transport.handleRequest(req, res, req.body);
	});

	const handleSessionRequest = async (req: Request, res: Response) => {
		const sessionId = req.header(SESSION_HEADER);
		const transport = sessionId ? transports.get(sessionId) : undefined;
		if (!transport) {
			res.status(400).send("Invalid or missing session ID");
			return;
		}
		await transport.handleRequest(req, res);
	};

	app.get("/mcp", oauth.requireBearer, handleSessionRequest);
	app.delete("/mcp", oauth.requireBearer, handleSessionRequest);

	await new Promise<void>((resolve) => {
		app.listen(port, () => {
			console.error(
				`Hevy MCP server listening on http://localhost:${port}/mcp`,
			);
			resolve();
		});
	});
}
