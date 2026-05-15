import { randomUUID } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import cors from "cors";
import express, { type Request, type Response } from "express";
import { buildServer } from "./index.js";
import { requireBasicAuth } from "./utils/auth.js";

const SESSION_HEADER = "mcp-session-id";

export interface HttpAuth {
	clientId: string;
	clientSecret: string;
}

export async function runHttpServer(
	apiKey: string,
	port: number,
	auth: HttpAuth,
): Promise<void> {
	const app = express();
	app.use(
		cors({
			origin: true,
			exposedHeaders: [SESSION_HEADER],
			allowedHeaders: ["content-type", SESSION_HEADER, "mcp-protocol-version"],
		}),
	);
	app.use(express.json({ limit: "4mb" }));

	const transports = new Map<string, StreamableHTTPServerTransport>();

	app.get("/health", (_req, res) => {
		res.json({ status: "ok" });
	});

	const basicAuth = requireBasicAuth(auth.clientId, auth.clientSecret);

	app.post("/mcp", basicAuth, async (req: Request, res: Response) => {
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

	app.get("/mcp", basicAuth, handleSessionRequest);
	app.delete("/mcp", basicAuth, handleSessionRequest);

	await new Promise<void>((resolve) => {
		app.listen(port, () => {
			console.error(
				`Hevy MCP server listening on http://localhost:${port}/mcp`,
			);
			resolve();
		});
	});
}
