import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { Request, RequestHandler, Response, Router } from "express";

const CODE_TTL_MS = 5 * 60 * 1000;
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

type AuthCode = {
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	clientId: string;
	expiresAt: number;
};

type IssuedToken = {
	expiresAt: number;
};

function safeEqual(a: string, b: string): boolean {
	const aBuf = Buffer.from(a, "utf8");
	const bBuf = Buffer.from(b, "utf8");
	const len = Math.max(aBuf.length, bBuf.length, 1);
	const aPad = Buffer.alloc(len);
	const bPad = Buffer.alloc(len);
	aBuf.copy(aPad);
	bBuf.copy(bPad);
	const equalContent = timingSafeEqual(aPad, bPad);
	return equalContent && aBuf.length === bBuf.length;
}

function getIssuer(req: Request): string {
	const forwardedProto = req.header("x-forwarded-proto");
	const forwardedHost = req.header("x-forwarded-host");
	const proto = forwardedProto || req.protocol;
	const host = forwardedHost || req.header("host") || "localhost";
	return `${proto}://${host}`;
}

function htmlEscape(s: string): string {
	return s.replace(
		/[&<>"']/g,
		(c) =>
			(
				({
					"&": "&amp;",
					"<": "&lt;",
					">": "&gt;",
					'"': "&quot;",
					"'": "&#39;",
				}) as Record<string, string>
			)[c],
	);
}

function renderForm(params: {
	action: string;
	state: string;
	redirectUri: string;
	codeChallenge: string;
	codeChallengeMethod: string;
	clientId: string;
	error?: string;
}): string {
	const errorHtml = params.error
		? `<p class="err">${htmlEscape(params.error)}</p>`
		: "";
	return `<!doctype html><html><head><meta charset="utf-8"><title>hevy-mcp authorize</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:5rem auto;padding:0 1rem;color:#222}
h1{font-size:1.25rem}
input[type=password]{width:100%;padding:.6rem;font-size:1rem;border:1px solid #bbb;border-radius:4px}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;border:0;border-radius:4px;background:#222;color:#fff;cursor:pointer}
.err{color:#a00}
.muted{color:#666;font-size:.9rem}
</style></head><body>
<h1>Authorize hevy-mcp</h1>
<p class="muted">Paste the server's shared secret to grant this client access.</p>
${errorHtml}
<form method="post" action="${htmlEscape(params.action)}">
<input type="password" name="secret" autocomplete="off" autofocus required placeholder="MCP_CLIENT_SECRET">
<input type="hidden" name="state" value="${htmlEscape(params.state)}">
<input type="hidden" name="redirect_uri" value="${htmlEscape(params.redirectUri)}">
<input type="hidden" name="code_challenge" value="${htmlEscape(params.codeChallenge)}">
<input type="hidden" name="code_challenge_method" value="${htmlEscape(params.codeChallengeMethod)}">
<input type="hidden" name="client_id" value="${htmlEscape(params.clientId)}">
<button type="submit">Authorize</button>
</form>
</body></html>`;
}

function verifyPkce(
	verifier: string,
	challenge: string,
	method: string,
): boolean {
	if (method === "plain") return safeEqual(verifier, challenge);
	if (method !== "S256") return false;
	const hashed = createHash("sha256")
		.update(verifier)
		.digest("base64")
		.replace(/\+/g, "-")
		.replace(/\//g, "_")
		.replace(/=+$/, "");
	return safeEqual(hashed, challenge);
}

export interface OAuthShim {
	mount(router: Router): void;
	requireBearer: RequestHandler;
}

export function createOAuthShim(opts: {
	clientSecret: string;
	now?: () => number;
}): OAuthShim {
	const now = opts.now ?? (() => Date.now());
	const codes = new Map<string, AuthCode>();
	const tokens = new Map<string, IssuedToken>();
	const attempts = new Map<string, number[]>();

	function rateLimit(ip: string): boolean {
		const t = now();
		const cutoff = t - RATE_LIMIT_WINDOW_MS;
		const recent = (attempts.get(ip) ?? []).filter((ts) => ts > cutoff);
		if (recent.length >= RATE_LIMIT_MAX) {
			attempts.set(ip, recent);
			return false;
		}
		recent.push(t);
		attempts.set(ip, recent);
		return true;
	}

	function gc(): void {
		const t = now();
		for (const [k, v] of codes) if (v.expiresAt <= t) codes.delete(k);
		for (const [k, v] of tokens) if (v.expiresAt <= t) tokens.delete(k);
	}

	const requireBearer: RequestHandler = (req, res, next) => {
		const header = req.header("authorization");
		if (!header || !header.toLowerCase().startsWith("bearer ")) {
			res.setHeader(
				"WWW-Authenticate",
				`Bearer realm="hevy-mcp", resource_metadata="${getIssuer(req)}/.well-known/oauth-protected-resource"`,
			);
			res.status(401).json({
				jsonrpc: "2.0",
				error: { code: -32001, message: "Unauthorized" },
				id: null,
			});
			return;
		}
		const token = header.slice(7).trim();
		gc();
		const record = tokens.get(token);
		if (!record || record.expiresAt <= now()) {
			res.setHeader(
				"WWW-Authenticate",
				`Bearer realm="hevy-mcp", error="invalid_token", resource_metadata="${getIssuer(req)}/.well-known/oauth-protected-resource"`,
			);
			res.status(401).json({
				jsonrpc: "2.0",
				error: { code: -32001, message: "Unauthorized" },
				id: null,
			});
			return;
		}
		next();
	};

	function mount(router: Router): void {
		router.get(
			"/.well-known/oauth-protected-resource",
			(req: Request, res: Response) => {
				const issuer = getIssuer(req);
				res.json({
					resource: issuer,
					authorization_servers: [issuer],
					bearer_methods_supported: ["header"],
				});
			},
		);

		router.get(
			"/.well-known/oauth-authorization-server",
			(req: Request, res: Response) => {
				const issuer = getIssuer(req);
				res.json({
					issuer,
					authorization_endpoint: `${issuer}/authorize`,
					token_endpoint: `${issuer}/token`,
					registration_endpoint: `${issuer}/register`,
					response_types_supported: ["code"],
					grant_types_supported: ["authorization_code"],
					code_challenge_methods_supported: ["S256", "plain"],
					token_endpoint_auth_methods_supported: ["none"],
				});
			},
		);

		router.post("/register", (req: Request, res: Response) => {
			const body = (req.body ?? {}) as Record<string, unknown>;
			const redirectUris = Array.isArray(body.redirect_uris)
				? (body.redirect_uris as unknown[]).filter(
						(u): u is string => typeof u === "string",
					)
				: [];
			const clientId = `mcp-${randomBytes(8).toString("hex")}`;
			res.status(201).json({
				client_id: clientId,
				client_id_issued_at: Math.floor(now() / 1000),
				redirect_uris: redirectUris,
				grant_types: ["authorization_code"],
				response_types: ["code"],
				token_endpoint_auth_method: "none",
			});
		});

		router.get("/authorize", (req: Request, res: Response) => {
			const q = req.query as Record<string, string | undefined>;
			const redirectUri = q.redirect_uri;
			const state = q.state ?? "";
			const codeChallenge = q.code_challenge ?? "";
			const codeChallengeMethod = q.code_challenge_method ?? "S256";
			const clientId = q.client_id ?? "";
			const responseType = q.response_type ?? "code";
			if (!redirectUri || !codeChallenge || responseType !== "code") {
				res
					.status(400)
					.type("text/plain")
					.send(
						"invalid_request: redirect_uri, code_challenge, response_type=code required",
					);
				return;
			}
			res
				.status(200)
				.type("html")
				.send(
					renderForm({
						action: "/authorize",
						state,
						redirectUri,
						codeChallenge,
						codeChallengeMethod,
						clientId,
					}),
				);
		});

		router.post("/authorize", (req: Request, res: Response) => {
			const body = (req.body ?? {}) as Record<string, string | undefined>;
			const redirectUri = body.redirect_uri ?? "";
			const state = body.state ?? "";
			const codeChallenge = body.code_challenge ?? "";
			const codeChallengeMethod = body.code_challenge_method ?? "S256";
			const clientId = body.client_id ?? "";
			const secret = body.secret ?? "";

			if (!redirectUri || !codeChallenge) {
				res.status(400).type("text/plain").send("invalid_request");
				return;
			}

			const ip = req.ip ?? "?";
			if (!rateLimit(ip)) {
				console.warn(`oauth.ratelimit ip=${ip}`);
				res
					.status(429)
					.type("html")
					.send(
						renderForm({
							action: "/authorize",
							state,
							redirectUri,
							codeChallenge,
							codeChallengeMethod,
							clientId,
							error: "Too many attempts. Wait 15 minutes before trying again.",
						}),
					);
				return;
			}

			if (!safeEqual(secret, opts.clientSecret)) {
				console.warn(`oauth.authorize.fail ip=${ip}`);
				res
					.status(401)
					.type("html")
					.send(
						renderForm({
							action: "/authorize",
							state,
							redirectUri,
							codeChallenge,
							codeChallengeMethod,
							clientId,
							error: "Incorrect secret.",
						}),
					);
				return;
			}

			gc();
			const code = randomBytes(32).toString("base64url");
			codes.set(code, {
				redirectUri,
				codeChallenge,
				codeChallengeMethod,
				clientId,
				expiresAt: now() + CODE_TTL_MS,
			});

			const url = new URL(redirectUri);
			url.searchParams.set("code", code);
			if (state) url.searchParams.set("state", state);
			res.redirect(302, url.toString());
		});

		router.post("/token", (req: Request, res: Response) => {
			const body = (req.body ?? {}) as Record<string, string | undefined>;
			const grantType = body.grant_type;
			const code = body.code ?? "";
			const redirectUri = body.redirect_uri ?? "";
			const codeVerifier = body.code_verifier ?? "";

			if (grantType !== "authorization_code") {
				res.status(400).json({ error: "unsupported_grant_type" });
				return;
			}
			gc();
			const record = codes.get(code);
			if (!record || record.expiresAt <= now()) {
				res.status(400).json({ error: "invalid_grant" });
				return;
			}
			codes.delete(code);
			if (record.redirectUri !== redirectUri) {
				res.status(400).json({ error: "invalid_grant" });
				return;
			}
			if (
				!verifyPkce(
					codeVerifier,
					record.codeChallenge,
					record.codeChallengeMethod,
				)
			) {
				res.status(400).json({ error: "invalid_grant" });
				return;
			}

			const token = randomBytes(32).toString("base64url");
			tokens.set(token, { expiresAt: now() + TOKEN_TTL_MS });
			res.json({
				access_token: token,
				token_type: "Bearer",
				expires_in: Math.floor(TOKEN_TTL_MS / 1000),
			});
		});
	}

	return { mount, requireBearer };
}
