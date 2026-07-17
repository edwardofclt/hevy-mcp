import { type Request, type Response, Router } from "express";
import { buildAppleAuthUrl, verifyAppleIdToken } from "../utils/apple.js";
import type { Db } from "../utils/db.js";
import {
	clearSessionCookie,
	createRequireWebSession,
	SESSION_COOKIE_NAME,
	setSessionCookie,
} from "../utils/session.js";

const DEFAULT_WEB_SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export interface AuthRoutesConfig {
	db: Db;
	masterKey: Buffer;
	apple: {
		teamId: string;
		clientId: string;
		keyId: string;
		privateKey: string;
		redirectUri: string;
	};
	webSessionTtlMs?: number;
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

// Only accept same-origin relative paths as a redirect target, to avoid an
// open redirect via a crafted `next` value in the Apple `state` round-trip.
function sanitizeNext(next: unknown): string {
	if (typeof next === "string" && next.startsWith("/")) return next;
	return "/account";
}

function encodeState(next: string): string {
	return Buffer.from(JSON.stringify({ next })).toString("base64url");
}

function decodeState(state: unknown): string {
	if (typeof state !== "string") return "/account";
	try {
		const parsed = JSON.parse(Buffer.from(state, "base64url").toString("utf8"));
		return sanitizeNext(
			typeof parsed === "object" && parsed !== null
				? (parsed as Record<string, unknown>).next
				: undefined,
		);
	} catch {
		return "/account";
	}
}

function renderLoginPage(authUrl: string): string {
	return `<!doctype html><html><head><meta charset="utf-8"><title>hevy-mcp sign in</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:5rem auto;padding:0 1rem;color:#222;text-align:center}
h1{font-size:1.25rem}
.apple-btn{display:inline-flex;align-items:center;justify-content:center;gap:.5rem;margin-top:1.5rem;padding:.75rem 1.5rem;font-size:1rem;border-radius:6px;background:#000;color:#fff;text-decoration:none}
.apple-btn:hover{background:#222}
.muted{color:#666;font-size:.9rem}
</style></head><body>
<h1>Sign in to hevy-mcp</h1>
<p class="muted">Manage your Hevy API key and authorize MCP clients.</p>
<a class="apple-btn" href="${htmlEscape(authUrl)}">Sign in with Apple</a>
</body></html>`;
}

function renderAccountPage(params: {
	configured: boolean;
	updatedAt?: number;
	error?: string;
}): string {
	const status = params.configured
		? `Hevy API key: configured (saved ${htmlEscape(new Date(params.updatedAt as number).toISOString())})`
		: "No Hevy API key configured yet.";
	const errorHtml = params.error
		? `<p class="err">${htmlEscape(params.error)}</p>`
		: "";
	return `<!doctype html><html><head><meta charset="utf-8"><title>hevy-mcp account</title>
<style>
body{font-family:system-ui,sans-serif;max-width:420px;margin:5rem auto;padding:0 1rem;color:#222}
h1{font-size:1.25rem}
input[type=text]{width:100%;padding:.5rem;font-size:1rem;box-sizing:border-box;margin-top:.5rem}
button{margin-top:1rem;padding:.6rem 1rem;font-size:1rem;border:0;border-radius:4px;background:#222;color:#fff;cursor:pointer}
.err{color:#a00}
.muted{color:#666;font-size:.9rem}
form{margin-top:1.5rem}
</style></head><body>
<h1>Your account</h1>
<p>${htmlEscape(status)}</p>
${errorHtml}
<form method="post" action="/account/hevy-key">
<label for="hevy_api_key">Hevy API key</label>
<input type="text" id="hevy_api_key" name="hevy_api_key" autocomplete="off">
<button type="submit">Save</button>
</form>
<form method="post" action="/account/logout">
<button type="submit">Sign out</button>
</form>
</body></html>`;
}

export function createAuthRoutes(config: AuthRoutesConfig): Router {
	const router = Router();
	const webSessionTtlMs = config.webSessionTtlMs ?? DEFAULT_WEB_SESSION_TTL_MS;
	const requireWebSession = createRequireWebSession(config.db);
	const appleEnv = {
		APPLE_CLIENT_ID: config.apple.clientId,
		APPLE_REDIRECT_URI: config.apple.redirectUri,
	};

	router.get("/login", (req: Request, res: Response) => {
		const next = sanitizeNext(req.query.next);
		const state = encodeState(next);
		const authUrl = buildAppleAuthUrl(state, appleEnv);
		res.status(200).type("html").send(renderLoginPage(authUrl));
	});

	// Apple calls this back via response_mode=form_post (a POST with an
	// application/x-www-form-urlencoded body), not a GET redirect, so the
	// id_token/state arrive in req.body rather than the query string.
	router.post("/auth/apple/callback", async (req: Request, res: Response) => {
		const body = (req.body ?? {}) as Record<string, unknown>;
		const next = decodeState(body.state);
		const idToken = body.id_token;

		if (typeof idToken !== "string") {
			console.warn("apple.callback missing id_token");
			res.status(401).type("text/plain").send("Sign-in failed.");
			return;
		}

		let claims: { sub: string; email?: string };
		try {
			claims = await verifyAppleIdToken(idToken, {
				APPLE_CLIENT_ID: config.apple.clientId,
			});
		} catch (err) {
			console.warn("apple.callback verify failed", err);
			res.status(401).type("text/plain").send("Sign-in failed.");
			return;
		}

		const user = config.db.upsertUser(claims.sub, claims.email);
		const session = config.db.createWebSession(user.id, webSessionTtlMs);
		setSessionCookie(res, session.id, session.expiresAt);
		res.redirect(302, next);
	});

	router.get("/account", requireWebSession, (_req: Request, res: Response) => {
		const status = config.db.getHevyKeyStatus(res.locals.userId as string);
		res
			.status(200)
			.type("html")
			.send(
				renderAccountPage({
					configured: status.configured,
					updatedAt: status.updatedAt,
				}),
			);
	});

	router.post(
		"/account/hevy-key",
		requireWebSession,
		(req: Request, res: Response) => {
			const body = (req.body ?? {}) as Record<string, unknown>;
			const raw = body.hevy_api_key;
			const trimmed = typeof raw === "string" ? raw.trim() : "";
			if (!trimmed) {
				const status = config.db.getHevyKeyStatus(res.locals.userId as string);
				res
					.status(400)
					.type("html")
					.send(
						renderAccountPage({
							configured: status.configured,
							updatedAt: status.updatedAt,
							error: "Please enter a Hevy API key.",
						}),
					);
				return;
			}
			config.db.saveHevyKey(
				res.locals.userId as string,
				trimmed,
				config.masterKey,
			);
			res.redirect(302, "/account");
		},
	);

	router.post("/account/logout", (req: Request, res: Response) => {
		const sessionId = req.signedCookies?.[SESSION_COOKIE_NAME];
		if (sessionId && sessionId !== false) {
			config.db.deleteWebSession(sessionId);
		}
		clearSessionCookie(res);
		res.redirect(302, "/login");
	});

	return router;
}
