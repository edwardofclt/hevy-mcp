import { createHmac } from "node:crypto";
import type {} from "cookie-parser";
import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { Db } from "./db.js";

export const SESSION_COOKIE_NAME = "hevy_mcp_session";

export function deriveCookieSecret(masterKey: Buffer): string {
	return createHmac("sha256", masterKey)
		.update("hevy-mcp-cookie-secret")
		.digest("hex");
}

export function createRequireWebSession(db: Db): RequestHandler {
	return (req: Request, res: Response, next: NextFunction): void => {
		const sessionId = req.signedCookies[SESSION_COOKIE_NAME];

		if (!sessionId || sessionId === false) {
			const next_param = encodeURIComponent(req.originalUrl);
			res.redirect(302, `/login?next=${next_param}`);
			return;
		}

		const session = db.getWebSession(sessionId);
		if (!session) {
			const next_param = encodeURIComponent(req.originalUrl);
			res.redirect(302, `/login?next=${next_param}`);
			return;
		}

		res.locals.userId = session.userId;
		next();
	};
}

export function setSessionCookie(
	res: Response,
	sessionId: string,
	expiresAt: number,
): void {
	res.cookie(SESSION_COOKIE_NAME, sessionId, {
		httpOnly: true,
		sameSite: "lax",
		secure: process.env.NODE_ENV === "production",
		signed: true,
		expires: new Date(expiresAt),
	});
}

export function clearSessionCookie(res: Response): void {
	res.clearCookie(SESSION_COOKIE_NAME);
}
