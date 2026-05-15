import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";

const WWW_AUTHENTICATE = 'Basic realm="hevy-mcp", charset="UTF-8"';

function safeEqual(a: string, b: string): boolean {
	const aBuf = Buffer.from(a, "utf8");
	const bBuf = Buffer.from(b, "utf8");
	// timingSafeEqual requires equal-length buffers; pad to the max length and
	// always do the compare so timing does not reveal which side was longer.
	const len = Math.max(aBuf.length, bBuf.length, 1);
	const aPad = Buffer.alloc(len);
	const bPad = Buffer.alloc(len);
	aBuf.copy(aPad);
	bBuf.copy(bPad);
	const equalContent = timingSafeEqual(aPad, bPad);
	return equalContent && aBuf.length === bBuf.length;
}

function parseBasic(header: string | undefined): [string, string] | null {
	if (!header) return null;
	const [scheme, encoded] = header.split(" ", 2);
	if (!scheme || scheme.toLowerCase() !== "basic" || !encoded) return null;
	let decoded: string;
	try {
		decoded = Buffer.from(encoded, "base64").toString("utf8");
	} catch {
		return null;
	}
	const idx = decoded.indexOf(":");
	if (idx < 0) return null;
	return [decoded.slice(0, idx), decoded.slice(idx + 1)];
}

export function requireBasicAuth(
	clientId: string,
	clientSecret: string,
): RequestHandler {
	return (req: Request, res: Response, next: NextFunction): void => {
		const parsed = parseBasic(req.header("authorization"));
		// Always run both compares, even when parsing failed, to keep timing
		// behavior independent of which step rejected.
		const [presentedId, presentedSecret] = parsed ?? ["", ""];
		const idOk = safeEqual(presentedId, clientId);
		const secretOk = safeEqual(presentedSecret, clientSecret);
		if (parsed && idOk && secretOk) {
			next();
			return;
		}
		console.warn(
			`auth.fail ip=${req.ip ?? "?"} ua=${req.header("user-agent") ?? "?"}`,
		);
		res.setHeader("WWW-Authenticate", WWW_AUTHENTICATE);
		res.status(401).json({
			jsonrpc: "2.0",
			error: { code: -32001, message: "Unauthorized" },
			id: null,
		});
	};
}
