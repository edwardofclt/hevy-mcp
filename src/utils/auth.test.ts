import type { NextFunction, Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { requireBasicAuth } from "./auth.js";

function basic(id: string, secret: string): string {
	return `Basic ${Buffer.from(`${id}:${secret}`, "utf8").toString("base64")}`;
}

function call(
	authHeader: string | undefined,
	id = "client",
	secret = "supersecret",
): {
	status: number | undefined;
	body: unknown;
	wwwAuth: string | undefined;
	nextCalled: boolean;
} {
	let status: number | undefined;
	let body: unknown;
	let wwwAuth: string | undefined;
	const headers = new Map<string, string>();
	if (authHeader !== undefined) headers.set("authorization", authHeader);
	const req = {
		header: (name: string) => headers.get(name.toLowerCase()),
		ip: "127.0.0.1",
	} as unknown as Request;
	const res = {
		setHeader: (name: string, value: string) => {
			if (name.toLowerCase() === "www-authenticate") wwwAuth = value;
		},
		status: (code: number) => {
			status = code;
			return res;
		},
		json: (payload: unknown) => {
			body = payload;
			return res;
		},
	} as unknown as Response;
	const next = vi.fn() as unknown as NextFunction;
	requireBasicAuth(id, secret)(req, res, next);
	return {
		status,
		body,
		wwwAuth,
		nextCalled:
			(next as unknown as { mock: { calls: unknown[] } }).mock.calls.length > 0,
	};
}

describe("requireBasicAuth", () => {
	it("401s when Authorization header is missing", () => {
		const r = call(undefined);
		expect(r.status).toBe(401);
		expect(r.wwwAuth).toMatch(/^Basic realm=/);
		expect(r.nextCalled).toBe(false);
	});

	it("401s on non-Basic scheme", () => {
		const r = call("Bearer abc");
		expect(r.status).toBe(401);
		expect(r.nextCalled).toBe(false);
	});

	it("401s on malformed base64 with no colon", () => {
		const r = call(`Basic ${Buffer.from("nocolonhere").toString("base64")}`);
		expect(r.status).toBe(401);
		expect(r.nextCalled).toBe(false);
	});

	it("401s on wrong id", () => {
		const r = call(basic("wrong", "supersecret"));
		expect(r.status).toBe(401);
		expect(r.nextCalled).toBe(false);
	});

	it("401s on wrong secret", () => {
		const r = call(basic("client", "wrong"));
		expect(r.status).toBe(401);
		expect(r.nextCalled).toBe(false);
	});

	it("401s when secret is a prefix of the expected value", () => {
		const r = call(basic("client", "super"));
		expect(r.status).toBe(401);
		expect(r.nextCalled).toBe(false);
	});

	it("calls next on correct credentials", () => {
		const r = call(basic("client", "supersecret"));
		expect(r.status).toBeUndefined();
		expect(r.nextCalled).toBe(true);
	});

	it("returns JSON-RPC shaped error body on failure", () => {
		const r = call(undefined);
		expect(r.body).toEqual({
			jsonrpc: "2.0",
			error: { code: -32001, message: "Unauthorized" },
			id: null,
		});
	});
});
