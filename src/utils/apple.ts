import {
	createRemoteJWKSet,
	importPKCS8,
	type JWTVerifyGetKey,
	jwtVerify,
	SignJWT,
} from "jose";

const APPLE_ISSUER = "https://appleid.apple.com";
const APPLE_AUTHORIZE_URL = `${APPLE_ISSUER}/auth/authorize`;
const APPLE_JWKS_URL = `${APPLE_ISSUER}/auth/keys`;

// Apple's token endpoint rejects a client-assertion JWT with an exp more
// than 6 months out, but there's no reason to mint one that long-lived;
// 5 minutes keeps the exposure window tight for a value regenerated per use.
const CLIENT_SECRET_TTL_SECONDS = 300;

let jwks: JWTVerifyGetKey | undefined;

function getJwks(): JWTVerifyGetKey {
	// createRemoteJWKSet caches the fetched key set in-memory and refetches
	// per the JWKS response's own cache headers / on verification key-miss.
	if (!jwks) jwks = createRemoteJWKSet(new URL(APPLE_JWKS_URL));
	return jwks;
}

export function buildAppleAuthUrl(
	state: string,
	env: { APPLE_CLIENT_ID: string; APPLE_REDIRECT_URI: string },
): string {
	const url = new URL(APPLE_AUTHORIZE_URL);
	url.searchParams.set("client_id", env.APPLE_CLIENT_ID);
	url.searchParams.set("redirect_uri", env.APPLE_REDIRECT_URI);
	url.searchParams.set("response_type", "code id_token");
	url.searchParams.set("scope", "name email");
	url.searchParams.set("response_mode", "form_post");
	url.searchParams.set("state", state);
	return url.toString();
}

export async function buildAppleClientSecret(env: {
	APPLE_TEAM_ID: string;
	APPLE_CLIENT_ID: string;
	APPLE_KEY_ID: string;
	APPLE_PRIVATE_KEY: string;
}): Promise<string> {
	const key = await importPKCS8(env.APPLE_PRIVATE_KEY, "ES256");
	const iat = Math.floor(Date.now() / 1000);
	return new SignJWT({})
		.setProtectedHeader({ alg: "ES256", kid: env.APPLE_KEY_ID })
		.setIssuer(env.APPLE_TEAM_ID)
		.setIssuedAt(iat)
		.setExpirationTime(iat + CLIENT_SECRET_TTL_SECONDS)
		.setAudience(APPLE_ISSUER)
		.setSubject(env.APPLE_CLIENT_ID)
		.sign(key);
}

export async function verifyAppleIdToken(
	idToken: string,
	env: { APPLE_CLIENT_ID: string },
	// test-only override to avoid hitting the real network in unit tests
	jwksOverride?: JWTVerifyGetKey,
): Promise<{ sub: string; email?: string }> {
	const { payload } = await jwtVerify(idToken, jwksOverride ?? getJwks(), {
		issuer: APPLE_ISSUER,
		audience: env.APPLE_CLIENT_ID,
	});
	return {
		sub: payload.sub as string,
		email: payload.email as string | undefined,
	};
}
