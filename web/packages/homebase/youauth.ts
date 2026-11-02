// YouAuth app sign-in from a browser (odin-core
// docs/youauth-unified-authorization.md), ported from the Immich Homebase
// client (packages/homebase-client/src/web/youauth.ts). The pending sign-in is
// plain JSON (the private key as a JWK) so the page can keep it in
// sessionStorage across the redirect to the identity and back.

import {
    type Bytes,
    fromBase64,
    fromUtf8,
    randomBytes,
    toBase64,
    toBase64Url,
} from "./bytes";
import {
    aesGcmDecrypt,
    ecdhSharedX,
    generateP384KeyPair,
    hkdfSha256,
    privateKeyFromJwk,
    privateKeyToJwk,
    publicKeyFromJwkJson,
    publicKeyToJwkJson,
    sha256,
    zkUnseal,
} from "./crypto";

export interface DriveRequest {
    /** 32 hex. */
    alias: string;
    /** 32 hex. */
    type: string;
    name: string;
    description: string;
    /** 3 is read + write (DrivePermission.cs). */
    permission: number;
    driveSlug: string;
    driveTypeSlug: string;
    /** "private" makes it a zero-knowledge drive. */
    sharingModel: "private" | "selectiveShare" | "collaborative";
}

export interface AppRegistration {
    appId: string;
    appName: string;
    /** Immutable once registered: `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`. */
    appSlug: string;
    clientFriendlyName: string;
    drives: DriveRequest[];
}

export interface PendingSignIn {
    identity: string;
    state: string;
    privateKeyJwk: JsonWebKey;
    redirectURI: string;
}

/** What an app holds after YouAuth. All of it is secret. */
export interface YouAuthCredentials {
    identity: string;
    /** 33 bytes; sent as `Authorization: Bearer <base64>`. */
    clientAuthToken: Bytes;
    /** 16 bytes; the key of the `{iv, data}` envelopes. */
    sharedSecret: Bytes;
    /** 16 bytes; the app's key to its zero-knowledge drives. */
    appZkKey: Bytes;
}

export type YouAuthErrorKind =
    /** The owner said no (`cancelled-by-user`, `access-denied`). */
    | "denied"
    /** The owner revoked the app. */
    | "revoked"
    /** The callback isn't for the sign-in this browser started. */
    | "state-mismatch"
    /** The token exchange failed: expired (5 min), reused, or refused. */
    | "exchange-failed"
    /** The identity gave no zero-knowledge app key (odin-core too old). */
    | "no-zero-knowledge"
    /** A call was refused (401/403): sign in with Homebase again. */
    | "unauthorized"
    | "other";

export class YouAuthError extends Error {
    constructor(
        readonly kind: YouAuthErrorKind,
        message: string,
    ) {
        super(message);
        this.name = "YouAuthError";
    }
}

/** "https://Frodo.Example/x" → "frodo.example". */
export const normalizeIdentity = (identity: string) =>
    identity
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/[/?#].*$/, "")
        .replace(/\.$/, "");

const hostnameRegex =
    /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}(:\d+)?$/;

export const isValidIdentity = (identity: string) =>
    hostnameRegex.test(normalizeIdentity(identity));

const toDriveParam = (drive: DriveRequest) => ({
    a: drive.alias,
    t: drive.type,
    n: drive.name,
    d: drive.description,
    p: drive.permission,
    ds: drive.driveSlug,
    ts: drive.driveTypeSlug,
    sm: drive.sharingModel,
});

/**
 * Step 1 and 2: a fresh key pair and state, and the URL of the identity's
 * authorize page. Keep `pending` until the callback.
 */
export const createAuthorizeRequest = async (
    identity: string,
    app: AppRegistration,
    redirectURI: string,
): Promise<{ url: string; pending: PendingSignIn }> => {
    const host = normalizeIdentity(identity);
    if (!hostnameRegex.test(host)) {
        throw new YouAuthError("other", "Not a Homebase identity");
    }
    const { privateKey, publicKey } = await generateP384KeyPair();
    const state = toBase64Url(randomBytes(16));
    const url = new URL(`https://${host}/api/owner/v1/youauth/authorize`);
    const params: Record<string, string> = {
        client_id: app.appId,
        client_type: "app",
        client_info: app.clientFriendlyName,
        redirect_uri: redirectURI,
        permission_request: JSON.stringify({
            n: app.appName,
            appId: app.appId,
            as: app.appSlug,
            fn: app.clientFriendlyName,
            d: JSON.stringify(app.drives.map(toDriveParam)),
            return: "backend-will-decide",
        }),
        public_key: toBase64Url(await publicKeyToJwkJson(publicKey)),
        state,
        cipher: "aes-gcm",
        zk_app_key: "1",
    };
    for (const [key, value] of Object.entries(params)) {
        url.searchParams.set(key, value);
    }
    return {
        url: url.toString(),
        pending: {
            identity: host,
            state,
            privateKeyJwk: await privateKeyToJwk(privateKey),
            redirectURI,
        },
    };
};

interface TokenResponse {
    base64SharedSecretCipher: string;
    base64SharedSecretIv: string;
    base64ClientAuthTokenCipher: string;
    base64ClientAuthTokenIv: string;
    cipher?: string | null;
    zkAppKey?: string | null;
}

/** An aes-gcm token field: the nonce is the first 12 bytes of the 16-byte IV. */
const openTokenField = (key: Bytes, ivBase64: string, cipherBase64: string) =>
    aesGcmDecrypt(
        key,
        fromBase64(ivBase64).slice(0, 12),
        fromBase64(cipherBase64),
    );

const callbackError = (error: string, description: string | null) => {
    const message = `${error}${description ? `: ${description}` : ""}`;
    switch (error) {
        case "cancelled-by-user":
        case "access-denied":
            return new YouAuthError("denied", message);
        case "app-revoked":
            return new YouAuthError("revoked", message);
        default:
            return new YouAuthError("other", message);
    }
};

/**
 * Derives the exchange secret: HKDF-SHA256(ECDH X, 48 bytes, salt), no info,
 * 16 bytes.
 */
export const exchangeSecret = async (
    privateKey: CryptoKey,
    remotePublicKeyBase64: string,
    saltBase64: string,
) =>
    hkdfSha256(
        await ecdhSharedX(
            privateKey,
            await publicKeyFromJwkJson(
                fromUtf8(fromBase64(remotePublicKeyBase64)),
            ),
        ),
        fromBase64(saltBase64),
        new Uint8Array(0),
    );

/**
 * Steps 3 to 7: finishes a sign-in from the callback's query, trusting the
 * identity it sent the browser to, never one the callback names.
 */
export const completeSignIn = async (
    pending: PendingSignIn,
    callback: URLSearchParams,
    fetchImpl: typeof fetch = fetch,
): Promise<YouAuthCredentials> => {
    const error = callback.get("error");
    if (error) throw callbackError(error, callback.get("error_description"));
    if (callback.get("state") != pending.state) {
        throw new YouAuthError(
            "state-mismatch",
            "This sign-in wasn't started in this browser tab",
        );
    }
    const remotePublicKey = callback.get("public_key");
    const salt = callback.get("salt");
    if (!remotePublicKey || !salt) {
        throw new YouAuthError(
            "other",
            "The callback has no public_key or salt",
        );
    }

    const privateKey = await privateKeyFromJwk(pending.privateKeyJwk);
    const secret = await exchangeSecret(privateKey, remotePublicKey, salt);
    const response = await fetchImpl(
        `https://${pending.identity}/api/owner/v1/youauth/token`,
        {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
                secret_digest: toBase64(await sha256(secret)),
            }),
        },
    );
    if (!response.ok) {
        throw new YouAuthError(
            "exchange-failed",
            `Token exchange failed (HTTP ${response.status}); it may have expired or been used`,
        );
    }
    const token = (await response.json()) as TokenResponse;
    if ((token.cipher ?? "aes-cbc") != "aes-gcm") {
        throw new YouAuthError(
            "exchange-failed",
            "Asked for aes-gcm, got aes-cbc",
        );
    }
    if (!token.zkAppKey) {
        throw new YouAuthError(
            "no-zero-knowledge",
            "This identity doesn't support zero-knowledge drives yet",
        );
    }
    return {
        identity: pending.identity,
        sharedSecret: await openTokenField(
            secret,
            token.base64SharedSecretIv,
            token.base64SharedSecretCipher,
        ),
        clientAuthToken: await openTokenField(
            secret,
            token.base64ClientAuthTokenIv,
            token.base64ClientAuthTokenCipher,
        ),
        appZkKey: await zkUnseal(fromBase64(token.zkAppKey), privateKey),
    };
};
