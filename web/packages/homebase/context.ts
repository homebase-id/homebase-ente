// What an app reads with its credentials: the security context (and its drive
// keys), and the identity's public profile. Ported from the Immich Homebase
// client (packages/homebase-client/src/web/keys.ts).

import { type Bytes, fromBase64, fromUtf8, randomBytes, toBase64, utf8 } from "./bytes";
import { aesCbcDecrypt, aesCbcEncrypt, openZkLock } from "./crypto";
import { YouAuthError } from "./youauth";

/** Credentials an app needs to call its identity's API. */
export interface AppCredentials {
    identity: string;
    clientAuthToken: Bytes;
    sharedSecret: Bytes;
}

/** A shared-secret envelope: AES-128-CBC/PKCS7 under the shared secret. */
export interface SharedSecretEnvelope {
    iv: string;
    data: string;
}

export const encryptEnvelope = async (
    sharedSecret: Bytes,
    plaintext: string,
): Promise<SharedSecretEnvelope> => {
    const iv = randomBytes(16);
    return {
        iv: toBase64(iv),
        data: toBase64(await aesCbcEncrypt(sharedSecret, iv, utf8(plaintext))),
    };
};

export const decryptEnvelope = (
    sharedSecret: Bytes,
    envelope: SharedSecretEnvelope,
) =>
    aesCbcDecrypt(
        sharedSecret,
        fromBase64(envelope.iv),
        fromBase64(envelope.data),
    );

/**
 * The `X-SSE` header isn't exposed to CORS, so an envelope is recognised by its
 * shape.
 */
export const isEnvelope = (value: unknown): value is SharedSecretEnvelope =>
    !!value &&
    typeof value == "object" &&
    typeof (value as SharedSecretEnvelope).iv == "string" &&
    typeof (value as SharedSecretEnvelope).data == "string";

/** An encrypted GET query: `?ss=<url-encoded envelope of the plain query>`. */
export const encryptQuery = async (sharedSecret: Bytes, query: string) =>
    `ss=${encodeURIComponent(JSON.stringify(await encryptEnvelope(sharedSecret, query)))}`;

/** `GET /api/v2/auth/context`, unwrapped from the shared-secret envelope. */
export const getSecurityContext = async (
    credentials: AppCredentials,
    fetchImpl: typeof fetch = fetch,
): Promise<unknown> => {
    const response = await fetchImpl(
        `https://${credentials.identity}/api/v2/auth/context`,
        {
            headers: {
                authorization: `Bearer ${toBase64(credentials.clientAuthToken)}`,
            },
        },
    );
    if (response.status == 401 || response.status == 403) {
        throw new YouAuthError(
            "unauthorized",
            "Homebase refused this app; log in with Homebase again",
        );
    }
    if (!response.ok) {
        throw new YouAuthError("other", `auth/context: HTTP ${response.status}`);
    }
    const body: unknown = await response.json();
    return isEnvelope(body)
        ? JSON.parse(fromUtf8(await decryptEnvelope(credentials.sharedSecret, body)))
        : body;
};

interface DriveGrant {
    permissionedDrive?: { drive?: { alias?: string } };
    zkAppKeyEncryptedStorageKey?: string | null;
}

const findDriveGrants = (node: unknown, found: DriveGrant[] = []) => {
    if (Array.isArray(node)) {
        for (const child of node) findDriveGrants(child, found);
    } else if (node && typeof node == "object") {
        if ("permissionedDrive" in node) found.push(node as DriveGrant);
        for (const child of Object.values(node)) findDriveGrants(child, found);
    }
    return found;
};

const sameGuid = (a?: string, b?: string) =>
    !!a &&
    !!b &&
    a.replaceAll("-", "").toLowerCase() == b.replaceAll("-", "").toLowerCase();

/**
 * Opens DrvK for one drive from the security context with the app's AppZkK.
 *
 * A grant without `zkAppKeyEncryptedStorageKey` means this app has no copy of
 * the drive's key yet: sign in again, never treat the drive as collaborative
 * (zero-knowledge-drive-api-plan.md 4.2).
 */
export const openDriveKey = (
    context: unknown,
    driveAlias: string,
    appZkKey: Bytes,
) => {
    const grant = findDriveGrants(context).find((g) =>
        sameGuid(g.permissionedDrive?.drive?.alias, driveAlias),
    );
    if (!grant) {
        throw new YouAuthError("unauthorized", "This app has no access to its drive");
    }
    if (!grant.zkAppKeyEncryptedStorageKey) {
        throw new YouAuthError(
            "no-zero-knowledge",
            "The drive has no zero-knowledge key for this app",
        );
    }
    return openZkLock(appZkKey, grant.zkAppKeyEncryptedStorageKey);
};

export interface HomebaseProfile {
    /** The identity, e.g. "frodo.baggins.demo.rocks". */
    identity: string;
    /** The profile name, if the owner published one. */
    name?: string;
    /** The public avatar. */
    imageURL: string;
}

/** `GET /pub/profile` (the profile card js-lib publishes): public, no token. */
export const getProfile = async (
    identity: string,
    fetchImpl: typeof fetch = fetch,
): Promise<HomebaseProfile> => {
    const profile: HomebaseProfile = {
        identity,
        imageURL: `https://${identity}/pub/image`,
    };
    try {
        const response = await fetchImpl(`https://${identity}/pub/profile`);
        if (response.ok) {
            const name = profileName(await response.json());
            if (name) profile.name = name;
        }
    } catch {
        // The profile is decoration; the identity is the name.
    }
    return profile;
};

const profileName = (body: unknown): string | undefined => {
    if (!body || typeof body != "object") return undefined;
    const { name, givenName, familyName } = body as Record<string, unknown>;
    if (typeof name == "string" && name.trim()) return name.trim();
    const parts = [givenName, familyName].filter(
        (p): p is string => typeof p == "string" && !!p.trim(),
    );
    return parts.length ? parts.join(" ") : undefined;
};
