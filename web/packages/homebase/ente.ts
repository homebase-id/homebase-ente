// What the Ente app needs from a Homebase sign-in to talk to the proxy
// (proxy/ in this repo): the X-Auth-Token it sends on every request, and the
// numeric Ente user ID that stands for the identity. Both are computed the
// same way by the proxy (proxy/src/EnteHomebaseProxy/EnteIds.cs).

import { toBase64, toBase64Url, utf8 } from "./bytes";
import { sha256 } from "./crypto";
import type { DriveSession } from "./drive";

/**
 * The X-Auth-Token for the proxy: base64url of {"v":1,"identity","token","ss","dk"}.
 * It holds the drive key, so it's a secret: never in a URL or a log.
 */
export const xAuthToken = (session: DriveSession) =>
    toBase64Url(
        JSON.stringify({
            v: 1,
            identity: session.identity,
            token: toBase64(session.clientAuthToken),
            ss: toBase64(session.sharedSecret),
            dk: toBase64(session.driveKey),
        }),
    );

/**
 * Ente's user ID for an identity: the first 6 bytes of SHA-256(identity) as a
 * number (below 2^48, so exact in JavaScript). Stable, and the same on every
 * device and in the proxy.
 */
export const enteUserID = async (identity: string) => {
    const digest = await sha256(utf8(identity));
    return digest.slice(0, 6).reduce((n, byte) => n * 256 + byte, 0);
};

/** The email Ente shows for a Homebase identity (it has none of its own). */
export const enteEmail = (identity: string) => `${identity}@homebase.invalid`;
