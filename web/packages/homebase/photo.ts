// A photo kept the Homebase way: the web app encrypts the original and its
// thumbnails in Homebase's format (AES-CBC with a file key, the key locked
// with the drive key), and the proxy stores them as sent. Ente's own
// encryption stays on its record of the photo, not on the media.
//
// The proxy derives the same key (OdinCrypto.DeriveObjectKey) and IDs
// (EnteIds.cs); its contract/ente-homebase.json has a test value both check.

import { fromBase64, fromUtf8, utf8, type Bytes } from "./bytes";
import { photo } from "./constants";
import { aesCbcDecrypt, aesCbcEncrypt, hkdfSha256 } from "./crypto";

/** Whether an Ente record's decryptionHeader says the bytes are a Homebase photo's. */
export const isHomebasePhoto = (decryptionHeader: string) =>
    decryptionHeader === photo.format;

/**
 * A new Ente file ID: milliseconds since 1970 × 2048 + random 0–2047, as the
 * proxy makes them (EnteIds.NewId). Increases with time; below 2^53.
 */
export const newPhotoID = (now = Date.now()) =>
    now * 2048 + (crypto.getRandomValues(new Uint16Array(1))[0]! % 2048);

/** The uniqueId of the photo with this Ente ID: 01 ‖ 7 zero bytes ‖ ID (big-endian). */
export const photoUniqueId = (id: number): Bytes => {
    if (!Number.isSafeInteger(id) || id <= 0) throw new Error("Bad photo ID");
    const bytes = new Uint8Array(16);
    bytes[0] = 1;
    new DataView(bytes.buffer).setBigUint64(8, BigInt(id));
    return bytes;
};

export interface PhotoKey {
    aesKey: Bytes;
    /** Also the payload's IV, which its thumbnails share (Homebase's way). */
    iv: Bytes;
}

/**
 * A photo's file key: HKDF-SHA256(drive key, salt = its uniqueId, info =
 * "ente-homebase-object"), 32 bytes = AES key ‖ IV. Derived rather than
 * random so a read needs no header first; the proxy also locks it in the
 * file's key header, so other Homebase apps open the file as usual.
 */
export const photoKey = async (
    driveKey: Bytes,
    id: number,
): Promise<PhotoKey> => {
    const okm = await hkdfSha256(
        driveKey,
        photoUniqueId(id),
        utf8(photo.keyInfo),
        32,
    );
    return { aesKey: okm.slice(0, 16), iv: okm.slice(16) };
};

export const encryptPhotoBytes = (key: PhotoKey, data: Bytes) =>
    aesCbcEncrypt(key.aesKey, key.iv, data);

export const decryptPhotoBytes = (key: PhotoKey, data: Bytes) =>
    aesCbcDecrypt(key.aesKey, key.iv, data);

/** The drive key in an X-Auth-Token (ente.ts xAuthToken). */
export const driveKeyOf = (xAuthToken: string): Bytes => {
    const { dk } = JSON.parse(fromUtf8(fromBase64(xAuthToken))) as {
        dk?: unknown;
    };
    if (typeof dk != "string") throw new Error("No drive key in the token");
    return fromBase64(dk);
};
