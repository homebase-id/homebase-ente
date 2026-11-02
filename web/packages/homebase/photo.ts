// A photo kept the Homebase way, as chat-kmp keeps media. The photo is one
// file with its own random key (records.ts). Its details are sealed with that
// key, and its original and thumbnails are encrypted with that key and the
// payload's own random IV. The proxy stores all of it as sent and can open
// none of it.
//
// Ente's record of the photo says so with decryptionHeader: "homebase-v2",
// and for the file and thumbnail "homebase-v2:" and the payload IV
// (the proxy's EnteRecords.File).

import { type Bytes, fromBase64, randomBytes } from "./bytes";
import { photo } from "./constants";
import { aesCbcDecrypt, aesCbcEncrypt } from "./crypto";

// Whether an Ente file or thumbnail decryptionHeader is a Homebase photo's.
export const isHomebasePhoto = (decryptionHeader: string) =>
    decryptionHeader.startsWith(`${photo.format}:`);

// The payload IV in a Homebase photo's file or thumbnail decryptionHeader.
export const photoPayloadIv = (decryptionHeader: string): Bytes => {
    if (!isHomebasePhoto(decryptionHeader)) {
        throw new Error("Not a Homebase photo");
    }
    const iv = fromBase64(decryptionHeader.slice(photo.format.length + 1));
    if (iv.length != 16) throw new Error("A payload IV is 16 bytes");
    return iv;
};

// A new Ente file ID: milliseconds since 1970 × 2048 + random 0–2047, as the
// proxy makes them (EnteIds.NewId). Increases with time; below 2^53.
export const newPhotoID = (now = Date.now()) =>
    now * 2048 + (crypto.getRandomValues(new Uint16Array(1))[0]! % 2048);

// A payload's own IV (chat-kmp PayloadBundleEncryptionService).
export const newPayloadIv = () => randomBytes(16);

// A payload or its thumbnail, encrypted with the photo's key and the payload's IV.
export const encryptPayload = (aesKey: Bytes, payloadIv: Bytes, data: Bytes) =>
    aesCbcEncrypt(aesKey, payloadIv, data);

export const decryptPayload = (aesKey: Bytes, payloadIv: Bytes, data: Bytes) =>
    aesCbcDecrypt(aesKey, payloadIv, data);
