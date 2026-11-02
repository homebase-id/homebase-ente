// Records sealed the Homebase way, as chat-kmp (the reference client) does it.
// Each file has its own random key: an AES-128 key and an IV. The key is
// locked with the drive key in a zkDrive key header, and the record's JSON
// is encrypted with it as the file's appData.content. Payloads use the same
// key with their own IV, and their thumbnails share that IV.
//
// The proxy (homebase-id/ente-homebase-proxy) stores and returns sealed
// records as they are (its SealedRecord.cs), and has no key that opens them.

import {
    type Bytes,
    concat,
    fromBase64,
    fromUtf8,
    randomBytes,
    toBase64,
    utf8,
} from "./bytes";
import { aesCbcDecrypt, aesCbcEncrypt } from "./crypto";

// A file's own key: AES-128 key and IV (chat-kmp KeyHeader).
export interface FileKey {
    aesKey: Bytes;
    iv: Bytes;
}

// As Odin stores it, and as a zkDrive file's header returns it.
export interface EncryptedKeyHeader {
    encryptionVersion: number;
    type: string | number;
    iv: string;
    encryptedAesKey: string;
}

// {"keyHeader", "content"}: what the web app sends the proxy, and gets back.
export interface SealedRecord {
    keyHeader: EncryptedKeyHeader;
    // Base64 of the AES-CBC of the record's JSON.
    content: string;
}

// A new random file key (chat-kmp KeyHeader.newRandom16).
export const newFileKey = (): FileKey => ({
    aesKey: randomBytes(16),
    iv: randomBytes(16),
});

// A zkDrive key header: AES-CBC(drive key, file IV, IV ‖ AesKey), 48 bytes.
export const lockFileKey = async (
    fileKey: FileKey,
    driveKey: Bytes,
): Promise<EncryptedKeyHeader> => ({
    encryptionVersion: 1,
    type: "zkDrive",
    iv: toBase64(fileKey.iv),
    encryptedAesKey: toBase64(
        await aesCbcEncrypt(
            driveKey,
            fileKey.iv,
            concat(fileKey.iv, fileKey.aesKey),
        ),
    ),
});

export const openFileKey = async (
    header: EncryptedKeyHeader,
    driveKey: Bytes,
): Promise<FileKey> => {
    if (header.type != "zkDrive" && header.type != 13) {
        throw new Error("Not a zkDrive key header");
    }
    const combined = await aesCbcDecrypt(
        driveKey,
        fromBase64(header.iv),
        fromBase64(header.encryptedAesKey),
    );
    if (combined.length != 32) {
        throw new Error("A zkDrive key header holds 32 bytes");
    }
    return { iv: combined.slice(0, 16), aesKey: combined.slice(16) };
};

// Seals `value` (as JSON) with `fileKey`, a new one unless given (a photo's
// key also encrypts its payload).
export const sealRecord = async (
    value: unknown,
    driveKey: Bytes,
    fileKey: FileKey = newFileKey(),
): Promise<{ sealed: SealedRecord; fileKey: FileKey }> => ({
    sealed: {
        keyHeader: await lockFileKey(fileKey, driveKey),
        content: toBase64(
            await aesCbcEncrypt(
                fileKey.aesKey,
                fileKey.iv,
                utf8(JSON.stringify(value)),
            ),
        ),
    },
    fileKey,
});

// Opens a sealed record: its parsed JSON and its key.
export const openRecord = async (
    sealed: SealedRecord,
    driveKey: Bytes,
): Promise<{ value: unknown; fileKey: FileKey }> => {
    const fileKey = await openFileKey(sealed.keyHeader, driveKey);
    const json = fromUtf8(
        await aesCbcDecrypt(
            fileKey.aesKey,
            fileKey.iv,
            fromBase64(sealed.content),
        ),
    );
    return { value: JSON.parse(json) as unknown, fileKey };
};

// A file key as one string, the way Ente keeps keys (base64): IV ‖ AesKey
// (chat-kmp KeyHeader.combine). Ente's EnteFile.key and Collection.key hold
// this in Homebase mode.
export const fileKeyToString = (fileKey: FileKey) =>
    toBase64(concat(fileKey.iv, fileKey.aesKey));

export const fileKeyFromString = (value: string): FileKey => {
    const combined = fromBase64(value);
    if (combined.length != 32) throw new Error("Not a Homebase file key");
    return { iv: combined.slice(0, 16), aesKey: combined.slice(16) };
};
