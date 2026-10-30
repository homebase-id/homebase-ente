// The Homebase byte formats on WebCrypto, ported from the Immich Homebase
// client (packages/homebase-client/src/web/crypto.ts). Sources in odin-core:
// - AES-GCM token fields: docs/youauth-unified-authorization.md, "aes-gcm"
// - ZkSeal v1: src/services/Odin.Services/Security/ZeroKnowledge/ZkSeal.cs
// - zkLock: docs/zero-knowledge-drive-api-plan.md 3.5

import {
    type Bytes,
    concat,
    crc32,
    fromBase64,
    randomBytes,
    utf8,
} from "./bytes";

const subtle = () => globalThis.crypto.subtle;

export const sha256 = async (data: Bytes): Promise<Bytes> =>
    new Uint8Array(await subtle().digest("SHA-256", data));

const cbcKey = (key: Bytes) =>
    subtle().importKey("raw", key, "AES-CBC", false, ["encrypt", "decrypt"]);

/** AES-128-CBC with PKCS7 (the shared-secret envelope). */
export const aesCbcEncrypt = async (key: Bytes, iv: Bytes, data: Bytes) =>
    new Uint8Array(
        await subtle().encrypt(
            { name: "AES-CBC", iv },
            await cbcKey(key),
            data,
        ),
    );

export const aesCbcDecrypt = async (key: Bytes, iv: Bytes, data: Bytes) =>
    new Uint8Array(
        await subtle().decrypt(
            { name: "AES-CBC", iv },
            await cbcKey(key),
            data,
        ),
    );

/** AES-GCM: 12-byte nonce, 16-byte tag appended, no associated data. */
export const aesGcmEncrypt = async (key: Bytes, nonce: Bytes, data: Bytes) => {
    const k = await subtle().importKey("raw", key, "AES-GCM", false, [
        "encrypt",
    ]);
    return new Uint8Array(
        await subtle().encrypt({ name: "AES-GCM", iv: nonce }, k, data),
    );
};

export const aesGcmDecrypt = async (
    key: Bytes,
    nonce: Bytes,
    cipherAndTag: Bytes,
) => {
    const k = await subtle().importKey("raw", key, "AES-GCM", false, [
        "decrypt",
    ]);
    return new Uint8Array(
        await subtle().decrypt({ name: "AES-GCM", iv: nonce }, k, cipherAndTag),
    );
};

/** A zkLock: base64 of 12-byte IV ‖ AES-GCM ciphertext ‖ tag. */
export const openZkLock = (key: Bytes, zkLockBase64: string) => {
    const lock = fromBase64(zkLockBase64);
    return aesGcmDecrypt(key, lock.slice(0, 12), lock.slice(12));
};

export const makeZkLock = async (key: Bytes, value: Bytes) => {
    const nonce = randomBytes(12);
    return concat(nonce, await aesGcmEncrypt(key, nonce, value));
};

export const hkdfSha256 = async (
    ikm: Bytes,
    salt: Bytes,
    info: Bytes,
    length = 16,
): Promise<Bytes> => {
    const key = await subtle().importKey("raw", ikm, "HKDF", false, [
        "deriveBits",
    ]);
    return new Uint8Array(
        await subtle().deriveBits(
            { name: "HKDF", hash: "SHA-256", salt, info },
            key,
            length * 8,
        ),
    );
};

// P-384. Public keys travel as JWK JSON; the raw point is 0x04 ‖ x ‖ y.
export const p384CoordinateLength = 48;
const p384 = { name: "ECDH", namedCurve: "P-384" } as const;

/** Extractable, so a pending sign-in can be kept across the redirect. */
export const generateP384KeyPair = () =>
    subtle().generateKey(p384, true, ["deriveBits"]);

/** Only the public fields of an EC JWK (drops `d`, `key_ops`, `ext`). */
const publicJwk = ({ kty, crv, x, y }: JsonWebKey): JsonWebKey => {
    if (
        kty === undefined ||
        crv === undefined ||
        x === undefined ||
        y === undefined
    ) {
        throw new Error("Not an EC public key JWK");
    }
    return { kty, crv, x, y };
};

export const publicKeyToJwkJson = async (publicKey: CryptoKey) =>
    JSON.stringify(publicJwk(await subtle().exportKey("jwk", publicKey)));

export const publicKeyFromJwkJson = (jwkJson: string) =>
    subtle().importKey(
        "jwk",
        publicJwk(JSON.parse(jwkJson) as JsonWebKey),
        p384,
        true,
        [],
    );

export const publicKeyFromRawPoint = (point: Bytes) => {
    if (point.length != 1 + 2 * p384CoordinateLength || point[0] != 0x04) {
        throw new Error("Not an uncompressed P-384 point");
    }
    return subtle().importKey("raw", point, p384, true, []);
};

export const rawPoint = async (publicKey: CryptoKey): Promise<Bytes> =>
    new Uint8Array(await subtle().exportKey("raw", publicKey));

export const privateKeyToJwk = (privateKey: CryptoKey) =>
    subtle().exportKey("jwk", privateKey);

export const privateKeyFromJwk = (jwk: JsonWebKey) =>
    subtle().importKey("jwk", jwk, p384, true, ["deriveBits"]);

/** The public half of a private key, from its JWK (x and y are in it). */
export const publicKeyOf = async (privateKey: CryptoKey) =>
    subtle().importKey(
        "jwk",
        publicJwk(await subtle().exportKey("jwk", privateKey)),
        p384,
        true,
        [],
    );

/**
 * The ECDH X coordinate. WebCrypto always returns the full 48 bytes; a client
 * that drops a leading zero fails one sign-in in 256 (odin-core #1728).
 */
export const ecdhSharedX = async (
    privateKey: CryptoKey,
    publicKey: CryptoKey,
): Promise<Bytes> =>
    new Uint8Array(
        await subtle().deriveBits(
            { name: "ECDH", public: publicKey },
            privateKey,
            p384CoordinateLength * 8,
        ),
    );

// ZkSeal version 1: 0x01 ‖ key id (4 bytes, big-endian, CRC-32 of the
// recipient's raw point) ‖ throwaway public key (97 bytes) ‖ 12-byte IV ‖
// AES-GCM ciphertext and tag. Key: hkdf-sha256(ECDH X, no salt,
// "homebase-zk-seal"), 16 bytes.
const sealVersion = 1;
const sealInfo = utf8("homebase-zk-seal");
const sealPointOffset = 5;
const sealIvOffset = sealPointOffset + 97;
const sealCipherOffset = sealIvOffset + 12;

export const sealKeyId = async (publicKey: CryptoKey) =>
    crc32(await rawPoint(publicKey));

export const readSealKeyId = (sealed: Uint8Array): number => {
    if (
        sealed.length < sealCipherOffset + 16 ||
        sealed[0] != sealVersion ||
        sealed[sealPointOffset] != 0x04
    ) {
        throw new Error("Not a sealed value");
    }
    return new DataView(
        sealed.buffer,
        sealed.byteOffset,
        sealed.byteLength,
    ).getUint32(1);
};

/** Seals to a public key. Only tests need this: the identity seals. */
export const zkSeal = async (data: Bytes, recipient: CryptoKey) => {
    const throwaway = await generateP384KeyPair();
    const key = await hkdfSha256(
        await ecdhSharedX(throwaway.privateKey, recipient),
        new Uint8Array(0),
        sealInfo,
    );
    const iv = randomBytes(12);
    const keyId = new Uint8Array(4);
    new DataView(keyId.buffer).setUint32(0, await sealKeyId(recipient));
    return concat(
        new Uint8Array([sealVersion]),
        keyId,
        await rawPoint(throwaway.publicKey),
        iv,
        await aesGcmEncrypt(key, iv, data),
    );
};

export const zkUnseal = async (sealed: Bytes, privateKey: CryptoKey) => {
    if (
        readSealKeyId(sealed) !=
        (await sealKeyId(await publicKeyOf(privateKey)))
    ) {
        throw new Error("Sealed to a different key");
    }
    const throwaway = await publicKeyFromRawPoint(
        sealed.slice(sealPointOffset, sealIvOffset),
    );
    const key = await hkdfSha256(
        await ecdhSharedX(privateKey, throwaway),
        new Uint8Array(0),
        sealInfo,
    );
    return aesGcmDecrypt(
        key,
        sealed.slice(sealIvOffset, sealCipherOffset),
        sealed.slice(sealCipherOffset),
    );
};
