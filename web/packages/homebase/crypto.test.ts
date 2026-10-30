// Every crypto step, checked against vectors written by the Immich Homebase
// client's TypeScript implementation (packages/homebase-client/scripts/
// vectors.ts, Node crypto), so this WebCrypto port and that one agree byte for
// byte. Random test keys only.

import { describe, expect, test } from "vitest";
import { crc32, fromBase64, fromUtf8, toBase64 } from "./bytes";
import { decryptEnvelope } from "./context";
import {
    aesCbcDecrypt,
    aesCbcEncrypt,
    aesGcmDecrypt,
    aesGcmEncrypt,
    hkdfSha256,
    makeZkLock,
    openZkLock,
    privateKeyFromJwk,
    publicKeyFromJwkJson,
    publicKeyOf,
    rawPoint,
    readSealKeyId,
    sealKeyId,
    sha256,
    zkSeal,
    zkUnseal,
} from "./crypto";
import vectors from "./vectors.json";

const b = fromBase64;

describe("matches the Immich TypeScript client", () => {
    test("AES-CBC", async () => {
        const { key, iv, plain, cipher } = vectors.aesCbc;
        expect(toBase64(await aesCbcEncrypt(b(key), b(iv), b(plain)))).toBe(
            cipher,
        );
        expect(toBase64(await aesCbcDecrypt(b(key), b(iv), b(cipher)))).toBe(
            plain,
        );
    });

    test("AES-GCM", async () => {
        const { key, nonce, plain, cipher } = vectors.aesGcm;
        expect(toBase64(await aesGcmEncrypt(b(key), b(nonce), b(plain)))).toBe(
            cipher,
        );
        expect(toBase64(await aesGcmDecrypt(b(key), b(nonce), b(cipher)))).toBe(
            plain,
        );
    });

    test("AES-GCM refuses a modified byte", async () => {
        const { key, nonce, cipher } = vectors.aesGcm;
        const tampered = b(cipher);
        tampered[3]! ^= 1;
        await expect(
            aesGcmDecrypt(b(key), b(nonce), tampered),
        ).rejects.toThrow();
    });

    test("HKDF-SHA256", async () => {
        const { ikm, salt, okm } = vectors.hkdf;
        expect(
            toBase64(await hkdfSha256(b(ikm), b(salt), new Uint8Array(0))),
        ).toBe(okm);
    });

    test("SHA-256", async () => {
        expect(toBase64(await sha256(b(vectors.sha256.data)))).toBe(
            vectors.sha256.digest,
        );
    });

    test("CRC-32", () => {
        expect(crc32(b(vectors.crc32.data))).toBe(vectors.crc32.value);
    });

    test("P-384 keys: JWK and raw point", async () => {
        const {
            recipientPrivateJwk,
            recipientPublicJwkJson,
            recipientRawPoint,
        } = vectors.zkSeal;
        const privateKey = await privateKeyFromJwk(recipientPrivateJwk);
        expect(toBase64(await rawPoint(await publicKeyOf(privateKey)))).toBe(
            recipientRawPoint,
        );
        expect(
            toBase64(
                await rawPoint(
                    await publicKeyFromJwkJson(recipientPublicJwkJson),
                ),
            ),
        ).toBe(recipientRawPoint);
    });

    test("ZkSeal: opens what the TypeScript client sealed", async () => {
        const { recipientPrivateJwk, sealed, plain } = vectors.zkSeal;
        const privateKey = await privateKeyFromJwk(recipientPrivateJwk);
        expect(toBase64(await zkUnseal(b(sealed), privateKey))).toBe(plain);
        expect(readSealKeyId(b(sealed))).toBe(
            await sealKeyId(await publicKeyOf(privateKey)),
        );
    });

    test("ZkSeal: refuses a value sealed to another key", async () => {
        const { recipientPrivateJwk, plain } = vectors.zkSeal;
        const other = await crypto.subtle.generateKey(
            { name: "ECDH", namedCurve: "P-384" },
            true,
            ["deriveBits"],
        );
        const sealed = await zkSeal(b(plain), other.publicKey);
        await expect(
            zkUnseal(sealed, await privateKeyFromJwk(recipientPrivateJwk)),
        ).rejects.toThrow("Sealed to a different key");
    });

    test("ZkSeal: round trip", async () => {
        const { recipientPrivateJwk, recipientPublicJwkJson, plain } =
            vectors.zkSeal;
        const sealed = await zkSeal(
            b(plain),
            await publicKeyFromJwkJson(recipientPublicJwkJson),
        );
        expect(sealed.length).toBe(1 + 4 + 97 + 12 + 16 + 16);
        expect(
            toBase64(
                await zkUnseal(
                    sealed,
                    await privateKeyFromJwk(recipientPrivateJwk),
                ),
            ),
        ).toBe(plain);
    });

    test("zkLock", async () => {
        const { key, value, lock } = vectors.zkLock;
        expect(toBase64(await openZkLock(b(key), lock))).toBe(value);
        const mine = await makeZkLock(b(key), b(value));
        expect(toBase64(await openZkLock(b(key), toBase64(mine)))).toBe(value);
    });

    test("shared-secret envelope", async () => {
        const { sharedSecret, plain, envelope } = vectors.envelope;
        expect(fromUtf8(await decryptEnvelope(b(sharedSecret), envelope))).toBe(
            plain,
        );
    });
});
