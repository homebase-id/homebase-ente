import { describe, expect, test } from "vitest";
import { fromBase64, toBase64, utf8 } from "./bytes";
import {
    decryptPhotoBytes,
    driveKeyOf,
    encryptPhotoBytes,
    newPhotoID,
    photoKey,
    photoUniqueId,
} from "./photo";
import { thumbnailSizes } from "./thumbnails";

// The proxy's contract/ente-homebase.json testValues.photoKey: the proxy
// checks the same values (ContractTests.ThePhotoKeyMatchesTheContractsTestValue).
const vector = {
    driveKey: "AAECAwQFBgcICQoLDA0ODw==",
    fileID: 3672856974923286,
    uniqueId: "01000000-0000-0000-000d-0c71a74d1616",
    aesKey: "5ed72441b8e5987d1e55d7364f285758",
    iv: "57c5b70fbf97a9e40a3e188ef526d5af",
    plaintext: "hello homebase",
    ciphertext: "Z9LEPwmA4ChvBtF87CMEzA==",
};

const hex = (bytes: Uint8Array) =>
    Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

describe("photo", () => {
    test("the uniqueId and key are the proxy's", async () => {
        const uid = hex(photoUniqueId(vector.fileID));
        expect(
            `${uid.slice(0, 8)}-${uid.slice(8, 12)}-${uid.slice(12, 16)}-${uid.slice(16, 20)}-${uid.slice(20)}`,
        ).toBe(vector.uniqueId);
        const key = await photoKey(fromBase64(vector.driveKey), vector.fileID);
        expect(hex(key.aesKey)).toBe(vector.aesKey);
        expect(hex(key.iv)).toBe(vector.iv);
        const encrypted = await encryptPhotoBytes(key, utf8(vector.plaintext));
        expect(toBase64(encrypted)).toBe(vector.ciphertext);
        expect(await decryptPhotoBytes(key, encrypted)).toEqual(
            utf8(vector.plaintext),
        );
    });

    test("new IDs grow with time and stay exact in JavaScript", () => {
        const id = newPhotoID(Date.UTC(2026, 9, 30));
        expect(Number.isSafeInteger(id)).toBe(true);
        expect(newPhotoID(Date.UTC(2026, 9, 30) + 1)).toBeGreaterThan(id);
        expect(Number.isSafeInteger(newPhotoID(Date.UTC(2109, 0, 1)))).toBe(
            true,
        );
    });

    test("the drive key comes out of the X-Auth-Token", () => {
        const token = btoa(JSON.stringify({ v: 1, dk: vector.driveKey }))
            .replaceAll("+", "-")
            .replaceAll("/", "_")
            .replace(/=+$/, "");
        expect(toBase64(driveKeyOf(token))).toBe(vector.driveKey);
    });
});

describe("thumbnails", () => {
    test("chat-kmp's sizes, never above the source", () => {
        const max = (n: number) =>
            thumbnailSizes(n).map((t) => t.maxPixelDimension);
        expect(max(4000)).toEqual([320, 640, 1080, 1600]);
        expect(max(1300)).toEqual([320, 640, 1080, 1300]);
        expect(max(1200)).toEqual([320, 640, 1200]); // 1080 is within 10%
        expect(max(1100)).toEqual([320, 640, 1100]);
        expect(max(400)).toEqual([320, 400]);
        expect(max(300)).toEqual([300]);
    });
});
