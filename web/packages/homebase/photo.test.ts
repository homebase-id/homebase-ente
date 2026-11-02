import { describe, expect, test } from "vitest";
import { randomBytes, toBase64 } from "./bytes";
import {
    decryptPayload,
    encryptPayload,
    isHomebasePhoto,
    newPayloadIv,
    newPhotoID,
    photoPayloadIv,
} from "./photo";
import { newFileKey } from "./records";
import { thumbnailSizes } from "./thumbnails";

describe("photo", () => {
    test("the payload IV is in the decryptionHeader the proxy sends", () => {
        const iv = newPayloadIv();
        const header = `homebase-v2:${toBase64(iv)}`;
        expect(isHomebasePhoto(header)).toBe(true);
        expect(photoPayloadIv(header)).toEqual(iv);
        expect(isHomebasePhoto("homebase-v2")).toBe(false);
        expect(isHomebasePhoto("homebase-v1")).toBe(false);
        expect(() => photoPayloadIv("homebase-v2:AAAA")).toThrow();
    });

    test("a payload opens with the photo's key and its own IV", async () => {
        const { aesKey, iv } = newFileKey();
        const payloadIv = newPayloadIv();
        expect(payloadIv).not.toEqual(iv);
        const data = randomBytes(1000);
        const encrypted = await encryptPayload(aesKey, payloadIv, data);
        expect(await decryptPayload(aesKey, payloadIv, encrypted)).toEqual(
            data,
        );
        // CBC with the wrong IV garbles the first block.
        expect(
            (await decryptPayload(aesKey, iv, encrypted)).slice(0, 16),
        ).not.toEqual(data.slice(0, 16));
    });

    test("new IDs grow with time and stay exact in JavaScript", () => {
        const id = newPhotoID(Date.UTC(2026, 9, 30));
        expect(Number.isSafeInteger(id)).toBe(true);
        expect(newPhotoID(Date.UTC(2026, 9, 30) + 1)).toBeGreaterThan(id);
        expect(Number.isSafeInteger(newPhotoID(Date.UTC(2109, 0, 1)))).toBe(
            true,
        );
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
