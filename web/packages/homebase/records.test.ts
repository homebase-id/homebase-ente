import { describe, expect, test } from "vitest";
import { fromBase64, randomBytes, toBase64 } from "./bytes";
import {
    fileKeyFromString,
    fileKeyToString,
    lockFileKey,
    newFileKey,
    openFileKey,
    openRecord,
    sealRecord,
} from "./records";
import vectors from "./vectors.json";

// The key header vector is also checked by the proxy
// (CryptoVectorTests.TheVectorsKeyHeaderIsASealedRecordsKeyHeader).
const v = vectors.keyHeader;

describe("records", () => {
    test("a key header is locked as chat-kmp locks it", async () => {
        const fileKey = { aesKey: fromBase64(v.aesKey), iv: fromBase64(v.iv) };
        const header = await lockFileKey(fileKey, fromBase64(v.driveKey));
        expect(header).toEqual(v.header);
        expect(await openFileKey(v.header, fromBase64(v.driveKey))).toEqual(
            fileKey,
        );
    });

    test("a sealed record opens to what was sealed, only with the drive key", async () => {
        const driveKey = randomBytes(16);
        const value = { type: "album", name: "Holidays", n: [1, 2] };
        const { sealed, fileKey } = await sealRecord(value, driveKey);
        expect(sealed.keyHeader.type).toBe("zkDrive");
        expect(sealed.content).not.toContain("Holidays");
        expect(atob(sealed.content)).not.toContain("Holidays");

        const opened = await openRecord(sealed, driveKey);
        expect(opened.value).toEqual(value);
        expect(opened.fileKey).toEqual(fileKey);
        await expect(openRecord(sealed, randomBytes(16))).rejects.toThrow();
    });

    test("every record gets its own key unless one is given", async () => {
        const driveKey = randomBytes(16);
        const a = await sealRecord({}, driveKey);
        const b = await sealRecord({}, driveKey);
        expect(toBase64(a.fileKey.aesKey)).not.toBe(toBase64(b.fileKey.aesKey));
        const c = await sealRecord({}, driveKey, a.fileKey);
        expect(c.fileKey).toBe(a.fileKey);
    });

    test("a header Odin gives back with a numeric type opens", async () => {
        const header = { ...v.header, type: 13 };
        expect(
            (await openFileKey(header, fromBase64(v.driveKey))).aesKey,
        ).toEqual(fromBase64(v.aesKey));
        await expect(
            openFileKey({ ...v.header, type: "aes" }, fromBase64(v.driveKey)),
        ).rejects.toThrow();
    });

    test("a file key round-trips through the string Ente keeps", () => {
        const fileKey = newFileKey();
        expect(fileKeyFromString(fileKeyToString(fileKey))).toEqual(fileKey);
        expect(() => fileKeyFromString(toBase64(randomBytes(16)))).toThrow();
    });
});
