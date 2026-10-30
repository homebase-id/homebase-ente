import { describe, expect, test } from "vitest";
import { fromBase64, fromUtf8 } from "./bytes";
import { enteEmail, enteUserID, xAuthToken } from "./ente";

describe("ente", () => {
    test("the user ID is the first 6 bytes of SHA-256(identity)", async () => {
        // The proxy's EnteIds.UserId must give the same number.
        expect(await enteUserID("frodo.baggins.demo.rocks")).toBe(
            256750248973160,
        );
        expect(Number.isSafeInteger(await enteUserID("x.example"))).toBe(true);
    });

    test("the X-Auth-Token carries the drive session, base64url", () => {
        const token = xAuthToken({
            identity: "frodo.example.test",
            clientAuthToken: new Uint8Array(33).fill(1),
            sharedSecret: new Uint8Array(16).fill(2),
            driveAlias: "0ada68d639fd7c0c7f35e46d80665c0c",
            driveKey: new Uint8Array(16).fill(3),
        });
        expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
        const decoded = JSON.parse(fromUtf8(fromBase64(token))) as Record<
            string,
            unknown
        >;
        expect(decoded).toMatchObject({ v: 1, identity: "frodo.example.test" });
        expect(fromBase64(decoded.dk as string)).toEqual(
            new Uint8Array(16).fill(3),
        );
    });

    test("the email is a placeholder under .invalid", () => {
        expect(enteEmail("frodo.example.test")).toBe(
            "frodo.example.test@homebase.invalid",
        );
    });
});
