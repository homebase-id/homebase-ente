/// <reference types="node" />
// The drive calls against a real identity. Skipped unless HOMEBASE_CREDENTIALS
// names a credentials file from a YouAuth consent (identity, clientAuthToken,
// sharedSecret, appZkKey, drive.alias). Never prints a value from it.
//
// Those credentials may belong to another app's drive, so every file made
// here is tagged and only tagged files of the test's fileType are deleted.

import { readFile } from "node:fs/promises";
import { afterAll, describe, expect, test } from "vitest";
import { fromBase64 } from "./bytes";
import { getSecurityContext, openDriveKey } from "./context";
import {
    type FileHeader,
    HomebaseDrive,
    isExistingUniqueIdError,
} from "./drive";

const credentialsPath = process.env.HOMEBASE_CREDENTIALS;

/** Marks this test's files, so cleanup touches nothing else. */
const testTag = "9ac6cac6-48a4-4c2c-a2a7-35af1869be39";
const testFileType = 7299;

const openDrive = async () => {
    const file = JSON.parse(await readFile(credentialsPath!, "utf8")) as {
        identity: string;
        clientAuthToken: string;
        sharedSecret: string;
        appZkKey: string;
        drive: { alias: string };
    };
    const credentials = {
        identity: file.identity,
        clientAuthToken: fromBase64(file.clientAuthToken),
        sharedSecret: fromBase64(file.sharedSecret),
    };
    const context = await getSecurityContext(credentials);
    const driveKey = await openDriveKey(
        context,
        file.drive.alias,
        fromBase64(file.appZkKey),
    );
    return new HomebaseDrive({
        ...credentials,
        driveAlias: file.drive.alias,
        driveKey,
    });
};

describe.skipIf(!credentialsPath)("drive (live)", () => {
    let drive: HomebaseDrive | undefined;
    const ensureDrive = async () => (drive ??= await openDrive());

    afterAll(async () => {
        if (!drive) return;
        const ours = (await drive.queryByTags([testTag])).filter(
            (h: FileHeader) =>
                h.fileMetadata.appData.fileType == testFileType &&
                h.fileMetadata.appData.tags?.includes(testTag),
        );
        if (ours.length) await drive.hardDelete(ours);
        expect(await drive.queryByTags([testTag])).toEqual([]);
    });

    test("create, read back by uniqueId, and refuse a second create", async () => {
        const drive = await ensureDrive();
        const uniqueId = crypto.randomUUID();
        const content = `ente-homebase live test ${crypto.randomUUID()}`;
        const file = {
            uniqueId,
            fileType: testFileType,
            tags: [testTag],
            content,
        };

        expect(await drive.getHeaderByUniqueId(uniqueId)).toBeUndefined();

        const { fileId } = await drive.createFile(file);
        const header = await drive.getHeaderByUniqueId(uniqueId);
        expect(header?.fileId).toBe(fileId);
        // Stored encrypted: Homebase holds ciphertext, the drive key opens it.
        expect(header?.fileMetadata.appData.content).not.toContain(content);
        expect(await drive.decryptContent(header!)).toBe(content);

        let refused: unknown;
        try {
            await drive.createFile({ ...file, content: "second" });
        } catch (e) {
            refused = e;
        }
        expect(isExistingUniqueIdError(refused)).toBe(true);
        expect(
            await drive.decryptContent(
                (await drive.getHeaderByUniqueId(uniqueId))!,
            ),
        ).toBe(content);
    }, 30_000);
});
