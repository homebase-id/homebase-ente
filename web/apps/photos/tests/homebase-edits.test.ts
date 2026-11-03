import type { Collection } from "ente-media/collection";
import type { EnteFile } from "ente-media/file";
import { updateCollectionSortOrder } from "ente-new/photos/services/collection";
import { updateFileCaption } from "ente-new/photos/services/file";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

// In Homebase mode an edit seals the record again, with the same key: the
// proxy can't open it, so it stores what the browser sends.
const driveKey = new Uint8Array(32).fill(7);

vi.mock("ente-homebase", async (importOriginal) => ({
    ...(await importOriginal<typeof import("ente-homebase")>()),
    homebaseDriveKey: () => Promise.resolve(driveKey),
}));
vi.mock("ente-base/http", async (importOriginal) => ({
    ...(await importOriginal<typeof import("ente-base/http")>()),
    authenticatedRequestHeaders: () => Promise.resolve({}),
}));
vi.mock("ente-base/origins", () => ({
    apiURL: (path: string) => Promise.resolve(`https://example.invalid${path}`),
    isHomebaseMode: () => Promise.resolve(true),
}));

const { openRecord, sealRecord } = await import("ente-homebase");

const fetchMock = vi.fn();
beforeEach(() => {
    vi.stubGlobal("fetch", fetchMock);
    fetchMock.mockResolvedValue(new Response(null, { status: 200 }));
});
afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
});

const sent = () => {
    const [url, request] = fetchMock.mock.calls[0]! as [string, RequestInit];
    return { url, body: JSON.parse(request.body as string) as unknown };
};

test("an album setting seals the album's details again, the rest as they were", async () => {
    const details = {
        type: "album",
        name: "Trip",
        pubMagicMetadata: { version: 3, count: 1, data: { coverID: 2 } },
        futureField: "kept",
    };
    const { sealed, fileKey } = await sealRecord(details, driveKey);
    const collection = {
        id: 10,
        homebase: sealed,
        pubMagicMetadata: details.pubMagicMetadata,
    } as unknown as Collection;

    await updateCollectionSortOrder(collection, true, "fileName");

    const { url, body } = sent();
    expect(url).toBe(
        "https://example.invalid/collections/public-magic-metadata",
    );
    const { id, homebase } = body as { id: number; homebase: typeof sealed };
    expect(id).toBe(10);
    const opened = await openRecord(homebase, driveKey);
    expect(opened.fileKey.aesKey).toEqual(fileKey.aesKey);
    expect(opened.fileKey.iv).not.toEqual(fileKey.iv);
    expect(opened.value).toEqual({
        ...details,
        pubMagicMetadata: {
            version: 4,
            count: 3,
            data: { coverID: 2, asc: true, sortBy: "fileName" },
        },
    });
});

test("a caption seals each photo's details again, with its own key", async () => {
    const details = {
        metadata: { title: "a.jpg", fileType: 0, creationTime: 1 },
        magicMetadata: { version: 1, count: 1, data: { visibility: 1 } },
    };
    const { sealed, fileKey } = await sealRecord(details, driveKey);
    const file = {
        id: 5,
        homebase: sealed,
        magicMetadata: details.magicMetadata,
    } as unknown as EnteFile;

    await updateFileCaption(file, "Sunset");

    const { url, body } = sent();
    expect(url).toBe("https://example.invalid/files/public-magic-metadata");
    const [item] = (
        body as { metadataList: { id: number; homebase: typeof sealed }[] }
    ).metadataList;
    expect(item!.id).toBe(5);
    const opened = await openRecord(item!.homebase, driveKey);
    expect(opened.fileKey.aesKey).toEqual(fileKey.aesKey);
    expect(opened.value).toEqual({
        ...details,
        pubMagicMetadata: { version: 1, count: 1, data: { caption: "Sunset" } },
    });
});
