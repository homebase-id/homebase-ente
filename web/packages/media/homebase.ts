// Ente's records in Homebase mode (homebase-id/ente-homebase-proxy): there's no
// Ente encryption on them. Each is sealed by this app, the Homebase way
// (ente-homebase records.ts), and the proxy returns it as "homebase":
// {keyHeader, content}, which only this browser's drive key opens.

import {
    homebaseDriveKey,
    openRecord,
    resealRecord,
    type SealedRecord,
} from "ente-homebase";
import { z } from "zod";
import { createMagicMetadata } from "./magic-metadata";

export const RemoteHomebaseRecord = z.object({
    keyHeader: z.object({
        encryptionVersion: z.number(),
        type: z.union([z.string(), z.number()]),
        iv: z.string(),
        encryptedAesKey: z.string(),
    }),
    content: z.string(),
});

// Ente's MagicMetadata as plain JSON, inside a sealed record.
export const PlainMagicMetadata = z.object({
    version: z.number(),
    count: z.number(),
    data: z.unknown(),
});

// A sealed record's JSON and key, opened with this browser's drive key.
export const openHomebaseRecord = async (sealed: SealedRecord) =>
    openRecord(sealed, await homebaseDriveKey());

// A sealed record's details with some fields replaced, sealed again with its
// own key. The fields not named stay exactly as they were sealed.
export const resealHomebaseRecord = async (
    sealed: SealedRecord,
    fields: Record<string, unknown>,
) =>
    resealRecord(sealed, await homebaseDriveKey(), (value) => ({
        ...(value as Record<string, unknown>),
        ...fields,
    }));

// A sealed record with new magic metadata (`field`), sealed again. Ente's
// server raises the version on each update; here the browser does.
export const resealHomebaseMagicMetadata = (
    sealed: SealedRecord | undefined,
    field: "magicMetadata" | "pubMagicMetadata",
    data: unknown,
    version: number | undefined,
) => {
    if (!sealed) throw new Error("Not a Homebase record");
    return resealHomebaseRecord(sealed, {
        [field]: createMagicMetadata(data, (version ?? 0) + 1),
    });
};
