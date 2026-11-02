// Ente's records in Homebase mode (homebase-id/ente-homebase-proxy): there's no
// Ente encryption on them. Each is sealed by this app, the Homebase way
// (ente-homebase records.ts), and the proxy returns it as "homebase":
// {keyHeader, content}, which only this browser's drive key opens.

import { homebaseDriveKey, openRecord, type SealedRecord } from "ente-homebase";
import { z } from "zod";

export const RemoteHomebaseRecord = z.object({
    keyHeader: z.object({
        encryptionVersion: z.number(),
        type: z.union([z.string(), z.number()]),
        iv: z.string(),
        encryptedAesKey: z.string(),
    }),
    content: z.string(),
});

/** Ente's MagicMetadata as plain JSON, inside a sealed record. */
export const PlainMagicMetadata = z.object({
    version: z.number(),
    count: z.number(),
    data: z.unknown(),
});

/** A sealed record's JSON and key, opened with this browser's drive key. */
export const openHomebaseRecord = async (sealed: SealedRecord) =>
    openRecord(sealed, await homebaseDriveKey());
