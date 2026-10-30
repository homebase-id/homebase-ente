// The proxy (homebase-id/ente-homebase-proxy) keeps the same values in its
// contract/ente-homebase.json; change both together (its CONTRACT.md).
//
// Ente Photos' own Homebase app registration and the fixed ids of what it
// keeps on its drive. The ids were generated once; never change them (the slug
// is immutable once an identity has registered the app, and the drive and
// password file are found by these ids on every device).

import type { AppRegistration } from "./youauth";

/** The zero-knowledge drive Ente Photos asks for. */
export const enteDrive = {
    alias: "0ada68d639fd7c0c7f35e46d80665c0c",
    type: "762e8336095125323b9d7c0913f3ac7c",
    name: "Ente Photos",
    description: "Photos and keys stored by Ente Photos",
    permission: 3,
    driveSlug: "photos",
    driveTypeSlug: "ente-photos",
    sharingModel: "private",
} as const;

export const enteApp: Omit<AppRegistration, "clientFriendlyName"> = {
    appId: "4d8d9eed-ad53-42d7-a125-323c69f619b1",
    appName: "Ente Photos",
    appSlug: "ente-photos",
    drives: [enteDrive],
};

/** The file on {@link enteDrive} that holds the generated Ente password. */
export const passwordFile = {
    uniqueId: "c7a886cd-326a-41db-9922-e92828ed02ec",
    /** Ente's own range; Immich uses 7100–7102. */
    fileType: 7200,
} as const;

/**
 * The file on {@link enteDrive} that holds Ente's key attributes (the master
 * key, locked with the Ente password). Written and read by the proxy for
 * PUT /users/attributes and GET /users/session-validity/v2.
 */
export const keyAttributesFile = {
    uniqueId: "d269c173-71a3-4fe4-8ee4-8d4da5c929e7",
    fileType: 7201,
} as const;

/** Where YouAuth sends the browser back to, relative to the app's origin. */
export const homebaseCallbackPath = "/homebase/callback";
