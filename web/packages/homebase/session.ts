// Signing in to Ente Photos with Homebase from a browser: start YouAuth, finish
// it on the callback page, and open the app's drive with what it left.

import { enteApp, enteDrive, homebaseCallbackPath } from "./constants";
import { getSecurityContext, openDriveKey } from "./context";
import { HomebaseDrive } from "./drive";
import {
    clearCredentials,
    type CredentialsStore,
    loadCredentials,
    saveCredentials,
} from "./store";
import {
    completeSignIn,
    createAuthorizeRequest,
    type PendingSignIn,
    type YouAuthCredentials,
    YouAuthError,
} from "./youauth";

/** sessionStorage key of the sign-in in progress (until the callback). */
const pendingKey = "ente-homebase-pending";

/** What the identity shows the owner as the device asking. */
const clientFriendlyName = (userAgent: string) =>
    `Ente Photos web (${userAgent.includes("Mac") ? "Mac" : userAgent.includes("Windows") ? "Windows" : "browser"})`;

/**
 * Starts a sign-in: keeps the pending sign-in in {@link pendingStorage} and
 * returns the identity's authorize URL to send the browser to.
 */
export const startHomebaseSignIn = async (
    identity: string,
    origin: string,
    pendingStorage: Pick<Storage, "setItem">,
    userAgent = "",
) => {
    const { url, pending } = await createAuthorizeRequest(
        identity,
        { ...enteApp, clientFriendlyName: clientFriendlyName(userAgent) },
        `${origin}${homebaseCallbackPath}`,
    );
    pendingStorage.setItem(pendingKey, JSON.stringify(pending));
    return url;
};

/** The app's drive, opened with the drive key from the security context. */
export const openHomebaseDrive = async (
    credentials: YouAuthCredentials,
    fetchImpl: typeof fetch = (...args) => fetch(...args),
) => {
    const context = await getSecurityContext(credentials, fetchImpl);
    const driveKey = await openDriveKey(
        context,
        enteDrive.alias,
        credentials.appZkKey,
    );
    return new HomebaseDrive(
        { ...credentials, driveAlias: enteDrive.alias, driveKey },
        fetchImpl,
    );
};

/**
 * Finishes a sign-in from the callback's query. It counts only once the
 * drive key opens; then the credentials are saved. The pending sign-in is
 * deleted whether or not it worked.
 */
export const finishHomebaseSignIn = async (
    callback: URLSearchParams,
    pendingStorage: Pick<Storage, "getItem" | "removeItem">,
    store: CredentialsStore,
    fetchImpl: typeof fetch = (...args) => fetch(...args),
) => {
    const json = pendingStorage.getItem(pendingKey);
    pendingStorage.removeItem(pendingKey);
    if (!json) {
        throw new YouAuthError(
            "state-mismatch",
            "This sign-in wasn't started in this browser tab",
        );
    }
    const pending = JSON.parse(json) as PendingSignIn;
    const credentials = await completeSignIn(pending, callback, fetchImpl);
    await openHomebaseDrive(credentials, fetchImpl);
    await saveCredentials(store, credentials);
    return credentials.identity;
};

/** The drive of the signed-in identity, or `undefined` if not signed in. */
export const openSavedHomebaseDrive = async (
    store: CredentialsStore,
    fetchImpl: typeof fetch = (...args) => fetch(...args),
) => {
    const credentials = await loadCredentials(store);
    return credentials && openHomebaseDrive(credentials, fetchImpl);
};

export const hasHomebaseSignIn = async (store: CredentialsStore) =>
    !!(await loadCredentials(store));

/** Signs out: forgets the credentials (the drive and its files stay). */
export const signOutOfHomebase = (store: CredentialsStore) =>
    clearCredentials(store);
