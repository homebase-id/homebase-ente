// Signing in to Ente Photos with Homebase (web/packages/homebase): the
// browser's credentials store, and a message for each way a sign-in fails.

import {
    replaceSavedLocalUser,
    saveKeyAttributes,
    saveOriginalKeyAttributes,
} from "ente-accounts/services/accounts-db";
import { decryptBox, deriveKey } from "ente-accounts/services/crypto";
import { saveMasterKeyInSessionAndSafeStore } from "ente-accounts/services/prelogin-session";
import {
    generateAndSaveInteractiveKeyAttributes,
    generateSignupKeys,
    type KeyAttributes,
    RemoteKeyAttributes,
} from "ente-accounts/services/user";
import { authenticatedRequestHeaders, ensureOk } from "ente-base/http";
import { setKV } from "ente-base/kv";
import { apiURL } from "ente-base/origins";
import { saveAuthToken } from "ente-base/token";
import {
    type CredentialsStore,
    enteEmail,
    enteUserID,
    type HomebaseDrive,
    HomebaseHttpError,
    indexedDBCredentialsStore,
    xAuthToken,
    YouAuthError,
} from "ente-homebase";
import { t } from "i18next";
import { z } from "zod";

/**
 * The Ente → Homebase proxy (homebase-id/ente-homebase-proxy) that stands in for Ente's
 * server when signed in with Homebase.
 */
export const homebaseProxyOrigin =
    process.env.NEXT_PUBLIC_ENTE_HOMEBASE_PROXY ?? "http://localhost:8095";

let _store: CredentialsStore | undefined;

/** Where this browser keeps its Homebase sign-in (sealed, in IndexedDB). */
export const homebaseStore = () => (_store ??= indexedDBCredentialsStore());

/**
 * What to log about a failure: its kind and HTTP status, never the error
 * itself, since a failing call's context could hold a secret.
 */
export const homebaseFailureLabel = (e: unknown) => {
    if (e instanceof YouAuthError) return `YouAuthError(${e.kind})`;
    if (e instanceof HomebaseHttpError) return `HTTP ${e.status}`;
    return e instanceof Error ? e.name : "unknown error";
};

/** What to tell the user about a failed sign-in or Homebase call. */
export const homebaseErrorMessage = (e: unknown) => {
    if (!(e instanceof YouAuthError)) return t("generic_error");
    switch (e.kind) {
        case "denied":
            return t("homebase_error_denied");
        case "revoked":
            return t("homebase_error_revoked");
        case "state-mismatch":
            return t("homebase_error_state_mismatch");
        case "exchange-failed":
            return t("homebase_error_exchange_failed");
        case "no-zero-knowledge":
            return t("homebase_error_no_zero_knowledge");
        case "unauthorized":
            return t("homebase_error_unauthorized");
        case "other":
            return t("generic_error");
    }
};

const SessionValidity = z.object({
    hasSetKeys: z.boolean(),
    keyAttributes: RemoteKeyAttributes.nullish(),
});

const fetchKeyAttributes = async () => {
    const res = await fetch(await apiURL("/users/session-validity/v2"), {
        headers: await authenticatedRequestHeaders(),
    });
    ensureOk(res);
    const { hasSetKeys, keyAttributes } = SessionValidity.parse(
        await res.json(),
    );
    return hasSetKeys && keyAttributes ? keyAttributes : undefined;
};

/** PUT /users/attributes; false if another device set them first (403). */
const putKeyAttributes = async (keyAttributes: KeyAttributes) => {
    const res = await fetch(await apiURL("/users/attributes"), {
        method: "PUT",
        headers: {
            ...(await authenticatedRequestHeaders()),
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ keyAttributes }),
    });
    if (res.status == 403) return false;
    ensureOk(res);
    return true;
};

const unlockMasterKey = async (
    password: string,
    keyAttributes: KeyAttributes,
) =>
    decryptBox(
        {
            encryptedData: keyAttributes.encryptedKey,
            nonce: keyAttributes.keyDecryptionNonce,
        },
        await deriveKey(
            password,
            keyAttributes.kekSalt,
            keyAttributes.opsLimit,
            keyAttributes.memLimit,
        ),
    );

/**
 * Logs in to Ente Photos with a Homebase sign-in and its hidden Ente password:
 * Ente's API goes to the proxy, and Ente's keys are set up (first time) or
 * unlocked with the password, as Ente's own sign-up and login pages would.
 * Afterwards the app is logged in as usual and can go to the gallery.
 *
 * Prototype: Ente keeps its auth token unencrypted in localStorage and
 * IndexedDB, and here that token is the X-Auth-Token, which holds the drive
 * key.
 */
export const logInToEnte = async (drive: HomebaseDrive, password: string) => {
    const { identity } = drive.session;
    const token = xAuthToken(drive.session);
    await setKV("apiOrigin", homebaseProxyOrigin);
    // Credentials only in headers, single-part uploads (ente-base isHomebaseMode).
    await setKV("homebase", "1");
    await saveAuthToken(token);
    replaceSavedLocalUser({
        id: await enteUserID(identity),
        email: enteEmail(identity),
        token,
    });

    let keyAttributes = await fetchKeyAttributes();
    let masterKey: string;
    if (keyAttributes) {
        masterKey = await unlockMasterKey(password, keyAttributes);
    } else {
        const generated = await generateSignupKeys(password);
        if (await putKeyAttributes(generated.keyAttributes)) {
            ({ keyAttributes, masterKey } = generated);
        } else {
            // Another device set up Ente first: use its keys.
            keyAttributes = await fetchKeyAttributes();
            if (!keyAttributes) throw new Error("Key attributes went missing");
            masterKey = await unlockMasterKey(password, keyAttributes);
        }
    }

    saveOriginalKeyAttributes(keyAttributes);
    saveKeyAttributes(keyAttributes);
    await generateAndSaveInteractiveKeyAttributes(
        password,
        keyAttributes,
        masterKey,
    );
    await saveMasterKeyInSessionAndSafeStore(masterKey);
};
