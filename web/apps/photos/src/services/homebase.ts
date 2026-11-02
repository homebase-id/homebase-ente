// Signing in to Ente Photos with Homebase (web/packages/homebase): the
// browser's credentials store, and a message for each way a sign-in fails.

import {
    type CredentialsStore,
    HomebaseHttpError,
    indexedDBCredentialsStore,
    YouAuthError,
} from "ente-homebase";
import { t } from "i18next";

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
