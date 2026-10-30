// Where a browser keeps its Homebase sign-in. The credentials are sealed with
// AES-GCM under a non-extractable key that lives next to them in IndexedDB:
// script can use the key but not read it, so the stored bytes are useless
// anywhere else. Never localStorage, cookies or URLs.

import { openDB } from "idb";
import {
    type Bytes,
    fromBase64,
    fromUtf8,
    randomBytes,
    toBase64,
    utf8,
} from "./bytes";
import type { YouAuthCredentials } from "./youauth";

/** Enough of a key-value store to keep the sealed credentials in. */
export interface CredentialsStore {
    get: (key: string) => Promise<unknown>;
    set: (key: string, value: unknown) => Promise<void>;
    delete: (key: string) => Promise<void>;
}

/** The browser's store: its own IndexedDB database, one object store. */
export const indexedDBCredentialsStore = (): CredentialsStore => {
    const db = openDB("ente-homebase", 1, {
        upgrade: (db) => void db.createObjectStore("kv"),
    });
    return {
        get: async (key): Promise<unknown> =>
            (await db).get("kv", key) as Promise<unknown>,
        set: async (key, value) =>
            void (await (await db).put("kv", value, key)),
        delete: async (key) => (await db).delete("kv", key),
    };
};

interface StoredCredentials {
    identity: string;
    clientAuthToken: string;
    sharedSecret: string;
    appZkKey: string;
}

interface Sealed {
    iv: Bytes;
    sealed: ArrayBuffer;
}

const sealingKeyName = "sealingKey";
const credentialsName = "credentials";

const sealingKey = async (store: CredentialsStore) => {
    const existing = (await store.get(sealingKeyName)) as CryptoKey | undefined;
    if (existing) return existing;
    const key = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        false,
        ["encrypt", "decrypt"],
    );
    await store.set(sealingKeyName, key);
    return key;
};

export const saveCredentials = async (
    store: CredentialsStore,
    credentials: YouAuthCredentials,
) => {
    const stored: StoredCredentials = {
        identity: credentials.identity,
        clientAuthToken: toBase64(credentials.clientAuthToken),
        sharedSecret: toBase64(credentials.sharedSecret),
        appZkKey: toBase64(credentials.appZkKey),
    };
    const iv = randomBytes(12);
    const sealed = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv },
        await sealingKey(store),
        utf8(JSON.stringify(stored)),
    );
    await store.set(credentialsName, { iv, sealed } satisfies Sealed);
};

/** The saved credentials, or `undefined` if this browser isn't signed in. */
export const loadCredentials = async (
    store: CredentialsStore,
): Promise<YouAuthCredentials | undefined> => {
    const sealed = (await store.get(credentialsName)) as Sealed | undefined;
    const key = (await store.get(sealingKeyName)) as CryptoKey | undefined;
    if (!sealed || !key) return undefined;
    const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: sealed.iv },
        key,
        sealed.sealed,
    );
    const stored = JSON.parse(
        fromUtf8(new Uint8Array(plain)),
    ) as StoredCredentials;
    return {
        identity: stored.identity,
        clientAuthToken: fromBase64(stored.clientAuthToken),
        sharedSecret: fromBase64(stored.sharedSecret),
        appZkKey: fromBase64(stored.appZkKey),
    };
};

/** Forgets the sign-in, and the key that sealed it. */
export const clearCredentials = async (store: CredentialsStore) => {
    await store.delete(credentialsName);
    await store.delete(sealingKeyName);
};
