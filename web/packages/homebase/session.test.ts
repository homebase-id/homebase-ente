// Signing in, the password on the drive, and the stored credentials, against an
// in-memory identity (fake-identity.ts). Random test keys only.

import { describe, expect, test } from "vitest";
import { passwordFile } from "./constants";
import { FakeIdentity } from "./fake-identity";
import { ensureEntePassword, passwordFingerprint } from "./password";
import {
    finishHomebaseSignIn,
    hasHomebaseSignIn,
    openSavedHomebaseDrive,
    signOutOfHomebase,
    startHomebaseSignIn,
} from "./session";
import { type CredentialsStore, loadCredentials } from "./store";
import { YouAuthError } from "./youauth";

const memoryStore = (): CredentialsStore & { map: Map<string, unknown> } => {
    const map = new Map<string, unknown>();
    return {
        map,
        get: (key) => Promise.resolve(map.get(key)),
        set: (key, value) => Promise.resolve(void map.set(key, value)),
        delete: (key) => Promise.resolve(void map.delete(key)),
    };
};

const memoryStorage = () => {
    const map = new Map<string, string>();
    return {
        map,
        getItem: (key: string) => map.get(key) ?? null,
        setItem: (key: string, value: string) => void map.set(key, value),
        removeItem: (key: string) => void map.delete(key),
    };
};

const origin = "http://localhost:3020";

/** A whole sign-in: start, the owner approves, the callback finishes it. */
const signIn = async (identity: FakeIdentity, store = memoryStore()) => {
    const pending = memoryStorage();
    const url = await startHomebaseSignIn(identity.identity, origin, pending);
    const callback = await identity.approve(url);
    await finishHomebaseSignIn(callback, pending, store, identity.fetch);
    return { store, pending };
};

const kindOf = async (promise: Promise<unknown>) => {
    try {
        await promise;
    } catch (e) {
        if (e instanceof YouAuthError) return e.kind;
        throw e;
    }
    throw new Error("Expected a YouAuthError");
};

describe("sign-in", () => {
    test("asks for Ente's app and drive, and comes back to the callback", async () => {
        const url = new URL(
            await startHomebaseSignIn(
                "Frodo.Example.Test",
                origin,
                memoryStorage(),
            ),
        );
        expect(url.host).toBe("frodo.example.test");
        expect(url.pathname).toBe("/api/owner/v1/youauth/authorize");
        expect(url.searchParams.get("client_id")).toBe(
            "4d8d9eed-ad53-42d7-a125-323c69f619b1",
        );
        expect(url.searchParams.get("redirect_uri")).toBe(
            `${origin}/homebase/callback`,
        );
        expect(url.searchParams.get("zk_app_key")).toBe("1");
        const request = JSON.parse(
            url.searchParams.get("permission_request")!,
        ) as { as: string; d: string };
        expect(request.as).toBe("ente-photos");
        expect(JSON.parse(request.d)).toMatchObject([
            { a: "0ada68d639fd7c0c7f35e46d80665c0c", sm: "private", p: 3 },
        ]);
    });

    test("a good callback saves the credentials and forgets the pending sign-in", async () => {
        const identity = new FakeIdentity();
        const { store, pending } = await signIn(identity);
        expect(pending.map.size).toBe(0);
        const saved = await loadCredentials(store);
        expect(saved?.identity).toBe(identity.identity);
        expect(saved?.clientAuthToken).toEqual(identity.clientAuthToken);
        expect(saved?.sharedSecret).toEqual(identity.sharedSecret);
        expect(saved?.appZkKey).toEqual(identity.appZkKey);
        // Sealed: nothing in the store is the credentials in the clear.
        expect(JSON.stringify([...store.map.values()])).not.toContain(
            identity.identity,
        );
    });

    test("a callback with another state is refused, and nothing is saved", async () => {
        const identity = new FakeIdentity();
        const pending = memoryStorage();
        const store = memoryStore();
        const url = await startHomebaseSignIn(
            identity.identity,
            origin,
            pending,
        );
        const callback = await identity.approve(url);
        callback.set("state", "someone-elses");
        expect(
            await kindOf(
                finishHomebaseSignIn(callback, pending, store, identity.fetch),
            ),
        ).toBe("state-mismatch");
        expect(pending.map.size).toBe(0);
        expect(await hasHomebaseSignIn(store)).toBe(false);
    });

    test("a callback without a pending sign-in is refused", async () => {
        const identity = new FakeIdentity();
        expect(
            await kindOf(
                finishHomebaseSignIn(
                    new URLSearchParams({ state: "x" }),
                    memoryStorage(),
                    memoryStore(),
                    identity.fetch,
                ),
            ),
        ).toBe("state-mismatch");
    });

    test("the owner saying no is reported as denied", async () => {
        const identity = new FakeIdentity();
        const pending = memoryStorage();
        await startHomebaseSignIn(identity.identity, origin, pending);
        expect(
            await kindOf(
                finishHomebaseSignIn(
                    new URLSearchParams({ error: "cancelled-by-user" }),
                    pending,
                    memoryStore(),
                    identity.fetch,
                ),
            ),
        ).toBe("denied");
        expect(pending.map.size).toBe(0);
    });

    test("a grant without Ente's drive fails the sign-in", async () => {
        const identity = new FakeIdentity();
        identity.driveAlias = "94dddf651c17f92ad503646208125058";
        const store = memoryStore();
        await expect(signIn(identity, store)).rejects.toBeInstanceOf(
            YouAuthError,
        );
        expect(await hasHomebaseSignIn(store)).toBe(false);
    });

    test("a revoked app is reported as unauthorized", async () => {
        const identity = new FakeIdentity();
        const { store } = await signIn(identity);
        identity.contextStatus = 401;
        expect(
            await kindOf(openSavedHomebaseDrive(store, identity.fetch)),
        ).toBe("unauthorized");
    });

    test("signing out forgets the credentials and the sealing key", async () => {
        const identity = new FakeIdentity();
        const { store } = await signIn(identity);
        expect(await hasHomebaseSignIn(store)).toBe(true);
        await signOutOfHomebase(store);
        expect(await hasHomebaseSignIn(store)).toBe(false);
        expect(store.map.size).toBe(0);
        expect(await openSavedHomebaseDrive(store, identity.fetch)).toBe(
            undefined,
        );
    });
});

describe("password", () => {
    const openDrive = async (identity: FakeIdentity) => {
        const { store } = await signIn(identity);
        return (await openSavedHomebaseDrive(store, identity.fetch))!;
    };

    test("the first sign-in creates it on the drive, encrypted", async () => {
        const identity = new FakeIdentity();
        const result = await ensureEntePassword(await openDrive(identity));
        expect(result.created).toBe(true);
        expect(result.password).toMatch(/^[A-Za-z0-9_-]{43}$/);
        const stored = identity.files.get(passwordFile.uniqueId)!;
        expect(stored.header.fileMetadata.appData.fileType).toBe(7200);
        expect(stored.header.fileMetadata.appData.content).not.toContain(
            result.password,
        );
    });

    test("a later sign-in finds the same one", async () => {
        const identity = new FakeIdentity();
        const first = await ensureEntePassword(await openDrive(identity));
        const second = await ensureEntePassword(await openDrive(identity));
        expect(second).toEqual({ password: first.password, created: false });
        expect(await passwordFingerprint(second.password)).toBe(
            await passwordFingerprint(first.password),
        );
    });

    test("losing the race to create it reads the winner's, not overwriting it", async () => {
        const identity = new FakeIdentity();
        const winnerDrive = await openDrive(identity);
        const loserDrive = await openDrive(identity);
        let winner: string | undefined;
        identity.beforeCreate = async () => {
            identity.beforeCreate = undefined;
            winner = (await ensureEntePassword(winnerDrive)).password;
        };
        const loser = await ensureEntePassword(loserDrive);
        expect(loser).toEqual({ password: winner, created: false });
        expect(identity.files.size).toBe(1);
    });

    test("the fingerprint is 8 hex digits of the SHA-256", async () => {
        // SHA-256("abc") = ba7816bf…
        expect(await passwordFingerprint("abc")).toBe("ba7816bf");
    });
});
