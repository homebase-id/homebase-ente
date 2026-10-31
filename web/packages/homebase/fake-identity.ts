// Tests only: an in-memory Homebase identity that answers the calls a sign-in
// makes (the YouAuth token exchange, the security context) and a drive's file
// create, read by uniqueId and query. It plays odin-core's side of each byte
// format, so the client code is checked against an independent encoder.

import {
    type Bytes,
    fromBase64,
    fromUtf8,
    randomBytes,
    toBase64,
    utf8,
} from "./bytes";
import { enteDrive } from "./constants";
import { decryptEnvelope, encryptEnvelope } from "./context";
import {
    aesCbcDecrypt,
    aesGcmEncrypt,
    generateP384KeyPair,
    makeZkLock,
    publicKeyFromJwkJson,
    publicKeyToJwkJson,
    sha256,
    zkSeal,
} from "./crypto";
import type { FileHeader } from "./drive";
import { exchangeSecret } from "./youauth";

interface StoredFile {
    header: FileHeader;
}

export class FakeIdentity {
    readonly identity = "frodo.example.test";
    readonly clientAuthToken = randomBytes(33);
    readonly sharedSecret = randomBytes(16);
    readonly appZkKey = randomBytes(16);
    readonly driveKey = randomBytes(16);
    readonly files = new Map<string, StoredFile>();
    /** The drive alias the security context grants (the Ente drive). */
    driveAlias: string = enteDrive.alias;
    /** Runs just before a create is stored (to stage a race). */
    beforeCreate: (() => Promise<void>) | undefined;
    /** The security context's status (401 to act revoked). */
    contextStatus = 200;
    private exchange:
        { digest: string; secret: Bytes; clientKey: CryptoKey } | undefined;

    /** The callback query the identity sends back for an authorize URL. */
    async approve(authorizeURL: string): Promise<URLSearchParams> {
        const url = new URL(authorizeURL);
        const clientKey = await publicKeyFromJwkJson(
            fromUtf8(fromBase64(url.searchParams.get("public_key")!)),
        );
        const server = await generateP384KeyPair();
        const salt = randomBytes(16);
        const serverPublic = toBase64(
            utf8(await publicKeyToJwkJson(server.publicKey)),
        );
        // The client derives the same secret from its private key and ours.
        const ours = await crypto.subtle.exportKey("jwk", clientKey);
        const secret = await exchangeSecret(
            server.privateKey,
            toBase64(utf8(JSON.stringify(ours))),
            toBase64(salt),
        );
        this.exchange = {
            digest: toBase64(await sha256(secret)),
            secret,
            clientKey,
        };
        return new URLSearchParams({
            state: url.searchParams.get("state")!,
            public_key: serverPublic,
            salt: toBase64(salt),
        });
    }

    private async tokenResponse(body: { secret_digest: string }) {
        const exchange = this.exchange;
        this.exchange = undefined;
        if (body.secret_digest != exchange?.digest) {
            return json(403, {});
        }
        const field = async (value: Bytes) => {
            const iv = randomBytes(16);
            return {
                iv: toBase64(iv),
                cipher: toBase64(
                    await aesGcmEncrypt(
                        exchange.secret,
                        iv.slice(0, 12),
                        value,
                    ),
                ),
            };
        };
        const ss = await field(this.sharedSecret);
        const token = await field(this.clientAuthToken);
        return json(200, {
            base64SharedSecretCipher: ss.cipher,
            base64SharedSecretIv: ss.iv,
            base64ClientAuthTokenCipher: token.cipher,
            base64ClientAuthTokenIv: token.iv,
            cipher: "aes-gcm",
            zkAppKey: toBase64(await zkSeal(this.appZkKey, exchange.clientKey)),
        });
    }

    private async envelope(status: number, value: unknown) {
        return json(
            status,
            await encryptEnvelope(this.sharedSecret, JSON.stringify(value)),
        );
    }

    private authorized(init: RequestInit | undefined) {
        const headers = (init?.headers ?? {}) as Record<string, string>;
        return (
            headers.authorization == `Bearer ${toBase64(this.clientAuthToken)}`
        );
    }

    private async create(body: Blob) {
        const parts = parseMultipart(new Uint8Array(await body.arrayBuffer()));
        const instructions = JSON.parse(
            fromUtf8(parts.get("instructions")!),
        ) as { transferIv: string };
        const descriptor = JSON.parse(
            fromUtf8(
                await aesCbcDecrypt(
                    this.sharedSecret,
                    fromBase64(instructions.transferIv),
                    parts.get("metadata")!,
                ),
            ),
        ) as {
            encryptedKeyHeader: FileHeader["sharedSecretEncryptedKeyHeader"];
            fileMetadata: { appData: FileHeader["fileMetadata"]["appData"] };
        };
        await this.beforeCreate?.();
        const uid = descriptor.fileMetadata.appData.uniqueId!;
        if (this.files.has(uid)) {
            return json(400, { errorCode: "existingFileWithUniqueId" });
        }
        const fileId = crypto.randomUUID();
        this.files.set(uid, {
            header: {
                fileId,
                sharedSecretEncryptedKeyHeader: descriptor.encryptedKeyHeader,
                fileMetadata: {
                    versionTag: crypto.randomUUID(),
                    appData: descriptor.fileMetadata.appData,
                },
            },
        });
        return json(200, { fileId, newVersionTag: crypto.randomUUID() });
    }

    /** A `fetch` that answers as this identity. */
    readonly fetch: typeof fetch = async (input, init) => {
        const url = new URL(
            typeof input == "string" || input instanceof URL
                ? input
                : input.url,
        );
        if (url.host != this.identity) throw new Error(`Unexpected ${url}`);
        const path = url.pathname;
        const method = init?.method ?? "GET";

        if (path == "/api/owner/v1/youauth/token" && method == "POST") {
            return this.tokenResponse(
                JSON.parse(init!.body as string) as { secret_digest: string },
            );
        }
        if (!this.authorized(init)) return json(401, {});

        if (path == "/api/v2/auth/context") {
            if (this.contextStatus != 200) return json(this.contextStatus, {});
            return this.envelope(200, {
                caller: { odinId: this.identity },
                permissionContext: {
                    permissionGroups: [
                        {
                            driveGrants: [
                                {
                                    permissionedDrive: {
                                        drive: { alias: this.driveAlias },
                                    },
                                    zkAppKeyEncryptedStorageKey: toBase64(
                                        await makeZkLock(
                                            this.appZkKey,
                                            this.driveKey,
                                        ),
                                    ),
                                },
                            ],
                        },
                    ],
                },
            });
        }

        const files = /^\/api\/v2\/drives\/([0-9a-f-]+)\/files(\/.*)?$/.exec(
            path,
        );
        if (files) {
            const rest = files[2] ?? "";
            if (rest == "" && method == "POST") {
                return this.create(init!.body as Blob);
            }
            const byUid = /^\/by-uid\/([0-9a-f-]+)\/header$/.exec(rest);
            if (byUid) {
                const file = this.files.get(byUid[1]!);
                return file ? this.envelope(200, file.header) : json(404, {});
            }
            if (rest == "/query-batch" && method == "POST") {
                const query = JSON.parse(
                    fromUtf8(
                        await decryptEnvelope(
                            this.sharedSecret,
                            JSON.parse(init!.body as string) as {
                                iv: string;
                                data: string;
                            },
                        ),
                    ),
                ) as { queryParams: { tagsMatchAtLeastOne: string[] } };
                const tags = query.queryParams.tagsMatchAtLeastOne;
                return this.envelope(200, {
                    searchResults: [...this.files.values()]
                        .map((f) => f.header)
                        .filter((h) =>
                            h.fileMetadata.appData.tags?.some((t) =>
                                tags.includes(t),
                            ),
                        ),
                });
            }
        }
        return json(404, {});
    };
}

const json = (status: number, value: unknown) =>
    new Response(JSON.stringify(value), {
        status,
        headers: { "content-type": "application/json" },
    });

const indexOf = (haystack: Uint8Array, needle: Uint8Array, from: number) => {
    outer: for (let i = from; i <= haystack.length - needle.length; i++) {
        for (let j = 0; j < needle.length; j++) {
            if (haystack[i + j] != needle[j]) continue outer;
        }
        return i;
    }
    return -1;
};

/**
 * The parts of a multipart/form-data body by name, as bytes (FormData would
 * turn parts without a filename into text, and the metadata part is binary).
 */
const parseMultipart = (body: Uint8Array) => {
    const firstLineEnd = indexOf(body, utf8("\r\n"), 0);
    const delimiter = utf8(`\r\n${fromUtf8(body.slice(0, firstLineEnd))}`);
    const parts = new Map<string, Bytes>();
    let start = firstLineEnd + 2;
    for (;;) {
        const headersEnd = indexOf(body, utf8("\r\n\r\n"), start);
        const end = indexOf(body, delimiter, headersEnd);
        if (headersEnd < 0 || end < 0) break;
        const name = /name="([^"]+)"/.exec(
            fromUtf8(body.slice(start, headersEnd)),
        )?.[1];
        if (name) parts.set(name, body.slice(headersEnd + 4, end));
        start = end + delimiter.length + 2;
    }
    return parts;
};
