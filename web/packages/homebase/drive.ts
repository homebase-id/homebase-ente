// Small files on a zero-knowledge drive, through the V2 drive API: create one
// with encrypted content, read it back by its uniqueId, and delete it. Ported
// from the Immich Homebase client (packages/homebase-client/src/web/
// drive-client.ts and keys.ts), without payloads or thumbnails.
//
// A zkDrive file is encrypted with its own key (AES-128-CBC key and IV), and
// that file key is locked with the drive key in the file's key header
// (odin-core docs/zero-knowledge-drives.md). Homebase stores both but can open
// neither.

import {
    type Bytes,
    concat,
    fromBase64,
    fromUtf8,
    randomBytes,
    toBase64,
    toBase64Url,
    utf8,
} from "./bytes";
import {
    type AppCredentials,
    decryptEnvelope,
    encryptEnvelope,
    isEnvelope,
} from "./context";
import { aesCbcDecrypt, aesCbcEncrypt } from "./crypto";

/** A signed-in app's access to one of its zero-knowledge drives. */
export interface DriveSession extends AppCredentials {
    driveAlias: string;
    driveKey: Bytes;
}

interface FileKey {
    aesKey: Bytes;
    iv: Bytes;
}

interface EncryptedKeyHeader {
    encryptionVersion: number;
    type: string | number;
    iv: string;
    encryptedAesKey: string;
}

export interface FileHeader {
    fileId: string;
    sharedSecretEncryptedKeyHeader: EncryptedKeyHeader;
    fileMetadata: {
        versionTag: string;
        appData: {
            uniqueId?: string | null;
            fileType: number;
            tags?: string[] | null;
            content?: string | null;
        };
    };
}

export interface NewFile {
    uniqueId: string;
    fileType: number;
    tags?: string[];
    /** Encrypted with the file's key before it leaves the browser. */
    content: string;
}

export class HomebaseHttpError extends Error {
    constructor(
        message: string,
        readonly status: number,
        /** Odin's `errorCode`, as a name or a number. */
        readonly errorCode: string | number | undefined,
    ) {
        super(message);
        this.name = "HomebaseHttpError";
    }
}

/**
 * Whether a create was refused because a file with that uniqueId exists
 * (OdinClientErrorCode.ExistingFileWithUniqueId).
 */
export const isExistingUniqueIdError = (e: unknown) =>
    e instanceof HomebaseHttpError &&
    e.status == 400 &&
    (e.errorCode == "existingFileWithUniqueId" || e.errorCode == 4105);

/** "0ada68…" → "0ada68d6-39fd-7c0c-7f35-e46d80665c0c". */
export const toGuid = (value: string) => {
    const hex = value.replaceAll("-", "").toLowerCase();
    if (!/^[0-9a-f]{32}$/.test(hex)) throw new Error("Not a GUID");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
};

/** A zkDrive key header: AES-CBC(DrvK, file IV, IV ‖ AesKey), 48 bytes. */
const lockFileKey = async (
    fileKey: FileKey,
    driveKey: Bytes,
): Promise<EncryptedKeyHeader> => ({
    encryptionVersion: 1,
    type: "zkDrive",
    iv: toBase64(fileKey.iv),
    encryptedAesKey: toBase64(
        await aesCbcEncrypt(
            driveKey,
            fileKey.iv,
            concat(fileKey.iv, fileKey.aesKey),
        ),
    ),
});

const openFileKey = async (
    header: EncryptedKeyHeader,
    driveKey: Bytes,
): Promise<FileKey> => {
    if (header.type != "zkDrive" && header.type != 13) {
        throw new Error("Not a zkDrive key header");
    }
    const combined = await aesCbcDecrypt(
        driveKey,
        fromBase64(header.iv),
        fromBase64(header.encryptedAesKey),
    );
    if (combined.length != 32) {
        throw new Error("A zkDrive key header holds 32 bytes");
    }
    return { iv: combined.slice(0, 16), aesKey: combined.slice(16) };
};

export class HomebaseDrive {
    private readonly filesRoot: string;

    constructor(
        readonly session: DriveSession,
        private readonly fetchImpl: typeof fetch = (...args) => fetch(...args),
    ) {
        this.filesRoot = `https://${session.identity}/api/v2/drives/${toGuid(session.driveAlias)}/files`;
    }

    private async send(url: string, init: RequestInit = {}) {
        const response = await this.fetchImpl(url, {
            ...init,
            headers: {
                authorization: `Bearer ${toBase64(this.session.clientAuthToken)}`,
                ...(init.headers as Record<string, string> | undefined),
            },
        });
        if (!response.ok) {
            // Odin's problem details carry no secrets; keep them out of the
            // message anyway and only read the error code.
            let errorCode: string | number | undefined;
            try {
                const body = (await response.json()) as { errorCode?: unknown };
                if (
                    typeof body.errorCode == "string" ||
                    typeof body.errorCode == "number"
                ) {
                    errorCode = body.errorCode;
                }
            } catch {
                // Not JSON.
            }
            throw new HomebaseHttpError(
                `${init.method ?? "GET"} ${new URL(url).pathname}: HTTP ${response.status}`,
                response.status,
                errorCode,
            );
        }
        return response;
    }

    /** A shared-secret envelope (recognised by shape), or plain JSON. */
    private async readJson<T>(response: Response): Promise<T | undefined> {
        const text = await response.text();
        if (!text) return undefined;
        const parsed: unknown = JSON.parse(text);
        if (!isEnvelope(parsed)) return parsed as T;
        const plain = fromUtf8(
            await decryptEnvelope(this.session.sharedSecret, parsed),
        );
        return plain ? (JSON.parse(plain) as T) : undefined;
    }

    /**
     * Creates a file. Fails with {@link isExistingUniqueIdError} if a file
     * with the same uniqueId exists; it never overwrites one.
     */
    async createFile(file: NewFile): Promise<{ fileId: string }> {
        const fileKey = { aesKey: randomBytes(16), iv: randomBytes(16) };
        const transferIv = randomBytes(16);
        const instructions = {
            transferIv: toBase64(transferIv),
            storageOptions: { storageIntent: "newFileOrOverwrite" },
            transitOptions: { recipients: [] },
            manifest: { payloadDescriptors: [] },
        };
        const descriptor = {
            encryptedKeyHeader: await lockFileKey(
                fileKey,
                this.session.driveKey,
            ),
            fileMetadata: {
                isEncrypted: true,
                allowDistribution: false,
                accessControlList: { requiredSecurityGroup: "owner" },
                appData: {
                    uniqueId: toGuid(file.uniqueId),
                    fileType: file.fileType,
                    dataType: 0,
                    userDate: null,
                    tags: file.tags ?? null,
                    groupId: null,
                    archivalStatus: 0,
                    content: toBase64(
                        await aesCbcEncrypt(
                            fileKey.aesKey,
                            fileKey.iv,
                            utf8(file.content),
                        ),
                    ),
                    previewThumbnail: null,
                },
                versionTag: null,
            },
        };
        const metadata = await aesCbcEncrypt(
            this.session.sharedSecret,
            transferIv,
            utf8(JSON.stringify(descriptor)),
        );
        const boundary = `----ente-homebase-${toBase64Url(randomBytes(12))}`;
        const part = (name: string, contentType: string) =>
            `--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n` +
            `Content-Type: ${contentType}\r\n\r\n`;
        const response = await this.send(this.filesRoot, {
            method: "POST",
            headers: {
                "content-type": `multipart/form-data; boundary=${boundary}`,
            },
            body: new Blob([
                part("instructions", "application/json"),
                JSON.stringify(instructions),
                "\r\n",
                part("metadata", "application/octet-stream"),
                metadata,
                `\r\n--${boundary}--\r\n`,
            ]),
        });
        const result = await this.readJson<{ fileId: string }>(response);
        if (!result?.fileId) throw new Error("Create returned no fileId");
        return { fileId: result.fileId };
    }

    /** The file with this uniqueId, or `undefined` if there is none. */
    async getHeaderByUniqueId(uniqueId: string) {
        try {
            return await this.readJson<FileHeader>(
                await this.send(
                    `${this.filesRoot}/by-uid/${toGuid(uniqueId)}/header`,
                ),
            );
        } catch (e) {
            if (e instanceof HomebaseHttpError && e.status == 404) {
                return undefined;
            }
            throw e;
        }
    }

    /** A file's content, decrypted with its key. */
    async decryptContent(header: FileHeader) {
        const content = header.fileMetadata.appData.content;
        if (!content) return undefined;
        const { aesKey, iv } = await openFileKey(
            header.sharedSecretEncryptedKeyHeader,
            this.session.driveKey,
        );
        return fromUtf8(await aesCbcDecrypt(aesKey, iv, fromBase64(content)));
    }

    /** Headers of the files with any of these tags (for cleaning up tests). */
    async queryByTags(tags: string[]) {
        const response = await this.send(`${this.filesRoot}/query-batch`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(
                await encryptEnvelope(
                    this.session.sharedSecret,
                    JSON.stringify({
                        queryParams: { tagsMatchAtLeastOne: tags },
                        resultOptionsRequest: {
                            cursorState: null,
                            maxRecords: 100,
                            includeMetadataHeader: true,
                            ordering: "newestFirst",
                            sorting: "anyChangeDate",
                        },
                    }),
                ),
            ),
        });
        const result = await this.readJson<{ searchResults: FileHeader[] }>(
            response,
        );
        return result?.searchResults ?? [];
    }

    /** Deletes files for good. Only ever called on files the caller made. */
    async hardDelete(headers: FileHeader[]) {
        await this.send(`${this.filesRoot}/hard-delete-batch`, {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify(
                await encryptEnvelope(
                    this.session.sharedSecret,
                    JSON.stringify({
                        files: headers.map((h) => ({
                            fileId: h.fileId,
                            versionTag: h.fileMetadata.versionTag,
                        })),
                    }),
                ),
            ),
        });
    }
}
