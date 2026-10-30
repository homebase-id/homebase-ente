// Byte helpers for the browser: no Buffer, no Node modules. Ported from the
// Immich Homebase client (packages/homebase-client/src/web/bytes.ts).

export type Bytes = Uint8Array<ArrayBuffer>;

export const utf8 = (text: string): Bytes => new TextEncoder().encode(text);
export const fromUtf8 = (bytes: Uint8Array): string =>
    new TextDecoder().decode(bytes);

export const concat = (...parts: Uint8Array[]): Bytes => {
    const out = new Uint8Array(
        parts.reduce((sum, part) => sum + part.length, 0),
    );
    let offset = 0;
    for (const part of parts) {
        out.set(part, offset);
        offset += part.length;
    }
    return out;
};

export const toBase64 = (bytes: Uint8Array): string => {
    let binary = "";
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
};

export const toBase64Url = (bytes: Uint8Array | string): string =>
    toBase64(typeof bytes == "string" ? utf8(bytes) : bytes)
        .replaceAll("+", "-")
        .replaceAll("/", "_")
        .replace(/=+$/, "");

/** Decodes standard or URL-safe base64, padded or not. */
export const fromBase64 = (value: string): Bytes => {
    const standard = value.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(
        standard.padEnd(Math.ceil(standard.length / 4) * 4, "="),
    );
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
};

/** getRandomValues fills at most 64 KiB per call. */
export const randomBytes = (length: number): Bytes => {
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i += 65_536) {
        crypto.getRandomValues(out.subarray(i, i + 65_536));
    }
    return out;
};

const crcTable = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++)
            c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        table[n] = c >>> 0;
    }
    return table;
})();

/**
 * IEEE CRC-32 (what odin-core's `CRC32C.CalculateCRC32C` computes despite its
 * name).
 */
export const crc32 = (data: Uint8Array): number => {
    let crc = 0xffffffff;
    for (const byte of data) crc = crcTable[(crc ^ byte) & 0xff]! ^ (crc >>> 8);
    return (crc ^ 0xffffffff) >>> 0;
};
