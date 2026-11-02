// Homebase thumbnails, as chat-kmp makes them (homebase-api
// image/ThumbnailGenerator.kt): a tiny preview kept inline in the file's
// metadata, plus WebP thumbnails of the payload at 320, 640, 1080 and 1600 px
// (never larger than the source). Browser only: it draws on a canvas.

import { toBase64, type Bytes } from "./bytes";

interface Instruction {
    quality: number;
    maxPixelDimension: number;
    maxBytes: number;
}

const ladder: Instruction[] = [
    { quality: 84, maxPixelDimension: 320, maxBytes: 26 * 1024 },
    { quality: 84, maxPixelDimension: 640, maxBytes: 102 * 1024 },
    { quality: 76, maxPixelDimension: 1080, maxBytes: 291 * 1024 },
    { quality: 76, maxPixelDimension: 1600, maxBytes: 640 * 1024 },
];

// Odin refuses an inline preview over 1024 bytes; chat-kmp aims for 768.
const tiny: Instruction = { quality: 76, maxPixelDimension: 20, maxBytes: 768 };

// chat-kmp's getRevisedThumbs: the sizes below the source's, and if any were
// dropped, one at the source's own size instead.
export const thumbnailSizes = (sourceMax: number): Instruction[] => {
    const low = Math.round(0.9 * sourceMax);
    const high = Math.round(1.1 * sourceMax);
    const kept = ladder.filter(
        (t) =>
            t.maxPixelDimension <= sourceMax &&
            (t.maxPixelDimension < low || t.maxPixelDimension > high),
    );
    if (kept.length < ladder.length) {
        const nearest = ladder.reduce((a, b) =>
            Math.abs(b.maxPixelDimension - sourceMax) <
            Math.abs(a.maxPixelDimension - sourceMax)
                ? b
                : a,
        );
        const maxBytes = Math.min(
            1024 * 1024,
            Math.max(
                10 * 1024,
                Math.round(
                    (nearest.maxBytes * sourceMax) / nearest.maxPixelDimension,
                ),
            ),
        );
        kept.push({
            quality: sourceMax <= 640 ? 84 : 76,
            maxPixelDimension: sourceMax,
            maxBytes,
        });
    }
    return kept.sort((a, b) => a.maxPixelDimension - b.maxPixelDimension);
};

export interface HomebaseThumbnail {
    pixelWidth: number;
    pixelHeight: number;
    contentType: string;
    bytes: Bytes;
}

export interface HomebasePreviewThumbnail {
    pixelWidth: number;
    pixelHeight: number;
    contentType: string;
    // Base64.
    content: string;
}

// WebP where the browser can encode it (Safari can't, and gets JPEG).
const encode = async (
    bitmap: ImageBitmap,
    { quality, maxPixelDimension, maxBytes }: Instruction,
): Promise<HomebaseThumbnail> => {
    const scale = Math.min(
        1,
        maxPixelDimension / Math.max(bitmap.width, bitmap.height),
    );
    const pixelWidth = Math.max(1, Math.round(bitmap.width * scale));
    const pixelHeight = Math.max(1, Math.round(bitmap.height * scale));
    const canvas = new OffscreenCanvas(pixelWidth, pixelHeight);
    const context = canvas.getContext("2d");
    if (!context) throw new Error("No 2D canvas");
    context.drawImage(bitmap, 0, 0, pixelWidth, pixelHeight);

    let type = "image/webp";
    let q = quality;
    for (;;) {
        const blob = await canvas.convertToBlob({ type, quality: q / 100 });
        if (blob.type != type) type = "image/jpeg";
        else if (blob.size <= maxBytes || q <= 10)
            return {
                pixelWidth,
                pixelHeight,
                contentType: blob.type,
                bytes: new Uint8Array(await blob.arrayBuffer()),
            };
        else q -= 10;
    }
};

// The tiny preview and the thumbnail set for an image, or undefined if the
// browser can't decode it (then pass a smaller rendition, such as Ente's own
// thumbnail, which Ente makes for every photo and video).
export const homebaseThumbnails = async (source: Blob) => {
    let bitmap: ImageBitmap;
    try {
        bitmap = await createImageBitmap(source);
    } catch {
        return undefined;
    }
    try {
        const sourceMax = Math.max(bitmap.width, bitmap.height);
        const thumbnails: HomebaseThumbnail[] = [];
        for (const size of thumbnailSizes(sourceMax))
            thumbnails.push(await encode(bitmap, size));
        const small = await encode(bitmap, tiny);
        const previewThumbnail: HomebasePreviewThumbnail = {
            pixelWidth: small.pixelWidth,
            pixelHeight: small.pixelHeight,
            contentType: small.contentType,
            content: toBase64(small.bytes),
        };
        return { previewThumbnail, thumbnails };
    } finally {
        bitmap.close();
    }
};
