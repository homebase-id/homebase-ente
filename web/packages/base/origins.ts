import { getKVS } from "ente-base/kv";
import { buildEnvCustomAPIEndpoint } from "./env";

export const apiOrigin = async () =>
    (await customAPIOrigin()) ?? "https://api.ente.com";

// path must begin with "/".
export const apiURL = async (
    path: string,
    queryParams?: Record<string, string | number | boolean>,
) => {
    let url = (await apiOrigin()) + path;
    if (queryParams) {
        const stringQP = Object.fromEntries(
            Object.entries(queryParams).map(([k, v]) => [k, v.toString()]),
        );
        const params = new URLSearchParams(stringQP);
        url = `${url}?${params.toString()}`;
    }
    return url;
};

export const customAPIOrigin = async () =>
    (await getKVS("apiOrigin")) ?? buildEnvCustomAPIEndpoint ?? undefined;

/**
 * Whether the app is signed in with Homebase, talking to the Ente → Homebase
 * proxy. Then credentials go only in headers, never in URLs (the token holds
 * the Homebase drive key), and uploads are single-part.
 */
export const isHomebaseMode = async () => (await getKVS("homebase")) == "1";

// This ignores the KV custom server and only reflects the build-time override.
export const isCustomAPIOrigin = !!buildEnvCustomAPIEndpoint;

export const customAPIHost = async () => {
    const origin = await customAPIOrigin();
    return origin ? new URL(origin).host : undefined;
};

// Custom deployments bypass Ente's uploader worker.
export const uploaderOrigin = async () =>
    (await customAPIOrigin()) ?? "https://uploader.ente.com";
