import { AuditApiError } from "@/api/error";
import type { AppConfig } from "@/config";

export const appendQuery = (path: string, params: Record<string, string | null>): string => {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
        if (value !== null && value !== "") {
            query.set(key, value);
        }
    }

    const queryText = query.toString();
    return queryText === "" ? path : `${path}?${queryText}`;
};

const errorCodeFromResponse = async (
    response: Response,
): Promise<{ code: string; requestId: string | null }> => {
    const fallbackCode = response.status === 401 ? "unauthorized" : `http_${response.status}`;
    try {
        const value = (await response.json()) as { code?: unknown; request_id?: unknown };
        return {
            code: typeof value.code === "string" ? value.code : fallbackCode,
            requestId: typeof value.request_id === "string" ? value.request_id : null,
        };
    } catch {
        return { code: fallbackCode, requestId: null };
    }
};

export const fetchReadOnlyJson = async <T>(
    config: AppConfig,
    accessToken: string,
    path: string,
): Promise<T> => {
    const response = await fetch(`${config.auditApiBaseUrl}${path}`, {
        headers: {
            Accept: "application/json",
            Authorization: `Bearer ${accessToken}`,
        },
        cache: "no-store",
    });

    if (!response.ok) {
        const error = await errorCodeFromResponse(response);
        throw new AuditApiError(error.code, error.requestId);
    }

    return (await response.json()) as T;
};
