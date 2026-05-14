import { AuditApiError } from "../api/error";

export const GENERIC_ERROR_MESSAGE = "処理に失敗しました。設定または接続状態を確認してください。";
export const AUTH_ERROR_MESSAGE = "認証に失敗しました。入力または設定を確認してください。";

export const safeErrorMessage = (error: unknown): string => {
    if (error instanceof AuditApiError) {
        return error.requestId === null
            ? `監査 API の読み取りに失敗しました: ${error.code}`
            : `監査 API の読み取りに失敗しました: ${error.code} / request_id=${error.requestId}`;
    }

    return GENERIC_ERROR_MESSAGE;
};
