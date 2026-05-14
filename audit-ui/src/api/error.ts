export class AuditApiError extends Error {
    readonly code: string;
    readonly requestId: string | null;

    constructor(code: string, requestId: string | null) {
        super(code);
        this.name = "AuditApiError";
        this.code = code;
        this.requestId = requestId;
    }
}
