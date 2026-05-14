export const nowIso = (): string => new Date().toISOString();

export const daysAgoIso = (days: number): string => {
    const date = new Date();
    date.setUTCDate(date.getUTCDate() - days);
    return date.toISOString();
};

export const currentYearMonth = (): string => new Date().toISOString().slice(0, 7);
