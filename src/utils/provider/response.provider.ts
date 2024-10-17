/* eslint-disable @rushstack/no-new-null */
export function responseObject<T>(
    payload: T,
    error: boolean = false
): {
    success: boolean;
    error: T | null;
    data: T | null;
} {
    if (error)
        return {
            success: false,
            error: payload,
            data: null
        };
    return {
        success: true,
        error: null,
        data: payload
    };
}
