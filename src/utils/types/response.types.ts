export type ResponseBody<T> = {
    success: boolean;
    data: T | null;
    errors: T | null;
};
