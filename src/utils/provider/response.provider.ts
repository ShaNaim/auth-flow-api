import { ResponseBody } from '@utils/types/response.types';
export function responseObject<T>(payload: T, error: boolean = false): ResponseBody<T> {
    return {
        success: error ? false : true,
        data: error ? null : payload,
        errors: error ? payload : null
    };
}
