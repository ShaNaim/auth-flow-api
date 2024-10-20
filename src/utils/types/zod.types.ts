export type ValidationErrorResponse = Array<{ path: string; code: string; message: string }>;
export type ValidationError = { path: Array<string>; code: string; message: string };
