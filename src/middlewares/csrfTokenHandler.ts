// middleware/csrfProtection.ts
import { Request, Response, NextFunction } from 'express';
import { StatusCodes } from 'http-status-codes';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';

/**
 * Middleware to protect against CSRF attacks
 * Verifies the CSRF token from headers against the token stored in cookies
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction) {
    // Skip for GET, HEAD, OPTIONS requests (they should be idempotent)
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
        return next();
    }

    const csrfTokenFromCookie = req.cookies['XSRF-TOKEN'];
    const csrfTokenFromHeader = req.headers['x-xsrf-token'] || req.headers['x-csrf-token'];

    // If either token is missing
    if (!csrfTokenFromCookie || !csrfTokenFromHeader) {
        return next(
            new CustomError({
                code: ErrorCodes.ForbiddenError,
                status: StatusCodes.FORBIDDEN,
                description: 'CSRF token missing',
                data: {
                    path: ['middleware', 'csrf', 'missing'],
                    message: 'CSRF protection: token is missing'
                }
            })
        );
    }

    // Compare tokens
    if (csrfTokenFromCookie !== csrfTokenFromHeader) {
        return next(
            new CustomError({
                code: ErrorCodes.ForbiddenError,
                status: StatusCodes.FORBIDDEN,
                description: 'CSRF token invalid',
                data: {
                    path: ['middleware', 'csrf', 'invalid'],
                    message: 'CSRF protection: token is invalid'
                }
            })
        );
    }

    next();
}
