import { Request, Response, NextFunction } from 'express';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import { TokenHandler } from '@utils/handlers';

export function tokenHandlerMiddleware(req: Request, res: Response, next: NextFunction) {
    return TokenHandler.validateAndRefreshTokens(req, res, next);
}

export function csrfHandlerMiddleware(req: Request, res: Response, next: NextFunction) {
    return TokenHandler.csrfProtection(req, res, next);
}

export function tokenRequired(req: Request, res: Response, next: NextFunction) {
    if (Boolean(req.jwt?.sub)) return next();
    return next(
        new CustomError({
            code: ErrorCodes.AuthError,
            status: StatusCodes.UNAUTHORIZED,
            description: `Unauthorized user`,
            data: `Your are not authorized to perform this action`
        })
    );
}
