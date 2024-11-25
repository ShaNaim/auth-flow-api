import { Request, Response, NextFunction } from 'express';
import authServices from '@modules/authentication';
import { IJwtPayload } from '@utils/types';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
// function handleAccessToken() {}
// function handleRefreshToken() {}

export function tokenHandler(req: Request, res: Response, next: NextFunction) {
    if (req?.headers?.authorization) {
        const accessToken = (req?.headers?.authorization || '').replace(/^Bearer\s/i, '');
        const decoded = authServices.verifyToken<IJwtPayload>(accessToken, 'access_token_public_key');
        if (decoded) {
            req.userId = decoded.sub;
            req.jwt = decoded;
        }
        return next();
    }
    return next();
}

export function tokenRequired(req: Request, res: Response, next: NextFunction) {
    if (Boolean(req.userId)) return next();
    return next(
        new CustomError({
            code: ErrorCodes.AuthError,
            status: StatusCodes.UNAUTHORIZED,
            description: `Unauthorized user`,
            data: `Your are not authorized to perform this action`
        })
    );
}
