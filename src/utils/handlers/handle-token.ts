import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import authServices from '@modules/authentication';
import config from '@config/config';
import logger from '@config/logger.config';
import dayjs from 'dayjs';
import { tokenTypes } from '@config/config';
import { IJwtPublicKey, IJwtPayload } from '@utils/types';

/**
 * Token Handler Middleware for managing authentication tokens via cookies
 */
export class TokenHandler {
    /**
     * Primary token validation and refresh middleware
     */
    static async validateAndRefreshTokens(req: Request, res: Response, next: NextFunction) {
        try {
            const accessToken = req.signedCookies.accessToken;
            const refreshToken = req.signedCookies.refreshToken;

            if (!accessToken && !refreshToken) {
                return next();
            }
            try {
                const decoded = jwt.verify(accessToken, authServices.getKey(tokenTypes.access_token_public_key as IJwtPublicKey), {
                    algorithms: ['RS256']
                }) as unknown as IJwtPayload;
                req.jwt = decoded;
                return next();
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
            } catch (error) {
                if (!refreshToken) {
                    return next();
                }

                const decoded = authServices.verifyRefreshToken(refreshToken);
                const sessionId = decoded.session;

                const user = await authServices.findUserBySessionId(sessionId);
                if (!user) {
                    throw new CustomError({
                        code: ErrorCodes.Unauthorized,
                        status: StatusCodes.UNAUTHORIZED,
                        description: 'Invalid session',
                        data: {
                            path: ['auth', 'refreshToken', 'session'],
                            message: 'Your session is invalid. Please log in again.'
                        }
                    });
                }

                const tokenExists = await authServices.verifyRefreshTokenInDatabase(authServices.hashToken(refreshToken), user.id);
                if (!tokenExists) {
                    throw new CustomError({
                        code: ErrorCodes.Unauthorized,
                        status: StatusCodes.UNAUTHORIZED,
                        description: 'Invalid token',
                        data: {
                            path: ['auth', 'refreshToken', 'database'],
                            message: 'Your session is invalid. Please log in again.'
                        }
                    });
                }

                const { accessToken: newAccessToken, refreshToken: newRefreshToken } = authServices.getSignedTokens(user);

                await authServices.rotateRefreshToken({
                    userId: user.id,
                    oldTokenHash: authServices.hashToken(refreshToken),
                    newTokenHash: authServices.hashToken(newRefreshToken),
                    userAgent: req.headers['user-agent'] || 'unknown',
                    ip: req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown',
                    expiresAt: new Date(Date.now() + Number(config.refresh_token_valid_time) * 60 * 1000)
                });

                this.setTokenCookies(res, newAccessToken, newRefreshToken);

                const csrfToken = await authServices.generateCSRFToken();
                res.cookie('XSRF-TOKEN', csrfToken, {
                    httpOnly: false,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: Number(config.access_token_valid_time) * 60 * 1000
                });

                req.jwt = {
                    sub: user.id,
                    email: user.email,
                    iat: dayjs().valueOf(),
                    issuer: 'shopmate-sha',
                    audience: 'shopmate-sha'
                };

                logger.info(`Refreshed tokens for user ${user.id}`);

                next();
            }
        } catch (error) {
            res.clearCookie('accessToken');
            res.clearCookie('refreshToken');
            res.clearCookie('XSRF-TOKEN');

            next(error);
        }
    }

    /**
     * Set token cookies with consistent configuration
     */
    static setTokenCookies(res: Response, accessToken: string, refreshToken: string) {
        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            maxAge: Number(config.access_token_valid_time) * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined,
            signed: true
        });
        logger.info(`accessToken cookie set successfully`);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/',
            maxAge: Number(config.refresh_token_valid_time) * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined,
            signed: true
        });
        logger.info(`refreshToken cookie set successfully`);
    }

    /**
     * CSRF Protection Middleware
     */
    static csrfProtection(req: Request, res: Response, next: NextFunction) {
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
            return next();
        }

        const csrfTokenFromCookie = req.signedCookies['XSRF-TOKEN'];
        const csrfTokenFromHeader = req.headers['x-xsrf-token'] || req.headers['x-csrf-token'] || req.body?.csrfToken;

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

    /**
     * Utility method to clear authentication cookies
     */
    static clearAuthCookies(res: Response) {
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        res.clearCookie('XSRF-TOKEN');
    }
}
