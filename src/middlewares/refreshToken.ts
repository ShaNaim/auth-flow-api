import { Request, Response, NextFunction } from 'express';
import authServices from '@modules/authentication';
import { tokenTypes } from '@config/config';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
import { IJwtPublicKey, IJwtPayload } from '@utils/types';
import logger from '@config/logger.config';
import dayjs from 'dayjs';
import jwt from 'jsonwebtoken';
import { StatusCodes } from 'http-status-codes';
import config from '@config/config';
/**
 * Middleware to revalidate access token using refresh token when access token expires
 */
export async function refreshTokenMiddleware(req: Request, res: Response, next: NextFunction) {
    try {
        // Check if there's an access token in the cookies
        const accessToken = req.signedCookies.accessToken;
        const refreshToken = req.signedCookies.refreshToken;

        // If no tokens exist, let the auth middleware handle it
        if (!accessToken && !refreshToken) {
            return next();
        }

        // Try to verify the access token
        try {
            const decoded = jwt.verify(accessToken, authServices.getKey(tokenTypes.access_token_public_key as IJwtPublicKey), {
                algorithms: ['RS256']
            }) as unknown as IJwtPayload;

            // If access token is valid, set user in request and continue
            req.jwt = decoded;
            return next();
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
        } catch (error) {
            // Access token is invalid or expired, let's try refresh token
            if (!refreshToken) {
                return next(); // No refresh token, let auth middleware handle it
            }

            // Verify refresh token
            const decoded = authServices.verifyRefreshToken(refreshToken);

            // Get session ID from the refresh token
            const sessionId = decoded.session;

            // Find user from database using session ID
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

            // Check if the refresh token hash exists in database
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

            // Generate new tokens
            const { accessToken: newAccessToken, refreshToken: newRefreshToken } = authServices.getSignedTokens(user);

            // Store new refresh token and invalidate old one
            await authServices.rotateRefreshToken({
                userId: user.id,
                oldTokenHash: authServices.hashToken(refreshToken),
                newTokenHash: authServices.hashToken(newRefreshToken),
                userAgent: req.headers['user-agent'] || 'unknown',
                ip: req.ip || (req.headers['x-forwarded-for'] as string) || 'unknown',
                expiresAt: new Date(Date.now() + Number(config.refresh_token_valid_time) * 60 * 1000)
            });

            // Set new cookies
            res.cookie('accessToken', newAccessToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: Number(config.access_token_valid_time) * 60 * 1000,
                domain: process.env.COOKIE_DOMAIN || undefined,
                signed: true
            });

            res.cookie('refreshToken', newRefreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                path: '/api/auth/refresh',
                maxAge: Number(config.refresh_token_valid_time) * 60 * 1000,
                domain: process.env.COOKIE_DOMAIN || undefined,
                signed: true
            });

            // Generate new CSRF token
            const csrfToken = await authServices.generateCSRFToken();
            res.cookie('XSRF-TOKEN', csrfToken, {
                httpOnly: false,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: Number(config.access_token_valid_time) * 60 * 1000
            });

            // Set user in request object
            req.jwt = {
                sub: user.id,
                email: user.email,
                iat: dayjs().unix(),
                exp: dayjs().add(config.access_token_valid_time, 'minute').unix(),
                issuer: 'auth-flow-api',
                audience: 'auth-flow-api',
                type: 'access'
            };

            // Log token refresh
            logger.info(`Refreshed tokens for user ${user.id}`);

            // Continue with the request
            next();
        }
    } catch (error) {
        // Clear cookies on error
        res.clearCookie('accessToken');
        res.clearCookie('refreshToken');
        res.clearCookie('XSRF-TOKEN');

        // Pass error to error handling middleware
        next(error);
    }
}
