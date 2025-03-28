import crypto from 'crypto';
import dayjs from 'dayjs';
import jwt from 'jsonwebtoken';
import * as argon2 from 'argon2';
import { StatusCodes } from 'http-status-codes';
import { User, Session } from '@prisma/client';

import logger from '@config/logger.config';
import { ErrorCodes } from '@errors/ErrorCodes';
import { CustomError } from '@errors/CustomError';
import config, { tokenTypes } from '@config/config';
import { IJwtPrivateKey, IJwtPublicKey, IJwtPayload } from '@utils/types';
import { LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';

import * as authModel from './auth.model';
import { StoreRefreshTokenParams } from './auth.types';

export function getToken(payload: object, keyName: IJwtPrivateKey, minutes: number | undefined = undefined) {
    const options: jwt.SignOptions = {
        algorithm: 'RS256'
    };

    if (minutes) {
        options.expiresIn = minutes;
    }
    return jwt.sign(payload, getKey(keyName), options);
}

export function getKey(keyName: IJwtPrivateKey | IJwtPublicKey): string {
    if (tokenTypes.access_token_private_key === keyName) return String(config.access_token_private_key);
    if (tokenTypes.access_token_public_key === keyName) return String(config.access_token_public_key);
    if (tokenTypes.refresh_token_private_key === keyName) return String(config.refresh_token_private_key);
    if (tokenTypes.refresh_token_public_key === keyName) return String(config.refresh_token_public_key);
    throw new CustomError({
        code: ErrorCodes.ServerError,
        status: StatusCodes.INTERNAL_SERVER_ERROR,
        description: 'No token found',
        data: {
            path: ['user', 'authentication', 'keyName', 'token'],
            message: `No token found in env file with ${keyName} key`
        },
        isOperational: false
    });
}

export function signAccessToken(user: User): string {
    const payload: IJwtPayload = {
        sub: user.id,
        email: user.email,
        iat: dayjs().valueOf(),
        issuer: 'shopmate-sha',
        audience: 'shopmate-sha'
    };

    return getToken(payload, tokenTypes.access_token_private_key as IJwtPrivateKey, Number(config.access_token_valid_time));
}

export function signRefreshToken(user: User): string {
    return getToken(
        { session: user.id.toString(), iat: new Date().getTime() },
        tokenTypes.refresh_token_private_key as IJwtPrivateKey,
        Number(config.refresh_token_valid_time)
    );
}

export function getSignedTokens(user: User): { accessToken: string; refreshToken: string } {
    return {
        accessToken: signAccessToken(user),
        refreshToken: signRefreshToken(user)
    };
}

/**
 * Generates a CSRF token for protection against CSRF attacks
 * @returns Promise with the generated CSRF token
 */
// eslint-disable-next-line require-await
export async function generateCSRFToken(): Promise<string> {
    return new Promise((resolve, reject) => {
        // Generate 32 random bytes and convert to hex string
        crypto.randomBytes(32, (err, buffer) => {
            if (err) {
                reject(
                    new CustomError({
                        code: ErrorCodes.ServerError,
                        status: StatusCodes.INTERNAL_SERVER_ERROR,
                        description: 'Failed to generate CSRF token',
                        data: {
                            path: ['auth', 'csrf', 'generation'],
                            message: err.message
                        },
                        isOperational: false
                    })
                );
            } else {
                resolve(buffer.toString('hex'));
            }
        });
    });
}

/**
 * Hashes a token securely for storage in the database
 * @param token The token to hash
 * @returns Hashed token
 */
export function hashToken(token: string): string {
    return crypto.createHash('sha256').update(`${token}${config.token_secret}`).digest('hex');
}

/**
 * Verifies if a refresh token is valid
 * @param refreshToken The refresh token to verify
 * @returns The decoded token payload if valid
 */
export function verifyRefreshToken(refreshToken: string): any {
    try {
        return jwt.verify(refreshToken, getKey(tokenTypes.refresh_token_public_key as IJwtPublicKey), { algorithms: ['RS256'] });
    } catch (error) {
        logger.error('Refresh token verification failed', error);
        throw new CustomError({
            code: ErrorCodes.Unauthorized,
            status: StatusCodes.UNAUTHORIZED,
            description: 'Invalid refresh token',
            data: {
                path: ['auth', 'refreshToken', 'verify'],
                message: 'Your session has expired. Please log in again.'
            }
        });
    }
}

/**
 * Find a user by session ID
 * @param sessionId The session ID
 * @returns User if found
 */
export async function findUserBySessionId(sessionId: string): Promise<User | null> {
    return await authModel.findUserBySessionId(sessionId);
}

/**
 * Verify if a refresh token exists in the database
 * @param tokenHash The hashed refresh token
 * @param userId The user ID
 * @returns Boolean indicating if token exists and is valid
 */
export async function verifyRefreshTokenInDatabase(tokenHash: string, userId: number): Promise<boolean> {
    return await authModel.verifyRefreshToken(tokenHash, userId);
}

/**
 * Rotate refresh tokens - invalidate old and store new
 * @param options Token rotation options
 */
export async function rotateRefreshToken(options: {
    userId: number;
    oldTokenHash: string;
    newTokenHash: string;
    userAgent: string;
    ip: string;
    expiresAt: Date;
}): Promise<void> {
    await authModel.invalidateRefreshToken(options.userId, options.oldTokenHash);
    await authModel.storeRefreshToken({
        userId: options.userId,
        tokenHash: options.newTokenHash,
        userAgent: options.userAgent,
        ip: options.ip,
        expiresAt: options.expiresAt
    });
}

/**
 * Store a refresh token in the database
 * @param options Token storage options
 */
export async function storeRefreshToken(options: StoreRefreshTokenParams): Promise<void> {
    await authModel.storeRefreshToken(options);
}

export async function handleSession(user: User): Promise<Session> {
    const hasSession = await authModel.findSessionsByUserId(user?.id);
    if (hasSession.length !== 0) {
        //TODO: Implement Multi-tenancy and handle Accoudingly
        return hasSession[0];
    }
    return await authModel.createSession(user.id);
}

export async function generateSession(user: User): Promise<Session> {
    return await authModel.createSession(user.id);
}

export async function hashString(value: string): Promise<string> {
    return await argon2.hash(value);
}

export async function compairHash(compare: string, target: string): Promise<boolean> {
    try {
        return await argon2.verify(compare, target);
    } catch (error) {
        logger.error('Could not verify password', error);
        logger.error('error', 'Could not verify password');
        return false;
    }
}

export function verifyToken<T>(token: string, keyName: IJwtPublicKey): T | undefined {
    return jwt.verify(token, getKey(keyName)) as T;
}

export async function authenticateUser(attemptUser: LoginSchema): Promise<User> {
    const userExists = await authModel.getUserForAuthentication(attemptUser?.email);
    if (!userExists)
        throw new CustomError({
            code: ErrorCodes.NotFound,
            status: StatusCodes.NOT_FOUND,
            description: 'No User Found',
            data: {
                path: ['user', 'email'],
                message: `No user exista with email: ${attemptUser?.email}`
            }
        });

    if (!(await compairHash(userExists.password, attemptUser?.password)))
        throw new CustomError({
            code: ErrorCodes.AuthError,
            status: StatusCodes.BAD_REQUEST,
            description: "Password don't match",
            data: {
                path: ['user', 'password'],
                message: `Password don't match`
            }
        });
    if (userExists.isBlocked)
        throw new CustomError({
            code: ErrorCodes.Unauthorized,
            status: StatusCodes.UNAUTHORIZED,
            description: 'User Blocked',
            data: {
                path: ['user', 'block'],
                message: `User blocked please contact admin`
            }
        });
    return userExists;
}

export async function userExists(slug: string): Promise<User | null> {
    return await authModel.getUserBySlug(slug);
}
