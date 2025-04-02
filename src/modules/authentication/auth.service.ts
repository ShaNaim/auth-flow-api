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

/**
 * Generates a JWT token with a payload, key, and expiration time.
 * @param payload - The payload to be included in the token.
 * @param keyName - The key name used for signing.
 * @param minutes - The expiration time in minutes.
 * @returns The signed JWT token.
 */
export function getToken(payload: object, keyName: IJwtPrivateKey, minutes: number | undefined = undefined) {
    logger.info(`Service => Generating token with key ${keyName}`);
    const options: jwt.SignOptions = {
        algorithm: 'RS256'
    };

    if (minutes) {
        options.expiresIn = minutes;
    }
    return jwt.sign(payload, getKey(keyName), options);
}

/**
 * Returns the key associated with the provided key name.
 * @param keyName - The key name to fetch.
 * @returns The corresponding key as a string.
 */
export function getKey(keyName: IJwtPrivateKey | IJwtPublicKey): string {
    logger.info(`Service => Fetching key for ${keyName}`);
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

/**
 * Signs and returns an access token for a user.
 * @param user - The user object.
 * @returns The signed JWT access token.
 */
export function signAccessToken(user: User): string {
    logger.info(`Service => Signing access token for user ${user.email}`);
    const payload: IJwtPayload = {
        sub: user.id,
        email: user.email,
        iat: dayjs().valueOf(),
        issuer: 'shopmate-sha',
        audience: 'shopmate-sha'
    };

    return getToken(payload, tokenTypes.access_token_private_key as IJwtPrivateKey, Number(config.access_token_valid_time));
}

/**
 * Signs and returns a refresh token for a user.
 * @param user - The user object.
 * @returns The signed JWT refresh token.
 */
export function signRefreshToken(user: User): string {
    logger.info(`Service => Signing refresh token for user ${user.email}`);
    return getToken(
        { session: user.id.toString(), iat: new Date().getTime() },
        tokenTypes.refresh_token_private_key as IJwtPrivateKey,
        Number(config.refresh_token_valid_time)
    );
}

/**
 * Generates and returns both access and refresh tokens for a user.
 * @param user - The user object.
 * @returns An object containing the access and refresh tokens.
 */
export function getSignedTokens(user: User): { accessToken: string; refreshToken: string } {
    logger.info(`Service => Generating access and refresh tokens for user ${user.email}`);
    return {
        accessToken: signAccessToken(user),
        refreshToken: signRefreshToken(user)
    };
}

/**
 * Generates a CSRF token for protection against CSRF attacks.
 * @returns A Promise that resolves to the generated CSRF token.
 */
// eslint-disable-next-line require-await
export async function generateCSRFToken(): Promise<string> {
    logger.info('Service => Generating CSRF token');
    return new Promise((resolve, reject) => {
        crypto.randomBytes(32, (err, buffer) => {
            if (err) {
                logger.error('Service => Failed to generate CSRF token', err);
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
 * Hashes a token securely for storage in the database.
 * @param token - The token to hash.
 * @returns The hashed token.
 */
export function hashToken(token: string): string {
    logger.info('Service => Hashing token for storage');
    return crypto.createHash('sha256').update(`${token}${config.token_secret}`).digest('hex');
}

/**
 * Verifies if a refresh token is valid.
 * @param refreshToken - The refresh token to verify.
 * @returns The decoded token payload if valid.
 */
export function verifyRefreshToken(refreshToken: string): any {
    try {
        logger.info('Service => Verifying refresh token');
        return jwt.verify(refreshToken, getKey(tokenTypes.refresh_token_public_key as IJwtPublicKey), { algorithms: ['RS256'] });
    } catch (error) {
        logger.error('Service => Refresh token verification failed', error);
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
 * Find a user by session ID.
 * @param sessionId - The session ID.
 * @returns The user object if found, or null if not.
 */
export async function findUserBySessionId(sessionId: string): Promise<User | null> {
    logger.info(`Service => Finding user by session ID: ${sessionId}`);
    return await authModel.findUserBySessionId(sessionId);
}

/**
 * Verifies if a refresh token exists in the database.
 * @param tokenHash - The hashed refresh token.
 * @param userId - The user ID.
 * @returns A boolean indicating whether the token exists and is valid.
 */
export async function verifyRefreshTokenInDatabase(tokenHash: string, userId: number): Promise<boolean> {
    logger.info('Service => Verifying refresh token in database');
    return await authModel.verifyRefreshToken(tokenHash, userId);
}

/**
 * Rotates refresh tokens by invalidating the old one and storing the new one.
 * @param options - The options for rotating the refresh token.
 */
export async function rotateRefreshToken(options: {
    userId: number;
    oldTokenHash: string;
    newTokenHash: string;
    userAgent: string;
    ip: string;
    expiresAt: Date;
}): Promise<void> {
    logger.info('Service => Rotating refresh token');
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
 * Stores a refresh token in the database.
 * @param options - The storage options for the refresh token.
 */
export async function storeRefreshToken(options: StoreRefreshTokenParams): Promise<void> {
    logger.info('Service => Storing refresh token in database');
    await authModel.storeRefreshToken(options);
}

/**
 * Handles user session creation or retrieval.
 * @param user - The user object.
 * @returns The session object associated with the user.
 */
export async function handleSession(user: User): Promise<Session> {
    logger.info(`Service => Handling session for user ${user.email}`);
    const hasSession = await authModel.findSessionsByUserId(user?.id);
    if (hasSession.length !== 0) {
        return hasSession[0];
    }
    return await authModel.createSession(user.id);
}

/**
 * Generates a new session for a user.
 * @param user - The user object.
 * @returns The new session object.
 */
export async function generateSession(user: User): Promise<Session> {
    logger.info(`Service => Generating new session for user ${user.email}`);
    return await authModel.createSession(user.id);
}

/**
 * Hashes a string securely using Argon2.
 * @param value - The value to hash.
 * @returns The hashed string.
 */
export async function hashString(value: string): Promise<string> {
    logger.info('Service => Hashing string');
    return await argon2.hash(value);
}

/**
 * Compares a hashed value with a target string to verify if they match.
 * @param compare - The hashed value.
 * @param target - The original value to compare with.
 * @returns True if they match, false otherwise.
 */
export async function compairHash(compare: string, target: string): Promise<boolean> {
    try {
        logger.info('Service => Comparing hashed value with target');
        return await argon2.verify(compare, target);
    } catch (error) {
        logger.error('Service => Could not verify password', error);
        return false;
    }
}

/**
 * Verifies a JWT token.
 * @param token - The JWT token to verify.
 * @param keyName - The key name used to verify the token.
 * @returns The decoded token payload if valid.
 */
export function verifyToken<T>(token: string, keyName: IJwtPublicKey): T | undefined {
    logger.info('Service => Verifying token');
    return jwt.verify(token, getKey(keyName)) as T;
}

/**
 * Authenticates a user based on the login credentials.
 * @param attemptUser - The login credentials provided by the user.
 * @returns The user object if authentication is successful.
 */
export async function authenticateUser(attemptUser: LoginSchema): Promise<User> {
    logger.info(`Service => Authenticating user ${attemptUser?.email}`);
    const userExists = await authModel.getUserForAuthentication(attemptUser?.email);
    if (!userExists)
        throw new CustomError({
            code: ErrorCodes.NotFound,
            status: StatusCodes.NOT_FOUND,
            description: 'No User Found',
            data: {
                path: ['user', 'email'],
                message: `No user exists with email: ${attemptUser?.email}`
            }
        });

    if (!(await compairHash(userExists.password, attemptUser?.password)))
        throw new CustomError({
            code: ErrorCodes.AuthError,
            status: StatusCodes.BAD_REQUEST,
            description: "Password doesn't match",
            data: {
                path: ['user', 'password'],
                message: `Password doesn't match`
            }
        });
    if (userExists.isBlocked)
        throw new CustomError({
            code: ErrorCodes.Unauthorized,
            status: StatusCodes.UNAUTHORIZED,
            description: 'User Blocked',
            data: {
                path: ['user', 'block'],
                message: `User blocked. Please contact admin`
            }
        });
    return userExists;
}

/**
 * Checks if a user exists based on their slug.
 * @param slug - The user's slug.
 * @returns The user object if found, or null if not.
 */
export async function userExists(slug: string): Promise<User | null> {
    logger.info(`Service => Checking if user exists for slug: ${slug}`);
    return await authModel.getUserBySlug(slug);
}
