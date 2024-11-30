import dayjs from 'dayjs';
import jwt from 'jsonwebtoken';
import * as argon2 from 'argon2';
import { StatusCodes } from 'http-status-codes';
import { Session, User } from '@prisma/client';

import log from '@config/logger.config';
import { ErrorCodes } from '@errors/ErrorCodes';
import { CustomError } from '@errors/CustomError';
import config, { tokenTypes } from '@config/config';
import { IJwtPrivateKey, IJwtPublicKey, IJwtPayload } from '@utils/types';
import { LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';

import * as authModel from './auth.model';

function getToken(payload: object, keyName: IJwtPrivateKey, minutes: number | undefined = undefined) {
    const options: jwt.SignOptions = {
        algorithm: 'RS256'
    };

    if (minutes) {
        options.expiresIn = minutes;
    }
    return jwt.sign(payload, getKey(keyName), options);
}

function getKey(keyName: IJwtPrivateKey | IJwtPublicKey): string {
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

function signAccessToken(user: User): string | undefined {
    const payload: IJwtPayload = {
        sub: user.id,
        email: user.email,
        iat: dayjs().valueOf(),
        issuer: 'shopmate-sha',
        audience: 'shopmate-sha'
    };

    return getToken(payload, tokenTypes.access_token_private_key as IJwtPrivateKey, Number(config.access_token_valid_time));
}

function signRefreshToken(user: User): string | undefined {
    return getToken(
        { session: user.id.toString(), iat: new Date().getTime() },
        tokenTypes.refresh_token_private_key as IJwtPrivateKey,
        Number(config.refresh_token_valid_time)
    );
}

export function getSignedTokens(user: User): { accessToken: string | undefined; refreshToken: string | undefined } {
    return {
        accessToken: signAccessToken(user),
        refreshToken: signRefreshToken(user)
    };
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
        log.error(error, 'Could not verify password');
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

const authServices = { hashString, compairHash, authenticateUser, verifyToken, userExists };
export default authServices;
