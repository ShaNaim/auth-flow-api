import dayjs from 'dayjs';
import jwt from 'jsonwebtoken';
import * as argon2 from 'argon2';
import { StatusCodes } from 'http-status-codes';
import { User } from '@prisma/client';

import log from '@config/logger.config';
import { ErrorCodes } from '@errors/ErrorCodes';
import { CustomError } from '@errors/CustomError';
import config, { tokenTypes } from '@config/config';
import { IJwtPrivateKey, IJwtPublicKey, IJwtPayload } from '@utils/types';
import { LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';

import { getUserForAuthentication } from './auth.model';

function getToken(payload: object, keyName: IJwtPrivateKey, minutes: number | undefined = undefined) {
    const options: jwt.SignOptions = {
        algorithm: 'RS256'
    };

    if (minutes) {
        const oneMin = 60000;
        options.expiresIn = minutes * oneMin;
    }
    return jwt.sign(payload, getKey(keyName), options);
}

function getKey(keyName: IJwtPrivateKey | IJwtPublicKey): string {
    if (tokenTypes.access_token_private_key === keyName) return String(config.access_token_private_key);
    if (tokenTypes.access_token_public_key === keyName) return config.access_token_public_key;
    if (tokenTypes.refresh_token_private_key === keyName) return config.refresh_token_private_key;
    if (tokenTypes.refresh_token_public_key === keyName) return config.refresh_token_public_key;
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

function signAccessToken(user: User, minutes: number = 20): string | undefined {
    const payload: IJwtPayload = {
        sub: user.id,
        email: user.email,
        iat: dayjs().valueOf(),
        issuer: 'shopmate-sha',
        audience: 'shopmate-sha'
    };

    return getToken(payload, tokenTypes.access_token_private_key as IJwtPrivateKey, minutes);
}

function signRefreshToken(user: User): string | undefined {
    return getToken({ session: user.id.toString(), iat: new Date().getTime() }, tokenTypes.refresh_token_private_key as IJwtPrivateKey);
}

export function getSignedTokens(user: User, minutes: number = 20) {
    return { accessToken: signAccessToken(user, minutes), refreshToken: signRefreshToken(user) };
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

export async function generaSession(value: string): Promise<string> {
    return await argon2.hash(value);
}

export async function authenticateUser(attemptUser: LoginSchema): Promise<User> {
    const userExists = await getUserForAuthentication(attemptUser?.email);
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

const authServices = { hashString, compairHash, authenticateUser };
export default authServices;
