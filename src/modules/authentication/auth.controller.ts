import { Request, Response } from 'express';
import { responseObject } from '@provider/response.provider';
import { RegisterSchema, LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
import { RequestType } from '@utils/types';
import userServices from '@modules/user/user';
import { gracefulErrorHandler } from '@errors/ErrorHandler';
import { CustomError } from '@errors/CustomError';
import authServices, { getSignedTokens, generateSession } from './auth.service';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';

export function healthController(req: Request, res: Response) {
    res.status(200).json(
        responseObject(
            {
                message: 'Auth System Running , Health OK'
            },
            false
        )
    );
}

export type IdType<T> = T extends { id: infer U } ? U : never;

export async function loginController(req: RequestType<LoginSchema, unknown, unknown>, res: Response) {
    try {
        const body = req?.body;
        const user = await authServices.authenticateUser(body);
        if (!Boolean(user)) {
            new CustomError({
                code: ErrorCodes.UnknownError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['user', 'authentication', 'unknown'],
                    message: `Something went wrong , please try again`
                }
            });
        }
        const { accessToken, refreshToken } = getSignedTokens(user);
        if (!accessToken || !refreshToken)
            new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['login', 'getSignedTokens', 'accessToken', 'refreshToken'],
                    message: `No ${accessToken ?? 'accessToken'} ${refreshToken ?? 'refreshToken'} found`
                },
                isOperational: false
            });

        const session = await generateSession(user);
        if (!session)
            new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['login', 'generateSession', 'session'],
                    message: `No session Found`
                },
                isOperational: false
            });
        res.status(200).json(responseObject({ email: user?.email, slug: user?.slug, accessToken, refreshToken }, false));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

export async function reginsterController(req: RequestType<RegisterSchema, unknown, unknown>, res: Response) {
    try {
        req.body.password = await authServices.hashString(req?.body?.password);
        const newUser = await userServices.createUserService(req.body);
        res.status(200).json(responseObject(newUser, false));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}
