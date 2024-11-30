import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { responseObject } from '@provider/response.provider';
import { ErrorCodes } from '@errors/ErrorCodes';
import { RegisterSchema, LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
import { RequestType } from '@utils/types';
import userServices from '@modules/user/user';
import { gracefulErrorHandler } from '@errors/ErrorHandler';
import { CustomError } from '@errors/CustomError';
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import authServices, { getSignedTokens, handleSession } from './auth.service';

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
            throw new CustomError({
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
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['login', 'getSignedTokens', 'accessToken', 'refreshToken'],
                    message: `No ${accessToken ?? 'accessToken'} ${refreshToken ?? 'refreshToken'} found`
                },
                isOperational: false
            });
        //TODO: Off till Multi-tenancy System implemented
        // const session = await handleSession(user);

        // if (!Boolean(session))
        //     throw new CustomError({
        //         code: ErrorCodes.ServerError,
        //         status: StatusCodes.INTERNAL_SERVER_ERROR,
        //         description: 'Something went wrong',
        //         data: {
        //             path: ['login', 'generateSession', 'session'],
        //             message: `No session Found`
        //         },
        //         isOperational: false
        //     });
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

export function logoutController(req: Request, res: Response) {
    res.status(200).json(responseObject('logout successful', false));
}

export async function blockUserController(req: Request, res: Response) {
    try {
        const existingUser = await authServices.userExists(req?.params?.slug);
        if (!existingUser) {
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: `No User Found`,
                data: `No User with provided credential exists`
            });
        }

        const newBlockedStatus = !existingUser.isBlocked;
        const updatedUser = await userServices.updateUser({
            id: existingUser.id,
            isBlocked: newBlockedStatus
        });

        if (!updatedUser) {
            throw new CustomError({
                code: ErrorCodes.CrudError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: `An unexpected error occurred.`,
                data: `Something went wrong, please try again.`
            });
        }

        const message = `User with credential: ${req.params.slug} has been ${newBlockedStatus ? 'Blocked' : 'Unblocked'}`;

        res.status(200).json(responseObject({ message }));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}
