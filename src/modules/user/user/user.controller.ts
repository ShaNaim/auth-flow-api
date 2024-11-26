import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';

import { RequestType } from '@utils/types';
import { ErrorCodes } from '@errors/ErrorCodes';
import { CustomError } from '@errors/CustomError';
import authServices from '@modules/authentication';
import { gracefulErrorHandler } from '@errors/ErrorHandler';
import { responseObject } from '@provider/response.provider';
import { SlugSchema, RegisterSchema } from '@utils/validator/requestSchemaValidator';

import userServices, { getUserbyId, getUser } from './user.service';

export function healthController(req: Request, res: Response) {
    res.status(200).json(
        responseObject(
            {
                message: 'User System Running , Health OK'
            },
            false
        )
    );
}

export async function createUser(req: RequestType<RegisterSchema, unknown, unknown>, res: Response) {
    try {
        req.body.password = await authServices.hashString(req?.body?.password);
        const newUser = await userServices.createUserService(req.body);
        res.status(200).json(responseObject(newUser, false));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

export async function getUserbySlug(req: RequestType<unknown, SlugSchema, unknown>, res: Response) {
    try {
        const user = await userServices.getUserInfobySlug(req?.params?.slug, true);
        res.status(200).json(responseObject(user, false));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

export async function getAuthenticatedUserInfo(req: RequestType<unknown, unknown, unknown>, res: Response) {
    try {
        if (!req?.userId)
            throw new CustomError({
                code: ErrorCodes.AuthError,
                status: StatusCodes.UNAUTHORIZED,
                description: `Unauthorized user`,
                data: `Your are not authorized to perform this action`
            });
        const authUser = await getUserbyId(req?.userId);
        res.status(200).json(responseObject(authUser, false));
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

export async function blockUser(req: RequestType<unknown, SlugSchema, unknown>, res: Response) {
    try {
        const existingUser = await getUser({ slug: req?.params?.slug });

        if (!existingUser)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: `No User Found`,
                data: `No User with provided credential exits`
            });
        if (existingUser.isBlocked) res.status(204).json(responseObject({ message: `No change Required` }, false));
        else {
            const updatedUser = await userServices.updateUser({ id: existingUser?.id, isBlocked: true });
            if (!updatedUser)
                throw new CustomError({
                    code: ErrorCodes.CrudError,
                    status: StatusCodes.INTERNAL_SERVER_ERROR,
                    description: `An unexpected error occurred.`,
                    data: `Something went wrong please try again`
                });
            res.status(204).json(responseObject({ message: `User with credential : ${req?.params?.slug} was blocked` }, false));
        }
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
}
