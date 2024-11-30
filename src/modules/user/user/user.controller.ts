import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';

import { ErrorCodes } from '@errors/ErrorCodes';
import { CustomError } from '@errors/CustomError';
import authServices from '@modules/authentication';
import { gracefulErrorHandler } from '@errors/ErrorHandler';
import { responseObject } from '@provider/response.provider';
import { personQueryTypes, RequestType } from '@utils/types';
import {
    SlugSchema,
    RegisterSchema,
    DetailsSchema,
    UpdateUserSchema,
    PersonInputSchema,
    AddressInputSchema
} from '@utils/validator/requestSchemaValidator';

import userServices, { getUserbyId } from './user.service';
import { isValueInObject } from '@utils/handle-validation';
import personServices from '@modules/user/person';
import addressServices from '@modules/user/address';

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

export async function updateUserController(req: RequestType<UpdateUserSchema, SlugSchema, DetailsSchema>, res: Response) {
    try {
        const user = await userServices.getUserInfobySlug(req?.params?.slug, true);
        if (!user)
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: `No User Found`,
                data: `No User with provided credential exits`
            });
        if (isValueInObject(req?.query?.details || '', personQueryTypes)) {
            let person;
            let address;
            const details = req?.query?.details || null;
            if (!user?.person?.slug)
                throw new CustomError({
                    code: ErrorCodes.NotFound,
                    status: StatusCodes.NOT_FOUND,
                    description: `No User Found`,
                    data: `No User with provided credential exits`
                });
            person = await personServices.updatePersonandReturn(
                user.person?.slug,
                req.body as PersonInputSchema,
                details === personQueryTypes.person || details === personQueryTypes.all ? 'person' : null
            );

            if (!user?.person?.address?.slug)
                throw new CustomError({
                    code: ErrorCodes.NotFound,
                    status: StatusCodes.NOT_FOUND,
                    description: `No User Found`,
                    data: `No User with provided credential exits`
                });
            address = await addressServices.updateAddressandReturn(
                user.person.address.slug,
                req.body.address as AddressInputSchema,
                details === personQueryTypes.address || details === personQueryTypes.all ? 'address' : null
            );
            res.status(200).json(responseObject({ ...person, address }, false));
        } else {
            if (user?.person?.slug) {
                personServices.updatePersonOptimisticly(user.person.slug, req.body as PersonInputSchema);
            }
            if (user?.person?.address?.slug)
                addressServices.updateAddressOptimisticly(user.person.address.slug, req.body.address as AddressInputSchema);
            res.status(204).json(responseObject('updated', false));
        }
    } catch (error) {
        gracefulErrorHandler.handleError(error as Error, res);
    }
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

export async function getAllUsersController(req: Request, res: Response) {
    const usersList = await userServices.getAllUsers();
    res.status(200).json(responseObject(usersList));
}
