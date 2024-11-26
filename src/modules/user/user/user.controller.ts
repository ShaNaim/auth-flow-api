import { Request, Response } from 'express';
import { responseObject } from '@provider/response.provider';
import { RequestType } from '@utils/types';

import { gracefulErrorHandler } from '@errors/ErrorHandler';
import authServices from '@modules/authentication';
import userServices from './user.service';
import { SlugSchema, RegisterSchema } from '@utils/validator/requestSchemaValidator';
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
