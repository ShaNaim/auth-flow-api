import { Request, Response } from 'express';
import { responseObject } from '@provider/response.provider';
import { LoginInputSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
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

export function loginController(req: Request, res: Response) {
    const body: LoginInputSchema = req?.body;
    res.status(200).json(responseObject(req?.body, false));
}

export function reginsterController(req: Request, res: Response) {
    res.status(200).json(responseObject(req?.body, false));
}
