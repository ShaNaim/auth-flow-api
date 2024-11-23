import { Request, Response } from 'express';
import { responseObject } from '@provider/response.provider';

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
