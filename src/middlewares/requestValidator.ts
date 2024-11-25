import { NextFunction, Request, Response } from 'express';
import { AnyZodObject } from 'zod';
import { StatusCodes } from 'http-status-codes';
import { MiddlewareType } from '@utils/types/middleware.types';
import { ValidationErrorResponse, ValidationError } from '@utils/types/zod.types';
import log from '@config/logger.config';
import { CustomError } from '@errors/CustomError';
import { ErrorCodes } from '@errors/ErrorCodes';
/**
 *
 * Validate the request body, query and params by zod.
 *
 * @param schema - The schema to validate the request body against
 * @returns void
 */
const requestValidator =
    (schema: AnyZodObject): MiddlewareType =>
    (req: Request, res: Response, next: NextFunction): void => {
        try {
            schema.parse({
                body: req.body,
                query: req.query,
                params: req.params
            });
            next();
        } catch (error: any) {
            const errors: ValidationErrorResponse = [];
            error.errors.forEach((element: ValidationError) => {
                errors.push({
                    code: element?.code || '',
                    path: Array.isArray(element?.path) ? element?.path[element?.path.length - 1] : 'unknown',
                    message: element?.message || ''
                });
            });
            log.error('[validation] Schema validation failed.');
            next(
                new CustomError({
                    code: ErrorCodes.ValidationError,
                    status: StatusCodes.BAD_REQUEST,
                    description: error.message,
                    data: errors
                })
            );
        }
    };

export default requestValidator;
