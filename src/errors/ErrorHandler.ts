import { Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { CustomError } from './CustomError';
import { ErrorArgs } from './ErrorArgs';
import log from '../config/logger.config';
import { ErrorCodes } from './ErrorCodes';
import { responseObject } from '@utils/provider/response.provider';
class ErrorHandler {
    private static isTrustedError(error: Error): boolean {
        if (error instanceof CustomError) {
            return error.isOperational;
        }

        return false;
    }

    private static handleTrustedError(error: CustomError, res: Response): Response {
        return res.status(error.status).json(
            responseObject(
                {
                    ...error
                },
                true
            )
        );
    }

    private static handleCriticalError(error: Error | CustomError, res?: Response): Response | void {
        if (res) {
            return res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(
                responseObject<ErrorArgs>(
                    {
                        code: ErrorCodes.UnknownError,
                        status: StatusCodes.INTERNAL_SERVER_ERROR,
                        description: 'Something went wrong. Please try again later.'
                    },
                    true
                )
            );
        }

        log.error('Application encountered a critical error. Exiting.');
        process.exit(1);
    }

    public handleError(error: Error, res?: Response): void {
        if (ErrorHandler.isTrustedError(error) && res) {
            ErrorHandler.handleTrustedError(error as CustomError, res);
        } else {
            ErrorHandler.handleCriticalError(error, res);
        }
    }
}

export const gracefulErrorHandler = new ErrorHandler();
