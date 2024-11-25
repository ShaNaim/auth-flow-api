import { Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { CustomError } from './CustomError';
import { ErrorArgs } from './ErrorArgs';
import log from '../config/logger.config';
import { ErrorCodes } from './ErrorCodes';
import { responseObject } from '@utils/provider/response.provider';
import DetermineErrorType from './DetermineErrorType';
class ErrorHandler {
    private static isTrustedError(error: Error): boolean {
        if (error instanceof CustomError) {
            return error.isOperational;
        }
        return false;
    }

    private static handleTrustedError(error: CustomError, res: Response): Response {
        log.error(`Application encountered a known error with code. ${error?.status}`);
        return res.status(error?.status).json(
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
            log.error(`Application encountered a Unknown error`);
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
        log.error(error);
        process.exit(1);
    }

    public handleError(error: Error, res?: Response): void {
        log.error(JSON.stringify(error, null, 2));
        const convertedError = new DetermineErrorType(error).convertKnowErrors();
        if (ErrorHandler.isTrustedError(convertedError as Error) && res) {
            ErrorHandler.handleTrustedError(convertedError as CustomError, res);
        } else {
            ErrorHandler.handleCriticalError(convertedError, res);
        }
    }
}

export const gracefulErrorHandler = new ErrorHandler();
