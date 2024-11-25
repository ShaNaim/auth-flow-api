import { StatusCodes } from 'http-status-codes';
import { Prisma } from '@prisma/client';
import { ErrorCodes } from './ErrorCodes';
import { CustomError } from './CustomError';
import log from '@config/logger.config';

function prismaErrorType(error: Prisma.PrismaClientKnownRequestError): CustomError {
    if (error?.code === 'P2002') {
        return new CustomError({
            code: ErrorCodes.ItemExists,
            status: StatusCodes.CONFLICT,
            description: `No Duplicate Allowed`,
            data: {
                path: [error?.meta?.modelName, error?.meta?.target],
                message: `${error?.meta?.modelName} with same ${error?.meta?.target} Already Exists`
            }
        });
    }
    if (error?.code === 'P1002') {
        return new CustomError({
            code: ErrorCodes.TimeOut,
            status: StatusCodes.INTERNAL_SERVER_ERROR,
            description: `The database server was reached but timed out.`,
            data: {
                path: [error?.meta?.modelName, error?.meta?.target],
                message: `The database server timed out, Please try again later`
            }
        });
    }
    if (error?.code === 'P2000') {
        return new CustomError({
            code: ErrorCodes.InvalidInput,
            status: StatusCodes.BAD_REQUEST,
            description: `Value Too Long`,
            data: {
                path: [error?.meta?.column],
                message: `Value for ${error?.meta?.column} exceeds the maximum length`
            }
        });
    }

    // P2003: Foreign key constraint failed
    if (error?.code === 'P2003') {
        return new CustomError({
            code: ErrorCodes.ForeignKeyConstraintFailed,
            status: StatusCodes.BAD_REQUEST,
            description: `Foreign Key Constraint Failed`,
            data: {
                path: [error?.meta?.fieldName],
                message: `Invalid reference in field ${error?.meta?.fieldName}`
            }
        });
    }

    // P2025: Record not found
    if (error?.code === 'P2025') {
        return new CustomError({
            code: ErrorCodes.RecordNotFound,
            status: StatusCodes.NOT_FOUND,
            description: `Record Not Found`,
            data: {
                message: `The requested record could not be found`
            }
        });
    }

    // P2014: Nested records conflict
    if (error?.code === 'P2014') {
        return new CustomError({
            code: ErrorCodes.NestedRecordConflict,
            status: StatusCodes.CONFLICT,
            description: `Nested Record Conflict`,
            data: {
                message: `The change you are trying to make violates a constraint on nested records`
            }
        });
    }

    // P2016: Query interpretation error
    if (error?.code === 'P2016') {
        return new CustomError({
            code: ErrorCodes.QueryError,
            status: StatusCodes.BAD_REQUEST,
            description: `Query Interpretation Error`,
            data: {
                message: `There was an error interpreting the query`
            }
        });
    }

    // P2017: Relation violation
    if (error?.code === 'P2017') {
        return new CustomError({
            code: ErrorCodes.RelationViolation,
            status: StatusCodes.BAD_REQUEST,
            description: `Relation Violation`,
            data: {
                message: `The relation does not satisfy required conditions`
            }
        });
    }

    // P2018: Required record not found
    if (error?.code === 'P2018') {
        return new CustomError({
            code: ErrorCodes.RequiredRecordNotFound,
            status: StatusCodes.NOT_FOUND,
            description: `Required Record Not Found`,
            data: {
                message: `A required record is missing in the database`
            }
        });
    }

    // P2034: Deadlock detected
    if (error?.code === 'P2034') {
        return new CustomError({
            code: ErrorCodes.DeadlockDetected,
            status: StatusCodes.CONFLICT,
            description: `Deadlock Detected`,
            data: {
                message: `A deadlock was detected while performing the operation`
            }
        });
    }

    log.error('Unknown Prisma Error');
    log.error(error);
    return new CustomError({
        code: ErrorCodes.UnknownError,
        status: StatusCodes.INTERNAL_SERVER_ERROR,
        description: 'Something went wrong. Please try again later.',
        isOperational: false
    });
}

export default prismaErrorType;
