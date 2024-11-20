import { Prisma } from '@prisma/client';
import { CustomError } from './CustomError';
import prismaErrorType from './prisma.error';

class DetermineErrorType {
    public readonly error: Error;

    public constructor(error: Error) {
        this.error = error;
    }

    public convertKnowErrors() {
        if (this?.error instanceof CustomError) {
            return this?.error;
        }
        if (this?.error instanceof Prisma.PrismaClientKnownRequestError) {
            return prismaErrorType(this?.error);
        }
        return this?.error;
    }
}

export default DetermineErrorType;
