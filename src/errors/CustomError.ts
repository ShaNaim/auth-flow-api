import { StatusCodes } from 'http-status-codes';
import { ErrorArgs } from './ErrorArgs';
import { ErrorCodes } from './ErrorCodes';

export class CustomError extends Error {
    public readonly code: ErrorCodes;
    public readonly status: StatusCodes;
    public readonly description: string;
    public readonly isOperational: boolean = true;
    public readonly metaData: any = undefined;
    public readonly data: any = undefined;

    public constructor(args: ErrorArgs) {
        super(args.description);

        // Set the prototype explicitly.
        Object.setPrototypeOf(this, new.target.prototype);

        this.status = args.status;
        this.code = args.code;
        this.description = args.description;
        this.metaData = args.metaData;
        this.data = args.data;

        if (args.isOperational !== undefined) {
            this.isOperational = args.isOperational;
        }

        Error.captureStackTrace(this);
    }
}
