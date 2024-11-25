import { StatusCodes } from 'http-status-codes';
import { ErrorCodes } from './ErrorCodes';

export interface ErrorArgs {
    code: ErrorCodes;
    status: StatusCodes;
    description: string;
    isOperational?: boolean;
    metaData?: any;
    data?: any;
}
