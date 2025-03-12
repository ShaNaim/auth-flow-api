import { IJwtPayload } from '@utils/types';

declare global {
    namespace Express {
        interface Request {
            userId?: number;
            jwt?: IJwtPayload;
        }
    }
}

// This is important - it makes the file a module rather than a script
export {};
