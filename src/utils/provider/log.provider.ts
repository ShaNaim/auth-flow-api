import log from '@config/logger.config';
import { Request, Response, NextFunction } from 'express';
export const requestLogger = (req: Request, res: Response, next: NextFunction) => {
    log.info(`${req.ip} :: ${req.method} :: ${req.url}`);
    next();
};
