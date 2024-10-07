import 'module-alias/register';
import { createServer, Server } from 'http';
import express, { Application, Request, Response } from 'express';
import log from '@config/logger';
import envirinment from '@config/config';
import { CustomError } from './errors/CustomError';
import { ErrorArgs } from '@errors/ErrorArgs';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import errorHandler from './middleware/errorHandler';

const app: Application = express();
const server: Server = createServer(app);

function initializeMiddlewares(): void {}
function initializeHelmet(): void {}
function initializeRoutes(): void {
    app.get(
        '/',
        (req, res, next) => {
            console.log('hello');
            next();
        },
        (req, res) => {
            res.status(StatusCodes.OK).json({ data: 'OK' });
        }
    );
}

function initializeErrorHandling(): void {
    // Intentional routes for global error handling
    app.get('/unknown-error', (_, res, next) => {
        next(new Error('Something wrong happened! Please try again later.'));
    });

    app.get('/known-error', (_, res, next) => {
        next(
            new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: 'Not found - raise known error.'
            })
        );
    });

    // Error handler. Must be placed at the end of the middleware chain.
    app.use(errorHandler);

    // Catch all unmatched routes
    app.all('*', (req: Request, res: Response) => {
        const errorResponse: ErrorArgs = {
            code: ErrorCodes.NotFound,
            status: StatusCodes.NOT_FOUND,
            description: 'Route not found!',
            isOperational: false,
            metaData: {
                path: req.path,
                method: req.method
            }
        };
        res.status(StatusCodes.NOT_FOUND).json(errorResponse);
    });
}

function listen(): void {
    // We are now listening server instead of app
    server.listen(envirinment.port, () => {
        log.info(`=========================================`);
        log.info(`Server started on port ${envirinment.port}`);
        log.info(`=========================================`);
    });
}
listen();
initializeRoutes();
