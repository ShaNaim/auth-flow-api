import 'module-alias/register';
import express, { Application, Request, Response } from 'express';
import errorHandler from '@middlewares/errorHandler';
import environment from '@config/config';
import hpp from 'hpp';
import log from '@config/logger.config';
import compression from 'compression';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import cors from 'cors';
import { createServer, Server } from 'http';
import { CustomError } from '@errors/CustomError';
import { ErrorArgs } from '@errors/ErrorArgs';
import { ErrorCodes } from '@errors/ErrorCodes';
import { StatusCodes } from 'http-status-codes';
import router from './routes';
import { requestLogger } from '@utils/provider/log.provider';
import os from 'os';
import { serverModes } from '@config/server.config';
import { tokenHandler } from '@middlewares/tokenHandler';

const app: Application = express();
const server: Server = createServer(app);
const initialUrl = `/v/${environment.version}`;
function initializeMiddlewares(): void {
    app.use(cors());
    app.use(express.json());
    app.use(hpp());
    app.use(compression());
    app.use(cookieParser());
    app.set('trust proxy', true);
    app.use(tokenHandler);
}

function initializeHelmet(): void {
    app.use(helmet());
}

function initializeRoutes(): void {
    app.get('/', (req, res) => {
        res.status(StatusCodes.OK).json({ data: 'OK' });
    });
    app.use(requestLogger);
    app.use(initialUrl, router);
}

function initializeNetworkAccess(): void {
    if (environment.mode !== serverModes.development) return;
    const networkInterfaces = os.networkInterfaces();

    // Find the IPv4 address in your network interfaces
    Object.keys(networkInterfaces).forEach((interfaceName) => {
        networkInterfaces[interfaceName]?.forEach((iface: { family: string; internal: any; address: any }) => {
            if (iface.family === 'IPv4' && !iface.internal) {
                log.info(`Network: http://${iface.address}:${environment.port}/`);
            }
        });
    });
}

function initializeErrorHandling(): void {
    // Intentional routes for global error handling
    app.get(`${initialUrl}/unknown-error`, (_, res, next) => {
        next(
            new CustomError({
                code: ErrorCodes.UnknownError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something wrong happened! Please try again later.'
            })
        );
    });

    app.get(`${initialUrl}/known-error`, (_, res, next) => {
        return next(
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
    server.listen(environment.port, () => {
        log.info(`Local: http://localhost:${environment.port}/`);
        initializeNetworkAccess();
    });
}

initializeMiddlewares();
initializeHelmet();
initializeRoutes();
initializeErrorHandling();
listen();
