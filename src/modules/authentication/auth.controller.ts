import { Request, Response } from 'express';
import { StatusCodes } from 'http-status-codes';
import { responseObject } from '@provider/response.provider';
import { ErrorCodes } from '@errors/ErrorCodes';
import { RegisterSchema, LoginSchema } from '@utils/validator/requestSchemaValidator/authentication.validator';
import { RequestType } from '@utils/types';
import userServices from '@modules/user/user';
import { gracefulErrorHandler } from '@errors/ErrorHandler';
import { CustomError } from '@errors/CustomError';
import * as authServices from './auth.service';
import logger from '@config/logger.config';
import config from '@config/config';

/**
 * Health check controller to verify if the authentication system is running.
 * @param {Request} req - Express request object.
 * @param {Response} res - Express response object.
 */
export function healthController(req: Request, res: Response) {
    logger.info('Health check endpoint hit');
    res.status(200).json(
        responseObject(
            {
                message: 'Auth System Running , Health OK'
            },
            false
        )
    );
}

/**
 * Handles user login by authenticating credentials and generating authentication tokens.
 * @param {RequestType<LoginSchema, unknown, unknown>} req - Express request object containing login details.
 * @param {Response} res - Express response object.
 */
export async function loginController(req: RequestType<LoginSchema, unknown, unknown>, res: Response) {
    try {
        const body = req?.body;
        const clientIP = req.ip || null;
        logger.info(`Login attempt for email: ${body?.email} from IP: ${clientIP}`);

        const user = await authServices.authenticateUser(body);
        if (!user) {
            logger.error(`Authentication failed for email: ${body?.email}`);
            throw new CustomError({
                code: ErrorCodes.UnknownError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['user', 'authentication', 'unknown'],
                    message: `Something went wrong, please try again`
                }
            });
        }

        logger.info(`User authenticated successfully: ${user.email}`);

        const csrfToken = await authServices.generateCSRFToken();
        const { accessToken, refreshToken } = authServices.getSignedTokens(user);

        if (!accessToken || !refreshToken) {
            logger.error(`Token generation failed for user: ${user.email}`);
            throw new CustomError({
                code: ErrorCodes.ServerError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: 'Something went wrong',
                data: {
                    path: ['login', 'getSignedTokens', 'accessToken', 'refreshToken'],
                    message: `Token generation issue`
                },
                isOperational: false
            });
        }

        await authServices.storeRefreshToken({
            userId: user.id,
            tokenHash: authServices.hashToken(refreshToken),
            userAgent: req.headers['user-agent'] || 'unknown',
            ip: clientIP,
            expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
        });

        logger.info(`Tokens stored successfully for user: ${user.email}`);

        res.cookie('accessToken', accessToken, {
            httpOnly: true,
            secure: config.mode === 'production',
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined,
            signed: true
        });
        logger.info(`accessToken cookie set successfully`);
        res.cookie('refreshToken', refreshToken, {
            httpOnly: true,
            secure: config.mode === 'production',
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: process.env.COOKIE_DOMAIN || undefined,
            signed: true
        });

        logger.info(`refreshToken cookie set successfully`);
        res.cookie('XSRF-TOKEN', csrfToken, {
            httpOnly: false,
            secure: config.mode === 'production',
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000
        });
        logger.info(`XSRF-TOKEN cookie set successfully`);
        logger.info(`Login successful for user: ${user.email}`);
        res.status(200).json(responseObject({ email: user?.email, slug: user?.slug, csrfToken }, false));
    } catch (error) {
        logger.error(`Login error: ${error}`);
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

/**
 * Handles user registration and stores new user details.
 * @param {RequestType<RegisterSchema, unknown, unknown>} req - Express request object containing registration details.
 * @param {Response} res - Express response object.
 */
export async function registerController(req: RequestType<RegisterSchema, unknown, unknown>, res: Response) {
    try {
        logger.info(`Registering new user: ${req.body.email}`);
        req.body.password = await authServices.hashString(req?.body?.password);
        const newUser = await userServices.createUserService(req.body);
        logger.info(`User registered successfully: ${newUser.email}`);
        res.status(200).json(responseObject(newUser, false));
    } catch (error) {
        logger.error(`User registration failed: ${error}`);
        gracefulErrorHandler.handleError(error as Error, res);
    }
}

/**
 * Logs out the user by clearing authentication tokens.
 * @param {Request} req - Express request object.
 * @param {Response} res - Express response object.
 */
export function logoutController(req: Request, res: Response) {
    logger.info(`User logged out`);
    res.status(200).json(responseObject('logout successful', false));
}

/**
 * Blocks or unblocks a user based on their current status.
 * @param {Request} req - Express request object containing user slug.
 * @param {Response} res - Express response object.
 */
export async function blockUserController(req: Request, res: Response) {
    try {
        logger.info(`Block user request received for: ${req.params.slug}`);
        const existingUser = await authServices.userExists(req?.params?.slug);
        if (!existingUser) {
            logger.warn(`Attempted to block non-existing user: ${req.params.slug}`);
            throw new CustomError({
                code: ErrorCodes.NotFound,
                status: StatusCodes.NOT_FOUND,
                description: `No User Found`,
                data: `No User with provided credential exists`
            });
        }

        const newBlockedStatus = !existingUser.isBlocked;
        const updatedUser = await userServices.updateUser({ id: existingUser.id, isBlocked: newBlockedStatus });
        if (!updatedUser) {
            logger.error(`Failed to update block status for user: ${req.params.slug}`);
            throw new CustomError({
                code: ErrorCodes.CrudError,
                status: StatusCodes.INTERNAL_SERVER_ERROR,
                description: `An unexpected error occurred.`,
                data: `Something went wrong, please try again.`
            });
        }

        logger.info(`User ${req.params.slug} has been ${newBlockedStatus ? 'Blocked' : 'Unblocked'}`);
        res.status(200).json(
            responseObject({ message: `User with credential: ${req.params.slug} has been ${newBlockedStatus ? 'Blocked' : 'Unblocked'}` })
        );
    } catch (error) {
        logger.error(`Error blocking user: ${error}`);
        gracefulErrorHandler.handleError(error as Error, res);
    }
}
