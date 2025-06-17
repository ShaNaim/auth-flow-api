import { PrismaClient, User, RefreshToken } from '@prisma/client';
import { IdType } from '@utils/types';
import { UserWithPerson, StoreRefreshTokenParams, RotateRefreshTokenParams } from './auth.types';
import logger from '@config/logger.config'; // Importing the logger

const prisma = new PrismaClient();

/**
 * Retrieves a user for authentication by their email.
 * @param email - The email of the user to authenticate.
 * @returns The user object with associated person data or null if not found.
 */
export async function getUserForAuthentication(email: string): Promise<UserWithPerson | null> {
    logger.info(`Model => Fetching user for authentication with email: ${email}`);
    return await prisma.user.findUnique({
        where: { email },
        include: { person: true }
    });
}

/**
 * Retrieves a user by their slug.
 * @param slug - The slug of the user to retrieve.
 * @returns The user object with associated person data or null if not found.
 */
export async function getUserBySlug(slug: string): Promise<UserWithPerson | null> {
    logger.info(`Model => Fetching user with slug: ${slug}`);
    return await prisma.user.findUnique({
        where: { slug },
        include: { person: true }
    });
}

/**
 * Finds a user by their session ID by checking the refresh token.
 * @param sessionId - The ID of the session to find the user by.
 * @returns The user object associated with the session or null if not found.
 */
export async function findUserBySessionId(sessionId: IdType<RefreshToken>): Promise<User | null> {
    try {
        logger.info(`Model => Finding user by session ID: ${sessionId}`);
        const session = await prisma.refreshToken.findUnique({
            where: { id: sessionId },
            include: { user: true }
        });
        return session?.user ?? null;
    } catch (error) {
        logger.error('Model => Error finding user by session ID:', error);
        return null;
    }
}

/**
 * Stores a refresh token for a user in the database.
 * @param params - The parameters required to store the refresh token.
 */
export async function storeRefreshToken(params: StoreRefreshTokenParams): Promise<void> {
    try {
        logger.info(`Model => Storing refresh token for user with ID: ${params.userId}`);
        await prisma.refreshToken.create({
            data: {
                userId: params.userId,
                token: params.tokenHash,
                userAgent: params.userAgent,
                ip: params.ip,
                expiresAt: params.expiresAt,
                isRevoked: false
            }
        });
    } catch (error) {
        logger.error('Model => Error storing refresh token:', error);
        throw error;
    }
}

/**
 * Verifies if a refresh token is valid for a given user by comparing the token hash.
 * @param tokenHash - The hashed refresh token.
 * @param userId - The ID of the user to verify the token for.
 * @returns A boolean indicating whether the refresh token is valid.
 */
export async function verifyRefreshToken(tokenHash: string, userId: number): Promise<boolean> {
    try {
        logger.info(`Model => Verifying refresh token for user with ID: ${userId}`);
        const token = await prisma.refreshToken.findFirst({
            where: {
                token: tokenHash,
                userId,
                isRevoked: false,
                expiresAt: { gt: new Date() }
            }
        });
        return !!token;
    } catch (error) {
        logger.error('Model => Error verifying refresh token:', error);
        return false;
    }
}

/**
 * Invalidates a specific refresh token by marking it as revoked.
 * @param userId - The ID of the user whose refresh token is being invalidated.
 * @param tokenHash - The hashed refresh token to revoke.
 */
export async function invalidateRefreshToken(userId: number, tokenHash: string): Promise<void> {
    try {
        logger.info(`Model => Invalidating refresh token for user with ID: ${userId}`);
        await prisma.refreshToken.updateMany({
            where: { userId, token: tokenHash },
            data: { isRevoked: true }
        });
    } catch (error) {
        logger.error('Model => Error invalidating refresh token:', error);
        throw error;
    }
}

/**
 * Rotates a user's refresh token by invalidating the old token and storing a new one.
 * @param params - The parameters for rotating the refresh token.
 */
export async function rotateRefreshToken(params: RotateRefreshTokenParams): Promise<void> {
    try {
        logger.info(`Model => Rotating refresh token for user with ID: ${params.userId}`);
        await prisma.$transaction([
            prisma.refreshToken.updateMany({
                where: {
                    userId: params.userId,
                    token: params.oldTokenHash,
                    isRevoked: false
                },
                data: { isRevoked: true }
            }),
            prisma.refreshToken.create({
                data: {
                    userId: params.userId,
                    token: params.newTokenHash,
                    userAgent: params.userAgent,
                    ip: params.ip,
                    expiresAt: params.expiresAt,
                    isRevoked: false
                }
            })
        ]);
    } catch (error) {
        logger.error('Model => Error rotating refresh token:', error);
        throw error;
    }
}

/**
 * Invalidates all refresh tokens for a user by marking them as revoked.
 * @param userId - The ID of the user whose tokens are being invalidated.
 */
export async function invalidateAllUserTokens(userId: number): Promise<void> {
    try {
        logger.info(`Model => Invalidating all refresh tokens for user with ID: ${userId}`);
        await prisma.refreshToken.updateMany({
            where: { userId, isRevoked: false },
            data: { isRevoked: true }
        });
    } catch (error) {
        logger.error('Model => Error invalidating all user tokens:', error);
        throw error;
    }
}
