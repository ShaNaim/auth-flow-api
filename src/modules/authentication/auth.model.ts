import { PrismaClient, Session, User, RefreshToken } from '@prisma/client';
import { IdType } from '@utils/types';
import { SessionUpdateData, UserWithPerson, StoreRefreshTokenParams, RotateRefreshTokenParams } from './auth.types';

const prisma = new PrismaClient();

// Session operations
export async function createSession(userId: IdType<User>): Promise<Session> {
    return await prisma.session.create({
        data: {
            user: { connect: { id: userId } }
        }
    });
}

export async function updateSession(sessionId: IdType<Session>, sessionData: SessionUpdateData): Promise<Session> {
    return await prisma.session.update({
        where: { id: sessionId },
        data: {
            isActive: sessionData.isActive,
            isBlocked: sessionData.isBlocked
        }
    });
}

export async function findSessionsByUserId(userId: IdType<User>): Promise<Session[]> {
    return await prisma.session.findMany({ where: { userId } });
}

export async function deleteSessionsByUserId(userId: IdType<User>): Promise<{ count: number }> {
    return await prisma.session.deleteMany({ where: { userId } });
}

export async function deleteSessionById(sessionId: IdType<Session>): Promise<Session> {
    return await prisma.session.delete({ where: { id: sessionId } });
}

// User operations
export async function getUserForAuthentication(email: string): Promise<UserWithPerson | null> {
    return await prisma.user.findUnique({
        where: { email },
        include: { person: true }
    });
}

export async function getUserBySlug(slug: string): Promise<UserWithPerson | null> {
    return await prisma.user.findUnique({
        where: { slug },
        include: { person: true }
    });
}

export async function findUserBySessionId(sessionId: IdType<RefreshToken>): Promise<User | null> {
    try {
        const session = await prisma.refreshToken.findUnique({
            where: { id: sessionId },
            include: { user: true }
        });
        return session?.user ?? null;
    } catch (error) {
        console.error('Error finding user by session ID:', error);
        return null;
    }
}

// Refresh token operations
export async function storeRefreshToken(params: StoreRefreshTokenParams): Promise<void> {
    try {
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
        console.error('Error storing refresh token:', error);
        throw error;
    }
}

export async function verifyRefreshToken(tokenHash: string, userId: number): Promise<boolean> {
    try {
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
        console.error('Error verifying refresh token:', error);
        return false;
    }
}

export async function invalidateRefreshToken(userId: number, tokenHash: string): Promise<void> {
    try {
        await prisma.refreshToken.updateMany({
            where: { userId, token: tokenHash },
            data: { isRevoked: true }
        });
    } catch (error) {
        console.error('Error invalidating refresh token:', error);
        throw error;
    }
}

export async function rotateRefreshToken(params: RotateRefreshTokenParams): Promise<void> {
    try {
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
        console.error('Error rotating refresh token:', error);
        throw error;
    }
}

export async function invalidateAllUserTokens(userId: number): Promise<void> {
    try {
        await prisma.refreshToken.updateMany({
            where: { userId, isRevoked: false },
            data: { isRevoked: true }
        });
    } catch (error) {
        console.error('Error invalidating all user tokens:', error);
        throw error;
    }
}
